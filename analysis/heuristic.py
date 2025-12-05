#!/usr/bin/env python3
"""
heuristic_labeler.py

Reads window-level features CSV produced by feature_extractor.py and produces:
- labelled CSV with appended columns:
    protocol probabilities (HANDSHAKE..CLEANUP),
    predicted_stage, predicted_behavior,
    is_crypto, crypto_confidence, algorithm_family,
    anomalies (comma-separated),
    explain_top (short list)
- JSON reports (reports/window_{i}.json)

Usage:
    python3 heuristic_labeler.py --input features.csv --out labeled_features.csv
"""

import argparse, csv, json, math, os
from collections import Counter, OrderedDict
import numpy as np

# ---------------------------
# Config / thresholds
# ---------------------------
ANOMALY_STACK_SPIKE_THRESHOLD = 0.6    # relative to max observed stack_nz across dataset (set later)
ANOMALY_REPETITION_THRESHOLD = 8       # repeated-blocks threshold
HIGH_ENTROPY = 0.55
LOW_ENTROPY = 0.30

# ---------------------------
# Utils
# ---------------------------
def softmax(score_dict):
    vals = np.array(list(score_dict.values()), dtype=float)
    ex = np.exp(vals - np.max(vals))
    p = ex / ex.sum() if ex.sum() != 0 else np.ones_like(ex)/len(ex)
    return {k: float(v) for k,v in zip(score_dict.keys(), p)}

def safe_div(a,b):
    return (a/b) if (b and b!=0) else 0.0

def pick_max_key(d):
    if not d: return None, 0.0
    k = max(d, key=lambda x: d[x])
    return k, d[k]

# ---------------------------
# Heuristic scoring (uses normalized densities)
# ---------------------------

def compute_stage_scores(feat):
    # feat: dict of features (already normalized/densities when appropriate)
    # Use the same coefficients you designed, but ensure densities in [0,1]
    f = feat
    # handshake
    score_handshake = (
        2.0 * f.get("syscall_connect", 0.0) +
        2.0 * (1.0 if f.get("hello_string", False) else 0.0) +
        1.5 * (1.0 if f.get("mnemonic_entropy",0) < LOW_ENTROPY else 0.0) +
        1.0 * (1.0 - f.get("arithmetic_density",0.0)) -
        1.5 * (f.get("xor_density",0.0) + f.get("shift_density",0.0))
    )

    # key exchange
    score_key_exchange = (
        1.5 * (1.0 if LOW_ENTROPY <= f.get("mnemonic_entropy",0) <= HIGH_ENTROPY else 0.0) +
        2.0 * f.get("arithmetic_density",0.0) +
        1.0 * f.get("branch_density",0.0) -
        2.0 * (f.get("xor_density",0.0) + f.get("shift_density",0.0)) -
        1.0 * min(f.get("loop_repetition",0.0), 50.0)  # penalty if huge repetition (encryption)
    )

    # encryption
    score_encryption = (
        3.0 * f.get("xor_density",0.0) +
        3.0 * f.get("shift_density",0.0) +
        3.0 * (1.0 if f.get("mnemonic_entropy",0.0) > HIGH_ENTROPY else 0.0) +
        2.0 * min(f.get("loop_repetition",0.0), 100.0)/100.0 +   # normalize loop_repetition
        1.0 * (f.get("stack_mutation_norm", 0.0)) +
        3.0 * (1.0 if f.get("has_crypto_pattern",0)==1 else 0.0)
    )

    # data transfer
    score_data_transfer = (
        3.0 * f.get("syscall_send",0.0) +
        2.0 * f.get("syscall_recv",0.0) +
        1.5 * (1.0 if f.get("mnemonic_entropy",0) < LOW_ENTROPY else 0.0) -
        3.0 * f.get("arithmetic_density",0.0) -
        2.0 * (f.get("xor_density",0.0) + f.get("shift_density",0.0))
    )

    # cleanup
    score_cleanup = (
        3.0 * f.get("syscall_close",0.0) +
        2.0 * (1.0 if f.get("mnemonic_entropy",0) < 0.15 else 0.0) -
        2.0 * f.get("arithmetic_density",0.0) -
        2.0 * (f.get("xor_density",0.0) + f.get("shift_density",0.0))
    )

    return {
        "HANDSHAKE": score_handshake,
        "KEY_EXCHANGE": score_key_exchange,
        "ENCRYPTION": score_encryption,
        "DATA_TRANSFER": score_data_transfer,
        "CLEANUP": score_cleanup
    }

# ---------------------------
# Simple crypto algorithm classifier (heuristic)
# ---------------------------
def guess_crypto_family(feat):
    # feat uses densities and loop_repetition normalized
    xor = feat.get("xor_density",0.0)
    shift = feat.get("shift_density",0.0)
    mult_div = feat.get("mult_div_density",0.0)
    big_int = feat.get("big_int_density",0.0)
    table_lookup = feat.get("table_lookup_density",0.0)  # if available

    # very simple heuristic rules:
    if big_int > 0.05 or mult_div > 0.05:
        return {"type":"ASYMMETRIC","algorithm":"RSA-like","confidence":0.85,
                "evidence":["big-int ops","multiply/div density high"]}
    if xor>0.15 and shift>0.12 and (feat.get("loop_repetition",0)/128.0) > 0.05:
        # Add-Xor-Rotate family (ChaCha/AES-like)
        # Distinguish AES vs ChaCha by table lookup density or round counts if available
        if table_lookup > 0.08:
            return {"type":"SYMMETRIC","algorithm":"AES-like","confidence":0.86,
                    "evidence":["table lookups", "xor/shift heavy", "round-like loop repetition"]}
        else:
            return {"type":"SYMMETRIC","algorithm":"AddXorRotate-like (ChaCha/Salsa)","confidence":0.78,
                    "evidence":["add/xor/rotate pattern","high xor/shift density"]}
    if xor>0.05 and shift<0.05 and feat.get("mnemonic_entropy",0.0) < 0.5:
        return {"type":"STREAM_OR_SIMPLE","algorithm":"XOR-based or RC4-like","confidence":0.6,
                "evidence":["xor present, low shift", "moderate entropy"]}
    return {"type":"UNKNOWN","algorithm":"unknown","confidence":0.15,"evidence":[]}

# ---------------------------
# Anomaly detector
# ---------------------------
def detect_anomalies(feat, max_stack_nz):
    anomalies=[]
    # stack spike (relative)
    if max_stack_nz>0:
        rel_stack = feat.get("stack_nonzero_total",0.0)/max_stack_nz
        if rel_stack > ANOMALY_STACK_SPIKE_THRESHOLD:
            anomalies.append({"type":"stack_entropy_spike","score":float(rel_stack)})
    # repetition anomaly
    if feat.get("loop_repetition",0) >= ANOMALY_REPETITION_THRESHOLD:
        anomalies.append({"type":"loop_repetition_high","score":float(feat.get("loop_repetition",0))})
    # very high entropy combined with very high repetition (weird)
    if feat.get("mnemonic_entropy",0.0) > 0.85 and feat.get("loop_repetition",0) > 4:
        anomalies.append({"type":"high_entropy_with_repetition","score":float(feat.get("mnemonic_entropy",0.0))})
    return anomalies

# ---------------------------
# Main CSV-driven labeler
# ---------------------------
def label_csv(in_csv, out_csv, json_reports_dir="reports"):
    # read CSV header and rows
    rows=[]
    with open(in_csv,"r",newline="") as f:
        r=csv.DictReader(f)
        header_fields = r.fieldnames
        for row in r:
            rows.append(row)

    if not rows:
        raise SystemExit("Input CSV empty")

    # find max stack_nonzero across dataset for relative anomaly thresholds
    all_stack = []
    for row in rows:
        v = safe_float(row.get("win_stack_nonzero_sum", row.get("win_stack_nz_sum",0)))
        all_stack.append(v)
    max_stack = max(all_stack) if all_stack else 0.0
    if max_stack == 0:
        max_stack = 1.0

    # Build output header (append columns)
    extra_cols = [
        "pred_HANDSHAKE","pred_KEY_EXCHANGE","pred_ENCRYPTION","pred_DATA_TRANSFER","pred_CLEANUP",
        "pred_stage","pred_stage_confidence",
        "is_crypto","crypto_confidence","algorithm_type","algorithm_family","algorithm_confidence",
        "anomalies","explain_top"
    ]
    out_header = header_fields + extra_cols

    os.makedirs(json_reports_dir, exist_ok=True)
    with open(out_csv,"w",newline="") as outf:
        writer = csv.DictWriter(outf, fieldnames=out_header)
        writer.writeheader()

        for i,row in enumerate(rows):
            # Derive features expected by scoring function from CSV row
            # Use available columns, with sensible fallbacks
            # token-level counts might be in columns; otherwise rely on aggregated fields
            def getf(k, fallback=0.0): 
                return safe_float(row.get(k, fallback))

            # Basic densities: try to compute from available columns
            total_tokens = getf("win_num_tokens", 1.0)
            # numeric counts available from extract.py naming
            num_bitops = getf("win_num_bitops", getf("win_num_bitops_sum",0))
            num_shiftops = getf("win_num_shiftops", getf("win_num_shiftops_sum",0))
            num_multdiv = getf("win_num_multdiv", getf("win_num_multdiv_sum",0))
            num_bigint = getf("win_num_bigint", getf("win_num_bigint_sum",0))
            num_br = getf("win_num_branches", getf("win_num_branches_sum", getf("win_num_branches",0)))
            num_jumps = getf("win_num_jumps", getf("win_num_jumps_sum",0))
            num_mem = getf("win_num_memory", getf("win_num_memory_ops_sum", getf("win_num_memory",0)))

            xor_density = safe_div(num_bitops, total_tokens)   # bitop includes xor approximated
            shift_density = safe_div(num_shiftops, total_tokens)
            mult_div_density = safe_div(num_multdiv, total_tokens)
            big_int_density = safe_div(num_bigint, total_tokens)
            arithmetic_density = safe_div(getf("win_num_memory",0) + getf("win_num_branches",0), total_tokens)  # fallback
            # better attempt: if you had arithmetic count column, use it; otherwise crude estimate
            if "win_num_multdiv" in row:
                arithmetic_density = safe_div(getf("win_num_multdiv",0)+getf("win_num_bitops",0), total_tokens)

            branch_density = safe_div(num_br, total_tokens)
            # repetition / loop
            loop_repetition = getf("win_repetition_score", getf("win_repetition", getf("win_repetition_score",0)))

            features = {
                "xor_density": xor_density,
                "shift_density": shift_density,
                "arithmetic_density": arithmetic_density,
                "branch_density": branch_density,
                "loop_repetition": loop_repetition,
                "mnemonic_entropy": getf("win_mnemonic_entropy_mean", getf("win_token_entropy",0)),
                "stack_mutation_norm": safe_div(getf("win_stack_nonzero_sum", getf("win_stack_nz_sum",0)), max_stack),
                "stack_nonzero_total": getf("win_stack_nonzero_sum", getf("win_stack_nz_sum",0)),
                "syscall_send": getf("syscall_send_count", getf("syscall_send",0)),
                "syscall_recv": getf("syscall_recv_count", getf("syscall_recv",0)),
                "syscall_connect": getf("syscall_connect_count", getf("syscall_connect",0)),
                "syscall_close": getf("syscall_close_count", getf("syscall_close",0)),
                "hello_string": bool(row.get("presence_of_hello_string", row.get("hello_string",'False')) in ("True","true",True,1,"1")),
                "has_crypto_pattern": int(getf("win_has_crypto_pattern", getf("win_has_crypto_pattern",0)))
            }

            # compute stage scores and probabilities
            scores = compute_stage_scores(features)
            probs = softmax(scores)

            # pick predicted stage
            pred_stage, pred_stage_score = pick_max_key(probs)

            # behavior class: simple mapping
            behavior = "crypto_routine" if probs.get("ENCRYPTION",0.0) >= 0.5 or features["has_crypto_pattern"]==1 else \
                       ("handshake_logic" if pred_stage=="HANDSHAKE" else "data_or_control")

            # crypto detection: if encryption prob high OR has_crypto_pattern
            is_crypto = 1 if (probs.get("ENCRYPTION",0.0) > 0.5 or features["has_crypto_pattern"]==1 or features["xor_density"]>0.12) else 0
            crypto_conf = float(probs.get("ENCRYPTION",0.0) if is_crypto else max(probs.values()))

            # algorithm guess
            algo = guess_crypto_family({**features, "table_lookup_density": safe_float(row.get("table_lookup_density",0.0))})

            # anomalies
            anomalies = detect_anomalies(features, max_stack)

            # explain top factors (simple)
            explain = []
            if features["xor_density"]>0.1: explain.append("frequent XOR ops")
            if features["shift_density"]>0.1: explain.append("frequent SHIFT ops")
            if features["loop_repetition"]>ANOMALY_REPETITION_THRESHOLD: explain.append("strong block repetition")
            if features["stack_nonzero_total"]> (0.5*max_stack): explain.append("stack heavy mutation")

            # prepare output row
            out = dict(row)  # original columns
            out.update({
                "pred_HANDSHAKE": round(float(probs.get("HANDSHAKE",0)),6),
                "pred_KEY_EXCHANGE": round(float(probs.get("KEY_EXCHANGE",0)),6),
                "pred_ENCRYPTION": round(float(probs.get("ENCRYPTION",0)),6),
                "pred_DATA_TRANSFER": round(float(probs.get("DATA_TRANSFER",0)),6),
                "pred_CLEANUP": round(float(probs.get("CLEANUP",0)),6),
                "pred_stage": pred_stage,
                "pred_stage_confidence": round(float(pred_stage_score),6),

                "is_crypto": int(is_crypto),
                "crypto_confidence": round(float(crypto_conf),6),

                "algorithm_type": algo["type"],
                "algorithm_family": algo["algorithm"],
                "algorithm_confidence": round(float(algo["confidence"]),6),

                "anomalies": json.dumps(anomalies),
                "explain_top": "; ".join(explain)
            })

            writer.writerow(out)

            # write JSON report
            report = {
                "window_index": i,
                "features": features,
                "scores": scores,
                "probabilities": probs,
                "predicted_stage": pred_stage,
                "predicted_stage_confidence": pred_stage_score,
                "is_crypto": bool(is_crypto),
                "crypto_confidence": crypto_conf,
                "algorithm_guess": algo,
                "anomalies": anomalies,
                "explain_top": explain
            }
            with open(os.path.join(json_reports_dir, f"window_{i:06d}.json"), "w") as rf:
                json.dump(report, rf, indent=2)

    print("Wrote labeled CSV:", out_csv)
    print("Reports folder:", json_reports_dir)

# ---------------------------
# helpers for safe parsing
# ---------------------------
def safe_float(x):
    try:
        if x is None: return 0.0
        if isinstance(x,(int,float)): return float(x)
        return float(str(x).strip())
    except:
        return 0.0

# ---------------------------
# CLI
# ---------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input","-i", required=True, help="Input features CSV from extractor")
    p.add_argument("--out","-o", required=False, default="labeled_features.csv", help="Output CSV")
    p.add_argument("--reports","-r", required=False, default="reports", help="JSON reports dir")
    args=p.parse_args()
    label_csv(args.input, args.out, args.reports)

if __name__=="__main__":
    main()
