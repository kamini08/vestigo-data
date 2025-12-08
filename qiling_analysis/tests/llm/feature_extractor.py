#!/usr/bin/env python3
"""
Stage 4 - FEATURE EXTRACTION + NORMALIZATION (FINAL VERSION)

Input:
  - trace.jsonl  (dynamic basic_block events from Qiling/PANDA)

Output:
  - windows.jsonl  (one JSON record per sliding window)

Each window record contains:
  - core densities (bitops, shifts, memory, bigint, branches, ...)
  - table_lookup_density (S-box / T-table heuristic)
  - repetition / entropy / exec_hotness
  - opcode_histogram & opcode_density
  - ngrams_2 / ngrams_3 over mnemonics
  - structural_signals (xor_heavy, rotate_heavy, mul_heavy, bigint_heavy, ...)
  - meta_scores:
        SPN_SCORE      (AES-like SPN / block cipher style)
        MODEXP_SCORE   (RSA/BigInt modular arithmetic style)
        HASH_SCORE     (SHA/MD5/Keccak/MDS mixing style)
        ARX_SCORE      (ChaCha/Salsa/Blake/PRNG-like ARX)
        NTT_SCORE      (very rough: poly/FFT/NTT-ish behavior)

These meta_scores are *not* final algorithm labels.
They are "architecture family" hints for the LLM / later fusion stages.
"""

import json
import argparse
from pathlib import Path
from collections import Counter
import math
from typing import Dict, Any, List, Tuple, Iterable

# -------------------- CONFIG -------------------- #

DEFAULT_WINDOW = 128   # number of basic_block events per window
DEFAULT_STRIDE = 64
TOP_K_NGRAMS = 8       # top-k opcode n-grams to keep


# -------------------- OPCODE CATEGORIES -------------------- #
"""
We operate on mnemonics_simple from Qiling traces and classify them into
coarse functional buckets.

You can extend this per architecture (ARM, MIPS, RISC-V) by adding prefixes.
"""

OPCODES = {
    "xor":    ("eor", "xor", "xori", "pxor"),
    "and":    ("and", "andi"),
    "or":     ("orr", "ori"),
    "shift":  ("shl", "shr", "sll", "srl", "sra", "rol", "ror", "rotr",
               "lsl", "lsr", "rcl", "rcr"),
    "add":    ("add", "addi", "adc"),
    "sub":    ("sub", "subi", "sbc"),
    "mul":    ("mul", "imul", "umull", "madd", "mulh", "mulhu"),
    "div":    ("div", "idiv", "udiv", "mod", "rem"),
    "load":   ("ldr", "ld", "lw", "lbu", "lb", "ldrb", "ldrh", "load"),
    "store":  ("str", "st", "sw", "sb", "strb", "strh", "store"),
    "branch": ("b", "bl", "beq", "bne", "jmp", "ret", "call",
               "j", "je", "jne", "jg", "jl"),
}
OPCODE_CATS = list(OPCODES.keys()) + ["other"]


# -------------------- BASIC HELPERS -------------------- #

def clean_mn(m: str) -> str:
    """
    Normalize mnemonic to a simplified, architecture-agnostic-ish form.
    E.g.: "add.w" -> "add", "ldr.w" -> "ldr"
    """
    if not m:
        return ""
    m = str(m).lower()
    m = m.split(".")[0]
    m = m.split("_")[0]
    return m


def classify_opcode(m: str) -> str:
    """
    Map raw mnemonic into coarse opcode category.
    """
    for cat, ops in OPCODES.items():
        if any(m.startswith(o) for o in ops):
            return cat
    return "other"


def ngrams(seq: List[str], n: int) -> List[Tuple[str, ...]]:
    if len(seq) < n:
        return []
    return [tuple(seq[i:i + n]) for i in range(len(seq) - n + 1)]


def entropy_of_list(seq: List[Any]) -> float:
    if not seq:
        return 0.0
    c = Counter(seq)
    total = len(seq)
    ent = 0.0
    for v in c.values():
        p = v / total
        ent -= p * math.log2(p)
    return ent


def g(d: Dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(d.get(key, default))
    except Exception:
        return default


# -------------------- TRACE LOADING -------------------- #

def load_events_from_trace(path: Path) -> List[Dict[str, Any]]:
    """
    Load Qiling/PANDA JSONL trace and normalize into a list of events:

    {
      "seq": int,
      "mn": [ "mov", "add", ... ],
      "execution_count": int,
      "instruction_count": int,
      "bytes_hash": "..."
    }

    We only care about type == "basic_block" entries.
    """
    events: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue

            if o.get("type") != "basic_block":
                continue

            d = o.get("data", {}) or {}
            mn = d.get("mnemonics_simple") or d.get("mnemonics") or []
            if isinstance(mn, str):
                mn = [mn]

            events.append({
                "seq": o.get("seq"),
                "mn": [clean_mn(m) for m in mn],
                "execution_count": int(d.get("execution_count", 1) or 1),
                "instruction_count": int(d.get("instruction_count", 0) or 0),
                "bytes_hash": d.get("bytes_hash"),
            })
    return events


# -------------------- META SCORES (CRYPTO FAMILIES) -------------------- #

def compute_meta_scores(features: Dict[str, Any]) -> Dict[str, float]:
    """
    Compute "crypto architecture family" scores:
      - SPN_SCORE    : AES-like S-box + mixing rounds
      - MODEXP_SCORE : BigInt modular exponentiation style (RSA/ECC core)
      - HASH_SCORE   : SHA/MD5/Keccak/MDS-like compression
      - ARX_SCORE    : ChaCha/Salsa/Blake/PRNG ARX style
      - NTT_SCORE    : Coarse heuristic for NTT/FFT-like patterns

    These are soft signals in [0, 1], not final labels.
    """

    bitop = g(features, "bitop_density")
    shift = g(features, "shift_density")
    memory = g(features, "memory_access_density")
    bigint = g(features, "bigint_density")
    rep = g(features, "round_repetition_score")
    tld = g(features, "table_lookup_density")
    entropy = g(features, "opcode_entropy")
    total_instr = g(features, "total_instructions")
    exec_hot = g(features, "exec_hotness")

    struct = features.get("structural_signals", {}) or {}
    xor_heavy = bool(struct.get("xor_heavy", False))
    rotate_heavy = bool(struct.get("rotate_heavy", False))
    mul_heavy = bool(struct.get("mul_heavy", False))
    bigint_heavy = bool(struct.get("bigint_heavy", False))
    table_like = bool(struct.get("table_lookup_like", False))

    # --- SPN_SCORE: AES-like / block cipher core --- #
    spn = 0.0
    # table-based AES / S-box
    spn += 0.25 * min(1.0, tld / 0.25)
    spn += 0.15 * min(1.0, memory / 0.3)
    # bitsliced or constant-time AES
    spn += 0.20 * min(1.0, bitop / 0.25)
    spn += 0.20 * min(1.0, rep / 0.12)
    # entropy band typical for AES inner loops
    if 2.0 <= entropy <= 3.3:
        spn += 0.10
    # not big-int like
    spn += 0.10 * (1.0 - min(1.0, bigint / 0.05))
    if table_like:
        spn += 0.05
    spn_score = max(0.0, min(spn, 1.0))

    # --- MODEXP_SCORE: BigInt / RSA / ECC modular arithmetic --- #
    modexp = 0.0
    modexp += 0.45 * min(1.0, bigint / 0.05)
    modexp += 0.20 * min(1.0, memory / 0.4)
    modexp += 0.20 * min(1.0, exec_hot / 0.5)
    modexp += 0.10 * min(1.0, total_instr / 800.0)
    if bigint_heavy:
        modexp += 0.05
    if mul_heavy:
        modexp += 0.05
    # ARX-ish signatures are not typical for big-int code
    if xor_heavy or rotate_heavy:
        modexp *= 0.85
    modexp_score = max(0.0, min(modexp, 1.0))

    # --- HASH_SCORE: SHA/MD5/Keccak/MDS-like --- #
    hash_s = 0.0
    hash_s += 0.30 * min(1.0, bitop / 0.30)
    hash_s += 0.20 * min(1.0, shift / 0.18)
    hash_s += 0.15 * min(1.0, rep / 0.10)
    hash_s += 0.10 * (1.0 - min(1.0, tld / 0.2))     # avoid strong S-box tables
    hash_s += 0.10 * (1.0 - min(1.0, bigint / 0.05)) # not big-int heavy
    if 1.4 <= entropy <= 3.5:
        hash_s += 0.10
    if rotate_heavy:
        hash_s += 0.05
    hash_score = max(0.0, min(hash_s, 1.0))

    # --- ARX_SCORE: ChaCha/Salsa/Blake/PRNG-like --- #
    arx = 0.0
    arx += 0.35 * min(1.0, (bitop + shift) / 0.45)
    arx += 0.25 * min(1.0, rep / 0.08)
    arx += 0.20 * (1.0 - min(1.0, bigint / 0.04))
    arx += 0.10 * (1.0 - min(1.0, tld / 0.25))
    if rotate_heavy:
        arx += 0.10
    arx_score = max(0.0, min(arx, 1.0))

    # --- NTT_SCORE: extremely rough heuristic for NTT/FFT-ish code --- #
    # We can't see index patterns here, but we can look for:
    #   - mix of mul + add/sub
    #   - moderate bigint_density (but not full RSA-level)
    #   - decent memory traffic (array-ish)
    #   - moderate repetition (stage loops)
    ntt = 0.0
    ntt += 0.25 * min(1.0, mul_heavy * 1.0 + bigint * 10.0)
    ntt += 0.20 * min(1.0, memory / 0.35)
    ntt += 0.20 * min(1.0, rep / 0.08)
    # mildly bigint but not full-blown RSA style
    if 0.01 <= bigint <= 0.06:
        ntt += 0.20
    # entropy in mid-ish range (lots of structured mixing)
    if 1.2 <= entropy <= 3.0:
        ntt += 0.15
    ntt_score = max(0.0, min(ntt, 1.0))

    return {
        "SPN_SCORE": round(spn_score, 4),
        "MODEXP_SCORE": round(modexp_score, 4),
        "HASH_SCORE": round(hash_score, 4),
        "ARX_SCORE": round(arx_score, 4),
        "NTT_SCORE": round(ntt_score, 4),
    }


# -------------------- WINDOW FEATURE COMPUTATION -------------------- #

def compute_window_features(events_slice: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute all dynamic features for a single sliding window of basic_block events.
    """
    flat_mn: List[str] = []
    exec_counts: List[int] = []
    block_hashes: List[str] = []

    for e in events_slice:
        flat_mn.extend(e["mn"])
        exec_counts.append(int(e["execution_count"]))
        block_hashes.append(e["bytes_hash"])

    total_instr = len(flat_mn) or 1

    # Opcode histogram & densities
    opcode_hist = Counter(classify_opcode(m) for m in flat_mn)

    opcode_density: Dict[str, float] = {}
    for cat in OPCODE_CATS:
        opcode_density[cat] = round(opcode_hist.get(cat, 0) / total_instr, 6)

    # Synthetic densities
    bitop_density = round(
        (opcode_hist.get("xor", 0) +
         opcode_hist.get("and", 0) +
         opcode_hist.get("or", 0)) / total_instr, 6
    )
    shift_density = opcode_density["shift"]
    memory_access_density = round(
        (opcode_hist.get("load", 0) + opcode_hist.get("store", 0)) / total_instr, 6
    )
    bigint_density = round(
        (opcode_hist.get("mul", 0) + opcode_hist.get("div", 0)) / total_instr, 6
    )
    branch_density = opcode_density["branch"]

    loads = opcode_hist.get("load", 0)
    stores = opcode_hist.get("store", 0)
    stores_safe = stores if stores > 0 else 1
    load_store_ratio = round(loads / stores_safe, 6)

    # Approx table lookup density:
    # - many loads, few stores -> likely table lookups (S-boxes, T-tables)
    if loads > stores:
        table_lookup_density = round(min(1.0, memory_access_density * 1.2), 6)
    else:
        table_lookup_density = round(memory_access_density * 0.5, 6)

    # N-grams
    n2 = Counter(ngrams(flat_mn, 2)).most_common(TOP_K_NGRAMS)
    n3 = Counter(ngrams(flat_mn, 3)).most_common(TOP_K_NGRAMS)
    ngrams_2 = [list(t) for t, _ in n2]
    ngrams_3 = [list(t) for t, _ in n3]

    # Repetition & block hash entropy
    bh = [b for b in block_hashes if b]
    repetition_score = 0.0
    block_hash_entropy = 0.0
    if bh:
        c = Counter(bh)
        repetition_score = max(c.values()) / len(events_slice)
        block_hash_entropy = entropy_of_list(bh)

    # Opcode entropy
    opcode_entropy = entropy_of_list(
        [classify_opcode(m) for m in flat_mn]
    )

    # Exec hotness
    exec_hotness = 0.0
    if exec_counts:
        exec_hotness = min(1.0, max(exec_counts) / 200.0)

    # Structural boolean signals
    structural_signals = {
        "xor_heavy": bitop_density > 0.20,
        "rotate_heavy": shift_density > 0.12,
        "mul_heavy": opcode_density.get("mul", 0.0) > 0.04,
        "bigint_heavy": bigint_density > 0.06,
        "table_lookup_like": table_lookup_density > 0.25,
        "branchy": branch_density > 0.10,
    }

    features: Dict[str, Any] = {
        # core densities
        "bitop_density": bitop_density,
        "shift_density": shift_density,
        "memory_access_density": memory_access_density,
        "bigint_density": bigint_density,
        "branch_density": branch_density,
        "load_store_ratio": load_store_ratio,
        "table_lookup_density": table_lookup_density,

        # repetition / entropy / volume / hotness
        "round_repetition_score": round(repetition_score, 6),
        "block_hash_entropy": round(block_hash_entropy, 6),
        "opcode_entropy": round(opcode_entropy, 6),
        "total_instructions": total_instr,
        "exec_hotness": round(exec_hotness, 6),

        # opcode-level details
        "opcode_histogram": dict(opcode_hist),
        "opcode_density": opcode_density,

        # n-grams
        "ngrams_2": ngrams_2,
        "ngrams_3": ngrams_3,

        # structural flags
        "structural_signals": structural_signals,
    }

    # Attach meta crypto-family scores
    features["meta_scores"] = compute_meta_scores(features)

    return features


# -------------------- WINDOWING OVER EVENTS -------------------- #

def windows_from_events(events: List[Dict[str, Any]],
                        window_size: int,
                        stride: int) -> Iterable[Tuple[int, int, List[Dict[str, Any]]]]:
    """
    Slide a window over the sequence of events.
    Yields: (start_index, end_index, events_slice)
    """
    n = len(events)
    if n == 0:
        return

    if n <= window_size:
        yield 0, n - 1, events
        return

    for s in range(0, n - window_size + 1, stride):
        e = s + window_size - 1
        yield s, e, events[s:e + 1]


# -------------------- MAIN PIPELINE -------------------- #

def process_trace(trace_path: str,
                  out_path: str,
                  window_size: int,
                  stride: int) -> None:
    trace_p = Path(trace_path)
    out_p = Path(out_path)

    if not trace_p.exists():
        print(f"[-] Trace file not found: {trace_p}")
        return

    print(f"[*] Loading trace from: {trace_p}")
    events = load_events_from_trace(trace_p)
    print(f"[+] Loaded {len(events)} basic_block events")

    count_windows = 0
    with out_p.open("w", encoding="utf-8") as outf:
        for ws, we, win in windows_from_events(events, window_size, stride):
            feats = compute_window_features(win)

            # Attach provenance info
            feats["seq_start"] = win[0]["seq"]
            feats["seq_end"] = win[-1]["seq"]
            feats["window_start_index"] = ws
            feats["window_end_index"] = we

            outf.write(json.dumps(feats) + "\n")
            count_windows += 1

    print(f"[ok] wrote {count_windows} windows -> {out_p}")


def main():
    p = argparse.ArgumentParser(
        description="Stage 4 - Feature Extraction + Normalization from trace.jsonl"
    )
    p.add_argument("--trace", required=True,
                   help="Input dynamic trace JSONL (basic_block events)")
    p.add_argument("--out", default="windows.jsonl",
                   help="Output windows JSONL file")
    p.add_argument("--window-size", type=int, default=DEFAULT_WINDOW,
                   help="Number of events per window")
    p.add_argument("--stride", type=int, default=DEFAULT_STRIDE,
                   help="Stride between windows (events)")
    args = p.parse_args()

    process_trace(args.trace, args.out, args.window_size, args.stride)


if __name__ == "__main__":
    main()
