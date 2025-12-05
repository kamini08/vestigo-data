#!/usr/bin/env python3
"""
feature_extractor.py

Dynamic feature extractor for protocol-stage + crypto-stage analysis.
Uses Qiling JSONL execution trace as input.

OUTPUT: final_features.csv (window-level features)
"""

import json, re, csv, math
from pathlib import Path
from collections import Counter
from datetime import datetime
import numpy as np

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------
# Resolve paths relative to this script's directory to avoid CWD issues
SCRIPT_DIR = Path(__file__).parent
ROOT_DIR = SCRIPT_DIR.parent

# Use script-relative paths only (no environment overrides)
INPUT_JSONL = str(SCRIPT_DIR / "rsa_64_mips_gcc_O0_20251204_050527.jsonl")
OUTPUT_CSV = str(ROOT_DIR / "features.csv")
VOCAB_JSON = str(ROOT_DIR / "vocab.json")

WINDOW_SIZE = 128
STRIDE = 64
PAD_ID = 0
UNK_ID = 1
TOPK = 128

BRANCH_OPS = {"beq", "bne", "bgtz", "bltz", "blez", "bgez"}
JUMP_OPS = {"j", "jal", "jr", "jalr"}
MEMORY_OPS = {"lw", "sw", "lb", "sb", "lbu", "lhu", "sh"}
BIT_OPS = {"xor", "and", "or", "nor"}
SHIFT_OPS = {"sll", "srl", "sra", "rotr"}
MULT_DIV_OPS = {"mult", "div", "multu", "divu"}
BIG_INT_OPS = {"addc", "adde", "subc", "sube", "mulh", "mulhu"}

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def clean_mn(m):
    if not m: return ""
    m = m.lower().strip()
    return re.sub(r"[^a-z0-9_]", "", m)

def entropy(seq):
    if not seq: return 0.0
    c = Counter(seq)
    total = sum(c.values())
    return -sum((v/total) * math.log2(v/total) for v in c.values())

def transition_entropy(seq):
    if len(seq) < 2: return 0.0
    bigrams = [(seq[i], seq[i+1]) for i in range(len(seq)-1)]
    return entropy(bigrams)

def slope(values):
    n=len(values)
    if n < 2: return 0.0
    x_mean=(n-1)/2
    y_mean=sum(values)/n
    num=sum((i-x_mean)*(values[i]-y_mean) for i in range(n))
    den=sum((i-x_mean)**2 for i in range(n))
    return num/den if den!=0 else 0.0

def parse_ts(ts):
    try:
        return int(ts)
    except:
        return int(datetime.fromisoformat(ts).timestamp()*1000)

# ---------------------------------------------------------
# LOAD EVENTS
# ---------------------------------------------------------

events=[]
with open(INPUT_JSONL,"r") as f:
    for line in f:
        if not line.strip(): continue
        o=json.loads(line)
        d=o["data"]
        mn=[clean_mn(x) for x in d.get("mnemonics_simple",[])]
        events.append({
            "seq":o["seq"],
            "ts":o.get("timestamp_ms",0),
            "addr":d["address"],
            "size":d["size"],
            "mn":mn,
            "hash":d["bytes_hash"],
            "ic":d["instruction_count"],
            "reg":d.get("register_state",{}),
            "mem":d.get("memory_state",{}),
            "meta":d.get("metadata",{})
        })

events=sorted(events,key=lambda x:x["ts"])

# ---------------------------------------------------------
# BUILD VOCAB
# ---------------------------------------------------------

cnt=Counter()
for e in events:
    cnt.update(e["mn"])
common=[op for op,_ in cnt.most_common(TOPK)]

vocab={"<PAD>":PAD_ID,"<UNK>":UNK_ID}
i=2
for op in common:
    vocab[op]=i; i+=1
inv_vocab={v:k for k,v in vocab.items()}

with open(VOCAB_JSON,"w") as f:
    json.dump(vocab,f,indent=2)

# ---------------------------------------------------------
# BLOCK-LEVEL FEATURE EXTRACTION
# ---------------------------------------------------------

blocks=[]
prev_stack_hash=None
prev_ts=None

for e in events:
    mn=e["mn"]
    c=Counter(mn)

    num_br = sum(c[m] for m in BRANCH_OPS)
    num_jp = sum(c[m] for m in JUMP_OPS)
    num_mem= sum(c[m] for m in MEMORY_OPS)
    num_bit= sum(c[m] for m in BIT_OPS)
    num_sh = sum(c[m] for m in SHIFT_OPS)
    num_md = sum(c[m] for m in MULT_DIV_OPS)
    num_bg = sum(c[m] for m in BIG_INT_OPS)

    # timing
    ts=e["ts"]
    dt = ts - prev_ts if prev_ts is not None else 0
    prev_ts=ts

    # registers
    rv=list(e["reg"].values())
    r_nonzero=sum(1 for v in rv if v not in ("0x0","0x00","0"))
    r_ratio=r_nonzero/max(1,len(rv))
    r_entropy=entropy(rv)

    # memory
    mem=e["mem"]
    stack_nz = mem.get("stack_nonzero_bytes",0)
    stack_hash = mem.get("stack_hash")
    stack_change = 1 if (stack_hash and prev_stack_hash and stack_hash!=prev_stack_hash) else 0
    prev_stack_hash = stack_hash or prev_stack_hash

    blocks.append({
        "mn":mn,
        "hash":e["hash"],
        "addr":e["addr"],
        "ic":e["ic"],
        "mn_ent":entropy(mn),
        "mn_trans_ent":transition_entropy(mn),
        "num_br":num_br,
        "num_jp":num_jp,
        "num_mem":num_mem,
        "num_bit":num_bit,
        "num_sh":num_sh,
        "num_md":num_md,
        "num_bg":num_bg,
        "dt":dt,
        "stack_nz":stack_nz,
        "stack_change":stack_change,
        "reg_ratio":r_ratio,
        "reg_ent":r_entropy,
        "has_crypto":1 if e["meta"].get("has_crypto_pattern") else 0,
    })

# ---------------------------------------------------------
# TOKEN STREAM
# ---------------------------------------------------------

tokens=[]
addr_stream=[]
hash_stream=[]
crypto_flag=[]

for b in blocks:
    if not b["mn"]:
        tokens.append(PAD_ID)
        addr_stream.append(b["addr"])
        hash_stream.append(b["hash"])
        crypto_flag.append(b["has_crypto"])
    else:
        for m in b["mn"]:
            tokens.append(vocab.get(m,UNK_ID))
            addr_stream.append(b["addr"])
            hash_stream.append(b["hash"])
            crypto_flag.append(b["has_crypto"])

tokens=np.array(tokens)

# ---------------------------------------------------------
# PER-TOKEN SCALAR STREAMS
# ---------------------------------------------------------

t_dt=[]; t_ic=[]; t_mnent=[]; t_stack=[]; t_reg=[]

for b in blocks:
    rep=max(1,len(b["mn"]))
    t_dt.extend([b["dt"]]*rep)
    t_ic.extend([b["ic"]]*rep)
    t_mnent.extend([b["mn_ent"]]*rep)
    t_stack.extend([b["stack_nz"]]*rep)
    t_reg.extend([b["reg_ratio"]]*rep)

t_dt=np.array(t_dt,float)
t_ic=np.array(t_ic,float)
t_mnent=np.array(t_mnent,float)
t_stack=np.array(t_stack,float)
t_reg=np.array(t_reg,float)
crypto_flag=np.array(crypto_flag)

# ---------------------------------------------------------
# WINDOWING + WINDOW FEATURES
# ---------------------------------------------------------

starts=list(range(0,max(1,len(tokens)-WINDOW_SIZE+1),STRIDE))
if len(tokens)<WINDOW_SIZE: starts=[0]

header=[f"t{i}" for i in range(WINDOW_SIZE)] + [
    "win_num_tokens","win_unique_tokens","win_token_entropy",
    "win_mnemonic_entropy_mean","win_opcode_transition_entropy",
    "win_num_branches","win_num_jumps","win_num_memory",
    "win_num_bitops","win_num_shiftops","win_num_multdiv",
    "win_num_bigint","win_ic_sum","win_dt_sum",
    "win_stack_nz_sum","win_reg_ratio_mean",
    "win_repetition_score","win_addr_entropy",
    "win_loop_estimate","win_branch_density",
    "win_entropy_slope",
    "label_crypto"
]

with open(OUTPUT_CSV,"w",newline="") as f:
    w=csv.writer(f); w.writerow(header)

    for s in starts:
        e=s+WINDOW_SIZE
        win=tokens[s:e]
        if len(win)<WINDOW_SIZE:
            win=np.concatenate([win,np.zeros(WINDOW_SIZE-len(win),int)])

        real_len=min(WINDOW_SIZE,len(tokens)-s)

        uniq=len(set(win[:real_len]))
        tok_ent=entropy(win[:real_len])

        # opcode transition entropy
        ops=[inv_vocab.get(int(t),"<UNK>") for t in win[:real_len]]
        opc_ent=transition_entropy(ops)

        # aggregated stats
        ic_sum=float(np.sum(t_ic[s:e]))
        dt_sum=float(np.sum(t_dt[s:e]))
        mn_mean=float(np.mean(t_mnent[s:e]))
        mn_slope=slope(t_mnent[s:e])

        # ctrl-flow & op counts
        mn_ops=ops
        num_br=sum(m in BRANCH_OPS for m in mn_ops)
        num_jp=sum(m in JUMP_OPS for m in mn_ops)
        num_mem=sum(m in MEMORY_OPS for m in mn_ops)
        num_bit=sum(m in BIT_OPS for m in mn_ops)
        num_sh =sum(m in SHIFT_OPS for m in mn_ops)
        num_md =sum(m in MULT_DIV_OPS for m in mn_ops)
        num_bg =sum(m in BIG_INT_OPS for m in mn_ops)

        # repetition & loop
        hashes=hash_stream[s:e]
        rep_score=max(Counter(hashes).values())

        addrs=addr_stream[s:e]
        addr_ent=entropy(addrs)
        loop_est=sum(1 for v in Counter(addrs).values() if v>1)

        stack_sum=float(np.sum(t_stack[s:e]))
        reg_mean=float(np.mean(t_reg[s:e]))

        branch_density=num_br/max(1,real_len)

        crypto_label=int(bool(np.any(crypto_flag[s:e])))

        row=list(map(int,win))+[
            real_len, uniq, tok_ent,
            mn_mean, opc_ent,
            num_br, num_jp, num_mem,
            num_bit, num_sh, num_md,
            num_bg, ic_sum, dt_sum,
            stack_sum, reg_mean,
            rep_score, addr_ent,
            loop_est, branch_density,
            mn_slope,
            crypto_label
        ]
        w.writerow(row)

print("[DONE] Feature extraction complete.")
