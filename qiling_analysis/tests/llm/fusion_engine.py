#!/usr/bin/env python3
"""
STAGE 5 — LLM FUSION ENGINE (FINAL)

Inputs:
    yara_hits.json
    windows.jsonl
    strace.jsonl

Output:
    final_report.json

This engine:
  - loads static + dynamic + syscall features
  - creates a unified "evidence package"
  - constructs an LLM prompt
  - parses LLM output into a structured JSON report
"""

import json
import argparse
from pathlib import Path
from typing import Any, Dict, List
import datetime

# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def load_json(path: str) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def load_jsonl(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except:
                continue
    return out

# ---------------------------------------------------------
# Build full LLM prompt
# ---------------------------------------------------------

def build_llm_prompt(yara, windows, strace):
    """
    The LLM is given:
        - static crypto signatures
        - dynamic architectural features
        - syscall semantics
        - meta_scores (SPN, ARX, MODEXP, HASH, NTT)
    """

    prompt = f"""
You are a world-class firmware cryptography analyst. 
You must identify cryptographic algorithms using:

1. Static YARA signatures  
2. Dynamic code architecture from sliding windows  
3. Syscall behavior (entropy sources, memory protection, IO patterns)  
4. Meta crypto-family signals:
        - SPN_SCORE
        - ARX_SCORE
        - MODEXP_SCORE
        - HASH_SCORE
        - NTT_SCORE

─────────────────────────────────────────
STATIC YARA MATCHES:
{json.dumps(yara, indent=2)}

─────────────────────────────────────────
SYSCALL TRACE SUMMARY:
First 50 syscalls:
{json.dumps(strace[:50], indent=2)}

─────────────────────────────────────────
DYNAMIC WINDOWS (FEATURES):
(Showing up to 15 windows)
"""

    for w in windows[:15]:
        prompt += "\n--- WINDOW ---\n"
        prompt += json.dumps(w, indent=2) + "\n"

    prompt += """
─────────────────────────────────────────
TASK:
Analyze all data and produce classification:

For each window:
    - algorithm_label   (AES128, RSA, SHA256, ChaCha20, ECC, etc.)
    - crypto_family     (SPN, ARX, MODEXP, HASH, NTT)
    - proprietary_flag  (true/false)
    - proprietary_type  (PROPRIETARY_SPN, PROPRIETARY_ARX, etc.)
    - confidence        (0 to 1)

Global Decision:
    - primary_algorithm
    - crypto_family
    - variant
    - mode (CBC/CTR/GCM if block cipher)
    - proprietary? (true/false)
    - confidence
    - explanation

Output JSON ONLY in this format:

{
  "windows": [
     {
       "window_id": 0,
       "algorithm": "AES128",
       "crypto_family": "SPN",
       "proprietary": false,
       "confidence": 0.92
     }
  ],
  "primary_algorithm": "AES128",
  "crypto_family": "SPN",
  "variant": "AES-128",
  "mode": "CTR",
  "proprietary": false,
  "confidence": 0.94,
  "explanation": "..."
}
"""
    return prompt


# ---------------------------------------------------------
# Dummy LLM call (replace with your LLM)
# ---------------------------------------------------------

def call_llm(prompt: str) -> str:
    """
    Replace this with:
        - Gemini API call
        - OpenAI GPT call
        - Local Llama call
        - Anything you prefer

    For now we output a placeholder JSON so the pipeline runs.
    """
    fake = {
        "windows": [],
        "primary_algorithm": "UNKNOWN",
        "crypto_family": "UNKNOWN",
        "variant": "UNKNOWN",
        "mode": "UNKNOWN",
        "proprietary": False,
        "confidence": 0.0,
        "explanation": "Replace call_llm() with real LLM code."
    }
    return json.dumps(fake)


# ---------------------------------------------------------
# MAIN ENGINE
# ---------------------------------------------------------

def run_fusion_engine(yara_file, windows_file, strace_file, out_file):
    yara_hits = load_json(yara_file) or {}
    windows = load_jsonl(windows_file)
    strace = load_jsonl(strace_file)

    print(f"[*] Loaded {len(windows)} dynamic windows")
    print(f"[*] Loaded {len(strace)} syscalls")

    prompt = build_llm_prompt(yara_hits, windows, strace)

    print("[*] Calling LLM…")
    llm_output = call_llm(prompt)

    try:
        result = json.loads(llm_output)
    except:
        print("[-] LLM output was not valid JSON!")
        result = {"error": "invalid LLM response"}

    report = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "yara_hits": yara_hits,
        "result": result,
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Fusion analysis completed → {out_file}")


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="LLM Fusion Engine")
    p.add_argument("--yara", required=True, help="yara_hits.json")
    p.add_argument("--windows", required=True, help="windows.jsonl")
    p.add_argument("--strace", required=True, help="strace.jsonl")
    p.add_argument("--out", default="final_report.json", help="output JSON")
    args = p.parse_args()

    run_fusion_engine(args.yara, args.windows, args.strace, args.out)


if __name__ == "__main__":
    main()
