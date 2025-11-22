import json
import math
from collections import Counter

# -----------------------------
#  CRYPTO CONSTANT SIGNATURES
# -----------------------------

AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
])

AES_INVSBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
])

AES_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])

DES_SBOX_FRAGMENT = bytes([0x0e, 0x04, 0x0d, 0x01])  # common in DES sboxes

CHACHA20_CONST = b"expand 32-byte k"

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf
]

MD5_T = [
    0xd76aa478, 0xe8c7b756, 0x242070db
]

SHA1_K_FRAGMENT = bytes([0x5A, 0x82, 0x79, 0x99])


# -----------------------------
# HELPERS
# -----------------------------

def contains(blob, constant):
    return 1 if bytes(constant) in blob else 0


def entropy(data):
    if not data:
        return 0
    freq = Counter(data)
    e = 0.0
    for c in freq.values():
        p = c / len(data)
        e -= p * math.log2(p)
    return e


# -----------------------------
# FEATURE EXTRACTION FUNCTION
# -----------------------------

def extract_features(binary_path, ghidra_json):
    with open(binary_path, "rb") as f:
        blob = f.read()

    with open(ghidra_json, "r") as f:
        gh = json.load(f)

    features = {}

    # -----------------------------
    # A. BINARY SIGNATURES
    # -----------------------------
    features["has_aes_sbox"] = contains(blob, AES_SBOX)
    features["has_aes_invsbox"] = contains(blob, AES_INVSBOX)
    features["has_aes_rcon"] = contains(blob, AES_RCON)
    features["has_des_sbox"] = contains(blob, DES_SBOX_FRAGMENT)
    features["has_chacha_const"] = contains(blob, CHACHA20_CONST)
    features["has_sha1_k"] = contains(blob, SHA1_K_FRAGMENT)
    features["has_sha256_k"] = contains(blob, bytes.fromhex("428a2f98"))
    features["has_md5_t"] = contains(blob, bytes.fromhex("d76aa478"))
    features["rsa_bigint_detected"] = 1 if b"\x00\x01\x00\x01" in blob or b"\x30\x82" in blob else 0

    features["file_size"] = len(blob)
    features["entropy_full"] = entropy(blob)

    # Sliding-window entropy (strong crypto → high & stable)
    window = 2048
    ent_windows = []
    for i in range(0, len(blob), window):
        ent_windows.append(entropy(blob[i:i+window]))

    features["entropy_mean"] = sum(ent_windows)/len(ent_windows)
    features["entropy_max"] = max(ent_windows)
    features["entropy_min"] = min(ent_windows)

    # -----------------------------
    # B. INSTRUCTION HISTOGRAM
    # -----------------------------
    instr_counts = Counter()

    for fn in gh["functions"]:
        for bb in fn["basicBlocks"]:
            for ins in bb["instructions"]:
                op = ins["op"].lower()
                instr_counts[op] += 1

    # collapse into crypto-relevant groups
    def count_ops(substrs):
        return sum(count for op, count in instr_counts.items()
                   if any(s in op for s in substrs))

    features.update({
        "op_xor": count_ops(["xor", "eor"]),
        "op_and": count_ops(["and"]),
        "op_or":  count_ops(["orr"]),
        "op_shift": count_ops(["lsl", "lsr", "asr", "ror"]),
        "op_load": count_ops(["ldr"]),
        "op_store": count_ops(["str"]),
        "op_add": count_ops(["add"]),
        "op_sub": count_ops(["sub"]),
        "op_mul": count_ops(["mul", "smull", "umull"]),
        "op_table_lookup": count_ops(["ldr", "[pc"])  # table accesses
    })

    # -----------------------------
    # C. STRUCTURAL FEATURES
    # -----------------------------
    features["num_functions"] = len(gh["functions"])
    features["num_basic_blocks"] = sum(len(fn["basicBlocks"]) for fn in gh["functions"])

    # Loop count (simple heuristic)
    loop_count = 0
    for fn in gh["functions"]:
        for bb in fn["basicBlocks"]:
            for ins in bb["instructions"]:
                if "bne" in ins["op"].lower() or "beq" in ins["op"].lower():
                    loop_count += 1
    features["loop_count"] = loop_count

    return features


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    feat = extract_features(
        "bin/aes_128_arm_gcc_O0.elf",
        "ghidra_output.json"
    )

    with open("features.json", "w") as f:
        json.dump(feat, f, indent=2)

    print("[+] Full crypto feature set extracted → features.json")
