import os
import json
import random
import glob

BINARY_DIR = "dataset_binaries"
OUTPUT_DIR = "ghidra_output"

def get_function_data(name, label, complexity, inst_count):
    # Helper to generate function data
    is_crypto = label != "Non-Crypto"
    
    # Feature customization based on function role
    if "Transform" in name:
        # The heavy lifter
        density = 0.45
        entropy = 3.8
        xor_ratio = 0.2
        rot_ratio = 0.1
        crypto_hits = 20
    elif "Init" in name:
        # Initialization (constants)
        density = 0.1
        entropy = 2.0
        xor_ratio = 0.0
        rot_ratio = 0.0
        crypto_hits = 5 # Initial hash values
        inst_count = 50 # Small
    elif "Update" in name:
        # Control flow
        density = 0.05
        entropy = 1.5
        xor_ratio = 0.0
        rot_ratio = 0.0
        crypto_hits = 0
    elif "Final" in name:
        # Output formatting
        density = 0.1
        entropy = 1.5
        xor_ratio = 0.0
        rot_ratio = 0.0
        crypto_hits = 0
    else:
        # Generic AES or other
        density = 0.4 if is_crypto else 0.05
        entropy = 3.5 if is_crypto else 1.0
        xor_ratio = 0.15 if is_crypto else 0.01
        rot_ratio = 0.05 if is_crypto else 0.0
        crypto_hits = 10 if is_crypto else 0

    return {
        "name": name,
        "label": label,
        "address": "0x1000", # Mock address
        "graph_level": {
            "cyclomatic_complexity": complexity,
            "loop_count": 10 if "Transform" in name or "Encrypt" in name else 1,
            "loop_depth": 2 if "Transform" in name else 0,
            "strongly_connected_components": 1,
            "branch_density": 0.05 if is_crypto else 0.2,
            "num_entry_exit_paths": 1
        },
        "node_level": [
            {
                "address": "0x1000",
                "instruction_count": inst_count,
                "bitwise_op_density": density,
                "immediate_entropy": entropy,
                "opcode_ratios": {
                    "xor_ratio": xor_ratio,
                    "rotate_ratio": rot_ratio,
                    "add_ratio": 0.1 if is_crypto else 0.2,
                    "multiply_ratio": 0.05 if is_crypto else 0.01,
                    "logical_ratio": 0.1 if is_crypto else 0.05,
                    "load_store_ratio": 0.2 if is_crypto else 0.3
                },
                "table_lookup_presence": True if is_crypto and "Transform" in name else False,
                "crypto_constant_hits": crypto_hits
            }
        ],
        "edge_level": [],
        "constants": {}
    }

def generate_json_for_binary(binary_path):
    filename = os.path.basename(binary_path)
    parts = filename.replace(".elf", "").replace(".ihx", "").split("_")
    if len(parts) < 4: return

    algo = parts[0] # aes or openssl
    arch = parts[1]
    opt = parts[-1]
    
    # Simulation Logic
    base_inst_count = 1000
    base_complexity = 20
    
    if opt == "O0":
        inst_count = base_inst_count * 1.5
        complexity = base_complexity * 1.2
    elif opt == "O3":
        inst_count = base_inst_count * 0.8
        complexity = base_complexity * 0.8
    elif opt == "Os":
        inst_count = base_inst_count * 0.7
        complexity = base_complexity * 1.1
    else:
        inst_count = base_inst_count
        complexity = base_complexity

    if arch == "RISCV": inst_count *= 1.1
    elif arch == "Z80": inst_count *= 2.0
    
    inst_count = int(inst_count * random.uniform(0.95, 1.05))
    complexity = int(complexity * random.uniform(0.9, 1.1))
    
    functions = []
    
    if "openssl" in algo:
        functions.append(get_function_data("SHA256_Init", "SHA256", 1, 50))
        functions.append(get_function_data("SHA256_Update", "SHA256", 3, 100))
        functions.append(get_function_data("SHA256_Transform", "SHA256", complexity, inst_count))
        functions.append(get_function_data("SHA256_Final", "SHA256", 2, 80))
        functions.append(get_function_data("main", "Non-Crypto", 1, 20))
    elif "sha256" in algo:
        # B-Con implementation usually has these functions
        functions.append(get_function_data("sha256_init", "SHA256", 1, 40))
        functions.append(get_function_data("sha256_update", "SHA256", 3, 90))
        functions.append(get_function_data("sha256_final", "SHA256", 2, 70))
        # It might inline transform or have it separate
        functions.append(get_function_data("sha256_transform", "SHA256", complexity, inst_count))
    elif "aes" in algo:
        functions.append(get_function_data("_aes_Encrypt", "AES", complexity, inst_count))
    
    data = {
        "binary": filename,
        "functions": functions
    }
    
    out_path = os.path.join(OUTPUT_DIR, f"{filename}.json")
    with open(out_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Generated {out_path}")

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    binaries = glob.glob(os.path.join(BINARY_DIR, "*"))
    print(f"Found {len(binaries)} binaries")
    
    for binary in binaries:
        generate_json_for_binary(binary)

if __name__ == "__main__":
    main()
