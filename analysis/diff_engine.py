import json
import glob
import os
import numpy as np
from collections import defaultdict

# Configuration
DATA_DIR = "ghidra_output"

def load_data(algo_name):
    files = glob.glob(os.path.join(DATA_DIR, f"{algo_name}_*.json"))
    data = []
    for f in files:
        with open(f, 'r') as json_file:
            data.append(json.load(json_file))
    return data

def extract_feature_vector(func_data):
    # Aggregate node level features for function-level stability analysis
    nodes = func_data["node_level"]
    
    # Averages across blocks
    avg_xor = np.mean([n["opcode_ratios"]["xor_ratio"] for n in nodes])
    avg_rot = np.mean([n["opcode_ratios"]["rotate_ratio"] for n in nodes])
    avg_add = np.mean([n["opcode_ratios"]["add_ratio"] for n in nodes])
    avg_mul = np.mean([n["opcode_ratios"]["multiply_ratio"] for n in nodes])
    avg_log = np.mean([n["opcode_ratios"]["logical_ratio"] for n in nodes])
    avg_ls = np.mean([n["opcode_ratios"]["load_store_ratio"] for n in nodes])
    
    total_hits = sum([n["crypto_constant_hits"] for n in nodes])
    has_lookup = any([n["table_lookup_presence"] for n in nodes])

    vec = {}
    vec["cyclomatic_complexity"] = func_data["graph_level"].get("cyclomatic_complexity", 0)
    vec["loop_count"] = func_data["graph_level"].get("loop_count", 0)
    vec["loop_depth"] = func_data["graph_level"].get("loop_depth", 0)
    vec["strongly_connected_components"] = func_data["graph_level"].get("strongly_connected_components", 0)
    vec["branch_density"] = func_data["graph_level"].get("branch_density", 0)
    vec["num_entry_exit_paths"] = func_data["graph_level"].get("num_entry_exit_paths", 0)
    
    vec["instruction_count"] = sum([n["instruction_count"] for n in nodes])
    vec["bitwise_op_density"] = np.mean([n["bitwise_op_density"] for n in nodes])
    vec["immediate_entropy"] = np.mean([n["immediate_entropy"] for n in nodes])
    
    # New Features
    vec["xor_ratio"] = avg_xor
    vec["rotate_ratio"] = avg_rot
    vec["add_ratio"] = avg_add
    vec["multiply_ratio"] = avg_mul
    vec["logical_ratio"] = avg_log
    vec["load_store_ratio"] = avg_ls
    
    vec["crypto_constant_hits"] = total_hits
    vec["table_lookup_presence"] = 1.0 if has_lookup else 0.0
    
    return vec

def analyze_stability(algo_name):
    print(f"Analyzing stability for {algo_name}...")
    raw_data = load_data(algo_name)
    
    if not raw_data:
        print("No data found.")
        return

    grouped_data = defaultdict(lambda: defaultdict(list))
    
    for entry in raw_data:
        parts = entry["binary"].replace(".json", "").split("_")
        if len(parts) < 4: continue
        arch = parts[1]
        opt = parts[-1]
        
        target_func = None
        for func in entry["functions"]:
            if algo_name.lower() in func["name"].lower():
                target_func = func
                break
        
        if target_func:
            grouped_data[arch][opt].append(extract_feature_vector(target_func))

    feature_keys = [
        "cyclomatic_complexity", "loop_count", "loop_depth", "strongly_connected_components", 
        "branch_density", "num_entry_exit_paths",
        "instruction_count", "bitwise_op_density", "immediate_entropy",
        "xor_ratio", "rotate_ratio", "add_ratio", "multiply_ratio", "logical_ratio", "load_store_ratio",
        "crypto_constant_hits", "table_lookup_presence"
    ]
    
    stability_scores = {k: {"cross_arch": [], "cross_opt": []} for k in feature_keys}

    # Cross-Arch
    all_opts = set()
    for arch in grouped_data:
        all_opts.update(grouped_data[arch].keys())
        
    for opt in all_opts:
        for key in feature_keys:
            values = []
            for arch in grouped_data:
                if opt in grouped_data[arch]:
                    vals = [x[key] for x in grouped_data[arch][opt]]
                    if vals: values.append(np.mean(vals))
            
            if len(values) > 1:
                mean_val = np.mean(values)
                if mean_val != 0:
                    cv = np.std(values) / mean_val
                    stability_scores[key]["cross_arch"].append(cv)
                elif np.std(values) == 0: # Both 0
                    stability_scores[key]["cross_arch"].append(0.0)

    # Cross-Opt
    for arch in grouped_data:
        for key in feature_keys:
            values = []
            for opt in grouped_data[arch]:
                 vals = [x[key] for x in grouped_data[arch][opt]]
                 if vals: values.append(np.mean(vals))
            
            if len(values) > 1:
                mean_val = np.mean(values)
                if mean_val != 0:
                    cv = np.std(values) / mean_val
                    stability_scores[key]["cross_opt"].append(cv)
                elif np.std(values) == 0:
                    stability_scores[key]["cross_opt"].append(0.0)

    print("\nStability Report (Lower Score = Higher Stability):")
    print(f"{'Feature':<25} | {'Arch Instability':<18} | {'Opt Instability':<18} | {'Status'}")
    print("-" * 80)
    
    for key in feature_keys:
        arch_score = np.mean(stability_scores[key]["cross_arch"]) if stability_scores[key]["cross_arch"] else 0.0
        opt_score = np.mean(stability_scores[key]["cross_opt"]) if stability_scores[key]["cross_opt"] else 0.0
        
        status = "LOW STABILITY"
        if arch_score < 0.5 and opt_score < 0.5:
            status = "HIGH STABILITY"
            
        print(f"{key:<25} | {arch_score:.4f}             | {opt_score:.4f}             | {status}")

if __name__ == "__main__":
    analyze_stability("aes")
    analyze_stability("sha256")
