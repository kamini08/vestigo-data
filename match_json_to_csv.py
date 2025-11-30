
# """
# Script to match JSON features from Ghidra output to CSV format.

# This script reads the features.csv file to understand which feature columns are needed,
# then processes all JSON files in ghidra_output/ folder and extracts features for EACH FUNCTION
# in each binary. It outputs one CSV row per function with all the function-level features.
# """

# import json
# import csv
# from pathlib import Path


# def parse_filename(filename):
#     """Parse filename into metadata fields."""
#     name = filename.replace('.elf.json', '')
#     parts = name.split('_')

#     if len(parts) < 4:
#         return None

#     algorithm = parts[0]
#     architecture = parts[1]
#     optimization = parts[-1]
#     compiler = '_'.join(parts[2:-1])

#     return algorithm, architecture, compiler, optimization


# def extract_graph_features(func):
#     graph = func.get('graph_level', {})
#     return {
#         'num_basic_blocks': graph.get('num_basic_blocks', 0),
#         'num_edges': graph.get('num_edges', 0),
#         'cyclomatic_complexity': graph.get('cyclomatic_complexity', 0),
#         'loop_count': graph.get('loop_count', 0),
#         'loop_depth': graph.get('loop_depth', 0),
#         'branch_density': graph.get('branch_density', 0),
#         'average_block_size': graph.get('average_block_size', 0),
#         'num_entry_exit_paths': graph.get('num_entry_exit_paths', 0),
#         'strongly_connected_components': graph.get('strongly_connected_components', 0),
#     }


# def extract_node_features(func):
#     nodes = func.get('node_level', [])

#     if not nodes:
#         return {
#             'instruction_count': 0,
#             'xor_ratio': 0,
#             'add_ratio': 0,
#             'multiply_ratio': 0,
#             'logical_ratio': 0,
#             'load_store_ratio': 0,
#             'bitwise_op_density': 0,
#             'immediate_entropy': 0,
#             'table_lookup_presence': 0,
#             'crypto_constant_hits': 0,
#             'branch_condition_complexity': 0,
#             'opcode_histogram': {},
#         }

#     instruction_count = []
#     xor_ratio = []
#     add_ratio = []
#     multiply_ratio = []
#     logical_ratio = []
#     load_store_ratio = []
#     bitwise_op_density = []
#     immediate_entropy = []
#     table_lookup_presence = []
#     crypto_constant_hits = []
#     branch_condition_complexity = []
#     combined_opcode_histogram = {}

#     for node in nodes:
#         instruction_count.append(node.get('instruction_count', 0))

#         opcode_ratios = node.get('opcode_ratios', {})
#         xor_ratio.append(opcode_ratios.get('xor_ratio', 0))
#         add_ratio.append(opcode_ratios.get('add_ratio', 0))
#         multiply_ratio.append(opcode_ratios.get('multiply_ratio', 0))
#         logical_ratio.append(opcode_ratios.get('logical_ratio', 0))
#         load_store_ratio.append(opcode_ratios.get('load_store_ratio', 0))

#         bitwise_op_density.append(node.get('bitwise_op_density', 0))
#         immediate_entropy.append(node.get('immediate_entropy', 0))
#         table_lookup_presence.append(1 if node.get('table_lookup_presence', False) else 0)
#         crypto_constant_hits.append(node.get('crypto_constant_hits', 0))
#         branch_condition_complexity.append(node.get('branch_condition_complexity', 0))

#         opcode_hist = node.get('opcode_histogram', {})
#         for opcode, count in opcode_hist.items():
#             combined_opcode_histogram[opcode] = combined_opcode_histogram.get(opcode, 0) + count

#     def mean(lst):
#         return sum(lst) / len(lst) if lst else 0

#     return {
#         'instruction_count': sum(instruction_count),
#         'xor_ratio': mean(xor_ratio),
#         'add_ratio': mean(add_ratio),
#         'multiply_ratio': mean(multiply_ratio),
#         'logical_ratio': mean(logical_ratio),
#         'load_store_ratio': mean(load_store_ratio),
#         'bitwise_op_density': mean(bitwise_op_density),
#         'immediate_entropy': mean(immediate_entropy),
#         'table_lookup_presence': mean(table_lookup_presence),
#         'crypto_constant_hits': sum(crypto_constant_hits),
#         'branch_condition_complexity': mean(branch_condition_complexity),
#         'opcode_histogram': combined_opcode_histogram,
#     }


# def extract_edge_features(func):
#     edges = func.get('edge_level', [])
#     if not edges:
#         return {'edge_type': '', 'is_loop_edge': 0}

#     edge_types = []
#     is_loop_edge = []

#     for edge in edges:
#         edge_types.append(edge.get('edge_type', 'unknown'))
#         is_loop_edge.append(1 if edge.get('is_loop_edge', False) else 0)

#     counts = {}
#     for et in edge_types:
#         counts[et] = counts.get(et, 0) + 1

#     def mean(lst):
#         return sum(lst) / len(lst) if lst else 0

#     return {
#         'edge_type': str(counts),
#         'is_loop_edge': mean(is_loop_edge),
#     }


# def extract_raw_opcode_counts(hist):
#     raw = {
#         'count_mov': 0, 'count_add': 0, 'count_sub': 0, 'count_mul': 0, 'count_div': 0,
#         'count_xor': 0, 'count_and': 0, 'count_or': 0, 'count_not': 0,
#         'count_shl': 0, 'count_shr': 0, 'count_ror': 0, 'count_rol': 0,
#         'count_cmp': 0, 'count_jmp': 0, 'count_call': 0, 'count_ret': 0,
#         'count_ldr': 0, 'count_str': 0, 'count_push': 0, 'count_pop': 0,
#     }

#     for opcode, count in hist.items():
#         u = opcode.upper()
#         if 'COPY' in u or 'MOV' in u: raw['count_mov'] += count
#         if 'ADD' in u: raw['count_add'] += count
#         if 'SUB' in u: raw['count_sub'] += count
#         if 'MUL' in u: raw['count_mul'] += count
#         if 'DIV' in u: raw['count_div'] += count
#         if 'XOR' in u: raw['count_xor'] += count
#         if 'AND' in u and 'BRANCH' not in u: raw['count_and'] += count
#         if 'OR' in u and 'XOR' not in u: raw['count_or'] += count
#         if 'NOT' in u: raw['count_not'] += count
#         if 'SHL' in u or 'LSL' in u or 'LEFT' in u: raw['count_shl'] += count
#         if 'SHR' in u or 'LSR' in u or 'ASR' in u or 'RIGHT' in u: raw['count_shr'] += count
#         if 'ROR' in u: raw['count_ror'] += count
#         if 'ROL' in u: raw['count_rol'] += count
#         if 'CMP' in u: raw['count_cmp'] += count
#         if 'JMP' in u or 'BRANCH' in u: raw['count_jmp'] += count
#         if 'CALL' in u or 'BL' in u: raw['count_call'] += count
#         if 'RET' in u: raw['count_ret'] += count
#         if 'LDR' in u or 'LOAD' in u: raw['count_ldr'] += count
#         if 'STR' in u or 'STORE' in u: raw['count_str'] += count
#         if 'PUSH' in u: raw['count_push'] += count
#         if 'POP' in u: raw['count_pop'] += count

#     return raw


# def extract_opcode_category_buckets(hist):
#     cat = {
#         'arithmetic_opcodes': 0,
#         'logical_opcodes': 0,
#         'memory_opcodes': 0,
#         'control_flow_opcodes': 0,
#         'comparison_opcodes': 0,
#         'bitwise_opcodes': 0,
#     }

#     for opcode, count in hist.items():
#         u = opcode.upper()
#         if any(x in u for x in ['ADD', 'SUB', 'MUL', 'DIV']): cat['arithmetic_opcodes'] += count
#         if any(x in u for x in ['AND', 'OR', 'NOT']): cat['logical_opcodes'] += count
#         if any(x in u for x in ['LOAD', 'STORE', 'LDR', 'STR', 'PUSH', 'POP']): cat['memory_opcodes'] += count
#         if any(x in u for x in ['BRANCH', 'JMP', 'CALL', 'RET']): cat['control_flow_opcodes'] += count
#         if 'CMP' in u: cat['comparison_opcodes'] += count
#         if any(x in u for x in ['XOR', 'SHL', 'SHR', 'ROR', 'ROL']): cat['bitwise_opcodes'] += count

#     return cat


# def extract_features_for_function(func):
#     features = {}

#     features['function_name'] = func.get('name', '')
#     features['function_address'] = func.get('address', '')
#     features['label'] = func.get('label', '')

#     features.update(extract_graph_features(func))
#     node = extract_node_features(func)
#     features.update(node)
#     features.update(extract_edge_features(func))

#     raw = extract_raw_opcode_counts(node['opcode_histogram'])
#     features['Raw opcode counts(count_mov, count_add, count_sub, count_mul, count_div, count_xor, count_and, count_or, count_not, count_shl, count_shr, count_ror, count_rol, count_cmp, count_jmp, count_call, count_ret, count_ldr, count_str, count_push, count_pop)'] = str(raw)

#     cat = extract_opcode_category_buckets(node['opcode_histogram'])
#     features['Opcode category buckets'] = str(cat)

#     ngram = {
#         'unique_ngram_count': features.get('unique_ngram_count', 0),
#         'top_5_bigrams': func.get('instruction_sequence', {}).get('top_5_bigrams', [])
#     }
#     features['N-gram features'] = str(ngram)

#     features['total_instructions'] = node['instruction_count']

#     features['text_size'] = 0
#     features['rodata_size'] = 0
#     features['data_size'] = 0
#     features['large_table_flag'] = 0
#     features['string_count'] = features.get('string_refs_count', 0)
#     features['string_density'] = 0
#     features['number_of_tables'] = 0

#     return features


# def extract_features_from_json(path):
#     try:
#         with open(path, 'r') as f:
#             data = json.load(f)

#         return [extract_features_for_function(func) for func in data.get('functions', [])]

#     except Exception as e:
#         print(f"Error processing {path}: {e}")
#         return []


# def get_csv_feature_columns(csv_path):
#     """Reads features.csv and returns feature column names (excluding metadata)."""

#     with open(csv_path, 'r') as f:
#         reader = csv.reader(f)
#         headers = next(reader)

#     metadata = [
#         'archietecture', 'architecture', 'algorithm', 'optimization', 'compiler',
#         'function_name', 'function_address', 'label'
#     ]

#     feature_cols = [h for h in headers if h.strip().lower() not in [m.lower() for m in metadata]]

#     return feature_cols


# def map_feature_to_json(feature, json_features):
#     value = json_features.get(feature, '')

#     if isinstance(value, (dict, list)):
#         return str(value)

#     return value


# def process_all_json_files(json_dir, csv_feature_columns):
#     """Processes all JSON files and produces list of rows."""

#     results = []

#     for file in sorted(Path(json_dir).glob("*.json")):
#         print(f"Processing: {file.name}")

#         parsed = parse_filename(file.name)
#         if not parsed:
#             print("  Skipped (bad filename format)")
#             continue

#         algorithm, architecture, compiler, optimization = parsed

#         functions = extract_features_from_json(file)

#         for func in functions:
#             row = {
#                 'archietecture': architecture,
#                 'algorithm': algorithm.upper(),
#                 'optimization': optimization,
#                 'compiler': compiler,

#                 # FIXED: add these missing metadata fields
#                 'function_name': func.get('function_name', ''),
#                 'function_address': func.get('function_address', ''),
#                 'label': func.get('label', ''),
#             }

#             for col in csv_feature_columns:
#                 row[col] = map_feature_to_json(col, func)

#             results.append(row)

#         print(f"  ✓ Extracted {len(functions)} functions")

#     return results


# def write_to_csv(rows, output_path, csv_feature_columns):
#     if not rows:
#         print("No results to write.")
#         return

#     columns = [
#         'archietecture', 'algorithm', 'optimization', 'compiler',
#         'function_name', 'function_address', 'label'
#     ] + csv_feature_columns

#     with open(output_path, 'w', newline='') as f:
#         writer = csv.DictWriter(f, fieldnames=columns)
#         writer.writeheader()
#         writer.writerows(rows)

#     print(f"\n✓ Wrote {len(rows)} rows to {output_path}")


# def main():
#     script_dir = Path(__file__).parent
#     csv_path = script_dir / "features.csv"
#     json_dir = script_dir / "ghidra_output"
#     output_path = script_dir / "features_output.csv"

#     print("Reading features.csv...")
#     feature_columns = get_csv_feature_columns(csv_path)

#     print("Processing JSON files...")
#     rows = process_all_json_files(json_dir, feature_columns)

#     print("Writing output CSV...")
#     write_to_csv(rows, output_path, feature_columns)

#     print("\nDone.")


# if __name__ == "__main__":
#     main()

import json
import csv
from pathlib import Path

# Node feature index → name mapping for your 9-dim vector
NODE_MAP = {
    0: "instruction_count",
    1: "xor_ratio",
    2: "immediate_entropy",
    3: "logical_ratio",
    4: "load_store_ratio",
    5: "bitwise_op_density",
    6: "table_lookup_presence",
    7: "crypto_constant_hits",
    8: "branch_condition_complexity"
}

# ---------------------------- CSV HEADER (GNN READY) ---------------------------- #

CSV_HEADER = [
    "architecture","algorithm","compiler","optimization","filename",
    "function_name","function_address","label",

    # Graph-level features
    "num_basic_blocks","num_edges","cyclomatic_complexity","loop_count","loop_depth",
    "branch_density","average_block_size","num_entry_exit_paths","strongly_connected_components",

    # Aggregated node-level features
    "instruction_count","xor_ratio","immediate_entropy","logical_ratio",
    "load_store_ratio","bitwise_op_density","table_lookup_presence",
    "crypto_constant_hits","branch_condition_complexity",

    # Aggregated edge-level features
    "num_conditional_edges","num_unconditional_edges",
    "num_loop_edges","avg_edge_branch_complexity"
]

# ---------------------------- NODE DECODING ---------------------------- #

def decode_node_list(node):
    """Convert list → feature dict using NODE_MAP."""
    out = {}
    for idx, name in NODE_MAP.items():
        out[name] = node[idx] if idx < len(node) else 0
    return out


def extract_nodes(nodes):
    """Aggregate node-level features."""
    agg = {name: [] for name in NODE_MAP.values()}

    for node in nodes:
        decoded = decode_node_list(node)
        for k, v in decoded.items():
            agg[k].append(v)

    def total(x): return sum(x) if x else 0
    def mean(x): return sum(x) / len(x) if x else 0

    return {
        "instruction_count": total(agg["instruction_count"]),
        "xor_ratio": mean(agg["xor_ratio"]),
        "immediate_entropy": mean(agg["immediate_entropy"]),
        "logical_ratio": mean(agg["logical_ratio"]),
        "load_store_ratio": mean(agg["load_store_ratio"]),
        "bitwise_op_density": mean(agg["bitwise_op_density"]),
        "table_lookup_presence": mean(agg["table_lookup_presence"]),
        "crypto_constant_hits": total(agg["crypto_constant_hits"]),
        "branch_condition_complexity": mean(agg["branch_condition_complexity"])
    }

# ---------------------------- EDGE AGGREGATION ---------------------------- #

def extract_edge_features(edges):
    cond = uncond = loop = 0
    bcc_values = []

    for e in edges:
        if e.get("edge_type") == "conditional":
            cond += 1
        elif e.get("edge_type") == "unconditional":
            uncond += 1

        if e.get("is_loop_edge"):
            loop += 1

        bcc_values.append(e.get("branch_condition_complexity", 0))

    avg_bcc = sum(bcc_values) / len(bcc_values) if bcc_values else 0

    return {
        "num_conditional_edges": cond,
        "num_unconditional_edges": uncond,
        "num_loop_edges": loop,
        "avg_edge_branch_complexity": avg_bcc
    }

# ---------------------------- FUNCTION PROCESSING ---------------------------- #

def process_function(func):
    metadata = func["metadata"]
    graph = func["graph_features"]

    node_stats = extract_nodes(func.get("nodes", []))
    edge_stats = extract_edge_features(func.get("edges", []))

    return {
        # Metadata
        "architecture": metadata.get("arch", ""),
        "algorithm": metadata.get("inferred_algo_from_file", ""),
        "compiler": metadata.get("compiler", ""),
        "optimization": metadata.get("opt", ""),
        "filename": metadata.get("filename", ""),
        "function_name": func["id"].split("::")[-1],
        "function_address": func.get("address", ""),
        "label": func.get("label", ""),

        # Graph features
        "num_basic_blocks": graph.get("num_basic_blocks", 0),
        "num_edges": graph.get("num_edges", 0),
        "cyclomatic_complexity": graph.get("cyclomatic_complexity", 0),
        "loop_count": graph.get("loop_count", 0),
        "loop_depth": graph.get("loop_depth", 0),
        "branch_density": graph.get("branch_density", 0),
        "average_block_size": graph.get("average_block_size", 0),
        "num_entry_exit_paths": graph.get("num_entry_exit_paths", 0),
        "strongly_connected_components": graph.get("strongly_connected_components", 0),

        # Node aggregates
        **node_stats,

        # Edge aggregates
        **edge_stats,
    }

# ---------------------------- JSON LOADER ---------------------------- #

def process_json_file(path):
    print(f"  → Reading {path.name}")
    with open(path, "r") as f:
        data = json.load(f)

    if isinstance(data, list):
        return [process_function(func) for func in data]

    print(f"❌ ERROR: {path.name} is not a JSON list.")
    return []

# ---------------------------- MAIN ---------------------------------- #

def main():
    json_dir = Path("ml/datasets/by_arch")
    out_csv = Path("features_output.csv")

    if not json_dir.exists():
        print(f"❌ ERROR: Directory does not exist → {json_dir.resolve()}")
        return

    files = list(json_dir.glob("*.json"))
    if not files:
        print("❌ ERROR: No JSON files found in by_arch/")
        return

    rows = []
    print(f"📂 Found {len(files)} JSON files\n")

    for jf in files:
        rows.extend(process_json_file(jf))

    print(f"\n✏ Writing CSV → {out_csv.resolve()}")
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n✔ DONE — Extracted {len(rows)} functions.")

if __name__ == "__main__":
    main()
