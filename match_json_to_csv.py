#!/usr/bin/env python3
"""
Script to match JSON features from Ghidra output to CSV format.

This script reads the features.csv file to understand which feature columns are needed,
then processes all JSON files in ghidra_output/ folder and extracts features for EACH FUNCTION
in each binary. It outputs one CSV row per function with all the function-level features.

Usage:
    python match_json_to_csv.py

The script will:
1. Read features.csv to get the list of feature columns
2. Process all JSON files in ghidra_output/
3. Extract features for EACH FUNCTION in each binary
4. Write results to features_output.csv (one row per function)

JSON file naming format: {algorithm}_{architecture}_{compiler}_{optimization}.elf.json
Example: aes128_ARM_clang_O1.elf.json
"""

import json
import csv
import os
from pathlib import Path
from collections import defaultdict


def parse_filename(filename):
    """
    Parse JSON filename to extract algorithm, architecture, compiler, and optimization.
    
    Filename format: {algorithm}_{architecture}_{compiler}_{optimization}.elf.json
    Examples:
        - aes128_ARM_clang_O1.elf.json
        - aes256_x86_gcc_O3.elf.json
        - rsa1024_MIPS_mips-linux-gnu-gcc_Os.elf.json
    
    Returns:
        tuple: (algorithm, architecture, compiler, optimization) or None if parsing fails
    """
    # Remove .elf.json extension
    name = filename.replace('.elf.json', '')
    
    # Split by underscore
    parts = name.split('_')
    
    if len(parts) < 4:
        return None
    
    # Algorithm is first part (e.g., aes128, rsa1024)
    algorithm = parts[0]
    
    # Architecture is second part (e.g., ARM, x86, MIPS, RISCV, AVR)
    architecture = parts[1]
    
    # Optimization is last part (e.g., O0, O1, O2, O3, Os)
    optimization = parts[-1]
    
    # Compiler is everything in between (handle multi-part compilers like mips-linux-gnu-gcc)
    compiler = '_'.join(parts[2:-1])
    
    return algorithm, architecture, compiler, optimization


def extract_graph_features(func):
    """
    Extract graph-level features from a single function.
    
    Args:
        func: Function dictionary from JSON
    
    Returns:
        dict: Graph-level features
    """
    graph = func.get('graph_level', {})
    
    return {
        'num_basic_blocks': graph.get('num_basic_blocks', 0),
        'num_edges': graph.get('num_edges', 0),
        'cyclomatic_complexity': graph.get('cyclomatic_complexity', 0),
        'loop_count': graph.get('loop_count', 0),
        'loop_depth': graph.get('loop_depth', 0),
        'branch_density': graph.get('branch_density', 0),
        'average_block_size': graph.get('average_block_size', 0),
        'num_entry_exit_paths': graph.get('num_entry_exit_paths', 0),
        'strongly_connected_components': graph.get('strongly_connected_components', 0),
    }


def extract_node_features(func):
    """
    Extract and aggregate node-level features from all nodes in a single function.
    
    Args:
        func: Function dictionary from JSON
    
    Returns:
        dict: Aggregated node-level features for the function
    """
    nodes = func.get('node_level', [])
    
    if not nodes:
        return {
            'instruction_count': 0,
            'xor_ratio': 0,
            'add_ratio': 0,
            'multiply_ratio': 0,
            'logical_ratio': 0,
            'load_store_ratio': 0,
            'bitwise_op_density': 0,
            'immediate_entropy': 0,
            'table_lookup_presence': 0,
            'crypto_constant_hits': 0,
            'branch_condition_complexity': 0,
            'opcode_histogram': {},
        }
    
    # Collect all node-level metrics
    instruction_count = []
    xor_ratio = []
    add_ratio = []
    multiply_ratio = []
    logical_ratio = []
    load_store_ratio = []
    bitwise_op_density = []
    immediate_entropy = []
    table_lookup_presence = []
    crypto_constant_hits = []
    branch_condition_complexity = []
    combined_opcode_histogram = {}
    
    for node in nodes:
        instruction_count.append(node.get('instruction_count', 0))
        
        # Opcode ratios
        opcode_ratios = node.get('opcode_ratios', {})
        xor_ratio.append(opcode_ratios.get('xor_ratio', 0))
        add_ratio.append(opcode_ratios.get('add_ratio', 0))
        multiply_ratio.append(opcode_ratios.get('multiply_ratio', 0))
        logical_ratio.append(opcode_ratios.get('logical_ratio', 0))
        load_store_ratio.append(opcode_ratios.get('load_store_ratio', 0))
        
        # Other node features
        bitwise_op_density.append(node.get('bitwise_op_density', 0))
        immediate_entropy.append(node.get('immediate_entropy', 0))
        table_lookup_presence.append(1 if node.get('table_lookup_presence', False) else 0)
        crypto_constant_hits.append(node.get('crypto_constant_hits', 0))
        branch_condition_complexity.append(node.get('branch_condition_complexity', 0))
        
        # Aggregate opcode histogram
        opcode_hist = node.get('opcode_histogram', {})
        for opcode, count in opcode_hist.items():
            combined_opcode_histogram[opcode] = combined_opcode_histogram.get(opcode, 0) + count
    
    # Helper to calculate mean
    def safe_mean(lst):
        return sum(lst) / len(lst) if lst else 0
    
    return {
        'instruction_count': sum(instruction_count),
        'xor_ratio': safe_mean(xor_ratio),
        'add_ratio': safe_mean(add_ratio),
        'multiply_ratio': safe_mean(multiply_ratio),
        'logical_ratio': safe_mean(logical_ratio),
        'load_store_ratio': safe_mean(load_store_ratio),
        'bitwise_op_density': safe_mean(bitwise_op_density),
        'immediate_entropy': safe_mean(immediate_entropy),
        'table_lookup_presence': safe_mean(table_lookup_presence),
        'crypto_constant_hits': sum(crypto_constant_hits),
        'branch_condition_complexity': safe_mean(branch_condition_complexity),
        'opcode_histogram': combined_opcode_histogram,
    }


def extract_edge_features(func):
    """
    Extract and aggregate edge-level features from a single function.
    
    Args:
        func: Function dictionary from JSON
    
    Returns:
        dict: Aggregated edge-level features for the function
    """
    edges = func.get('edge_level', [])
    
    if not edges:
        return {
            'edge_type': '',
            'is_loop_edge': 0,
        }
    
    edge_types = []
    is_loop_edge = []
    
    for edge in edges:
        edge_types.append(edge.get('edge_type', 'unknown'))
        is_loop_edge.append(1 if edge.get('is_loop_edge', False) else 0)
    
    # Count edge types
    edge_type_counts = {}
    for et in edge_types:
        edge_type_counts[et] = edge_type_counts.get(et, 0) + 1
    
    # Helper to calculate mean
    def safe_mean(lst):
        return sum(lst) / len(lst) if lst else 0
    
    return {
        'edge_type': str(edge_type_counts),  # Store as string representation
        'is_loop_edge': safe_mean(is_loop_edge),
    }


def extract_raw_opcode_counts(opcode_histogram):
    """
    Extract raw opcode counts from opcode_histogram.
    Maps Ghidra intermediate opcodes to architecture-specific operation categories.
    
    Args:
        opcode_histogram: Dictionary of opcode counts from JSON
    
    Returns:
        dict: Raw opcode counts
    """
    # Initialize all counts to 0
    raw_counts = {
        'count_mov': 0,
        'count_add': 0,
        'count_sub': 0,
        'count_mul': 0,
        'count_div': 0,
        'count_xor': 0,
        'count_and': 0,
        'count_or': 0,
        'count_not': 0,
        'count_shl': 0,
        'count_shr': 0,
        'count_ror': 0,
        'count_rol': 0,
        'count_cmp': 0,
        'count_jmp': 0,
        'count_call': 0,
        'count_ret': 0,
        'count_ldr': 0,
        'count_str': 0,
        'count_push': 0,
        'count_pop': 0,
    }
    
    # Map Ghidra opcodes to our categories
    for opcode, count in opcode_histogram.items():
        opcode_upper = opcode.upper()
        
        # MOV operations
        if 'COPY' in opcode_upper or 'MOV' in opcode_upper:
            raw_counts['count_mov'] += count
        
        # ADD operations
        if 'ADD' in opcode_upper:
            raw_counts['count_add'] += count
        
        # SUB operations
        if 'SUB' in opcode_upper:
            raw_counts['count_sub'] += count
        
        # MUL operations
        if 'MUL' in opcode_upper or 'MULT' in opcode_upper:
            raw_counts['count_mul'] += count
        
        # DIV operations
        if 'DIV' in opcode_upper or 'SDIV' in opcode_upper or 'UDIV' in opcode_upper:
            raw_counts['count_div'] += count
        
        # XOR operations
        if 'XOR' in opcode_upper:
            raw_counts['count_xor'] += count
        
        # AND operations
        if 'AND' in opcode_upper and 'BRANCH' not in opcode_upper:
            raw_counts['count_and'] += count
        
        # OR operations
        if 'OR' in opcode_upper and 'XOR' not in opcode_upper:
            raw_counts['count_or'] += count
        
        # NOT operations
        if 'NOT' in opcode_upper or 'NEGATE' in opcode_upper:
            raw_counts['count_not'] += count
        
        # Shift left
        if 'LEFT' in opcode_upper or 'SHL' in opcode_upper or 'LSL' in opcode_upper:
            raw_counts['count_shl'] += count
        
        # Shift right
        if 'RIGHT' in opcode_upper or 'SHR' in opcode_upper or 'LSR' in opcode_upper or 'ASR' in opcode_upper:
            raw_counts['count_shr'] += count
        
        # Rotate right
        if 'ROR' in opcode_upper or 'ROTR' in opcode_upper:
            raw_counts['count_ror'] += count
        
        # Rotate left
        if 'ROL' in opcode_upper or 'ROTL' in opcode_upper:
            raw_counts['count_rol'] += count
        
        # Compare operations
        if 'CMP' in opcode_upper or 'EQUAL' in opcode_upper or 'LESS' in opcode_upper or 'CARRY' in opcode_upper or 'BORROW' in opcode_upper:
            raw_counts['count_cmp'] += count
        
        # Jump/Branch operations
        if 'BRANCH' in opcode_upper or 'JUMP' in opcode_upper or 'JMP' in opcode_upper:
            raw_counts['count_jmp'] += count
        
        # Call operations
        if 'CALL' in opcode_upper or 'BL' in opcode_upper:
            raw_counts['count_call'] += count
        
        # Return operations
        if 'RETURN' in opcode_upper or 'RET' in opcode_upper:
            raw_counts['count_ret'] += count
        
        # Load operations
        if 'LOAD' in opcode_upper or 'LDR' in opcode_upper or 'LDM' in opcode_upper:
            raw_counts['count_ldr'] += count
        
        # Store operations
        if 'STORE' in opcode_upper or 'STR' in opcode_upper or 'STM' in opcode_upper:
            raw_counts['count_str'] += count
        
        # Push operations (usually part of store)
        if 'PUSH' in opcode_upper:
            raw_counts['count_push'] += count
        
        # Pop operations (usually part of load)
        if 'POP' in opcode_upper:
            raw_counts['count_pop'] += count
    
    return raw_counts


def extract_opcode_category_buckets(opcode_histogram):
    """
    Extract opcode category buckets from opcode histogram.
    
    Args:
        opcode_histogram: Dictionary of opcode counts
    
    Returns:
        dict: Opcode category bucket counts
    """
    categories = {
        'arithmetic_opcodes': 0,
        'logical_opcodes': 0,
        'memory_opcodes': 0,
        'control_flow_opcodes': 0,
        'comparison_opcodes': 0,
        'bitwise_opcodes': 0,
    }
    
    for opcode, count in opcode_histogram.items():
        opcode_upper = opcode.upper()
        
        # Arithmetic
        if any(x in opcode_upper for x in ['ADD', 'SUB', 'MUL', 'DIV', 'INC', 'DEC']):
            categories['arithmetic_opcodes'] += count
        
        # Logical
        if any(x in opcode_upper for x in ['AND', 'OR', 'NOT', 'NEGATE']) and 'BRANCH' not in opcode_upper:
            categories['logical_opcodes'] += count
        
        # Memory
        if any(x in opcode_upper for x in ['LOAD', 'STORE', 'PUSH', 'POP', 'LDR', 'STR', 'LDM', 'STM']):
            categories['memory_opcodes'] += count
        
        # Control flow
        if any(x in opcode_upper for x in ['BRANCH', 'CALL', 'RETURN', 'JUMP', 'JMP']):
            categories['control_flow_opcodes'] += count
        
        # Comparison
        if any(x in opcode_upper for x in ['EQUAL', 'LESS', 'CARRY', 'BORROW', 'CMP']):
            categories['comparison_opcodes'] += count
        
        # Bitwise
        if any(x in opcode_upper for x in ['XOR', 'LEFT', 'RIGHT', 'SHL', 'SHR', 'ROT', 'LSL', 'LSR', 'ASR', 'ROR']):
            categories['bitwise_opcodes'] += count
    
    return categories


def extract_features_for_function(func):
    """
    Extract all features from a single function.
    
    Args:
        func: Function dictionary from JSON
    
    Returns:
        dict: Dictionary of all features for this function
    """
    features = {}
    
    # Add function metadata
    features['function_name'] = func.get('name', '')
    features['function_address'] = func.get('address', '')
    
    # Graph-level features
    graph_features = extract_graph_features(func)
    features.update(graph_features)
    
    # Node-level features
    node_features = extract_node_features(func)
    features.update(node_features)
    
    # Edge-level features
    edge_features = extract_edge_features(func)
    features.update(edge_features)
    
    # Additional function-level features
    # Crypto signatures
    crypto_sig = func.get('crypto_signatures', {})
    features['has_aes_sbox'] = crypto_sig.get('has_aes_sbox', 0)
    features['rsa_bigint_detected'] = crypto_sig.get('rsa_bigint_detected', 0)
    features['has_aes_rcon'] = crypto_sig.get('has_aes_rcon', 0)
    features['has_sha_constants'] = crypto_sig.get('has_sha_constants', 0)
    
    # Data references
    data_refs = func.get('data_references', {})
    features['rodata_refs_count'] = data_refs.get('rodata_refs_count', 0)
    features['string_refs_count'] = data_refs.get('string_refs_count', 0)
    features['stack_frame_size'] = data_refs.get('stack_frame_size', 0)
    
    # Operation category counts
    op_cats = func.get('op_category_counts', {})
    features['bitwise_ops'] = op_cats.get('bitwise_ops', 0)
    features['crypto_like_ops'] = op_cats.get('crypto_like_ops', 0)
    features['arithmetic_ops'] = op_cats.get('arithmetic_ops', 0)
    features['mem_ops_ratio'] = op_cats.get('mem_ops_ratio', 0)
    
    # Instruction sequence
    inst_seq = func.get('instruction_sequence', {})
    features['unique_ngram_count'] = inst_seq.get('unique_ngram_count', 0)
    top_bigrams = inst_seq.get('top_5_bigrams', [])
    features['top_5_bigrams'] = str(top_bigrams) if top_bigrams else ''
    
    # Entropy metrics
    entropy = func.get('entropy_metrics', {})
    features['function_byte_entropy'] = entropy.get('function_byte_entropy', 0)
    features['opcode_entropy'] = entropy.get('opcode_entropy', 0)
    features['cyclomatic_complexity_density'] = entropy.get('cyclomatic_complexity_density', 0)
    
    # Label
    features['label'] = func.get('label', '')
    
    # Extract raw opcode counts from the opcode_histogram
    opcode_histogram = node_features.get('opcode_histogram', {})
    raw_opcode_counts = extract_raw_opcode_counts(opcode_histogram)
    
    # Combine raw opcode counts into ONE column as JSON string
    features['Raw opcode counts(count_mov, count_add, count_sub, count_mul, count_div, count_xor, count_and, count_or, count_not, count_shl, count_shr, count_ror, count_rol, count_cmp, count_jmp, count_call, count_ret, count_ldr, count_str, count_push, count_pop)'] = str(raw_opcode_counts)
    
    # Extract opcode category buckets and combine into ONE column
    opcode_categories = extract_opcode_category_buckets(opcode_histogram)
    features['Opcode category buckets'] = str(opcode_categories)
    
    # Combine N-gram features into ONE column
    ngram_features = {
        'unique_ngram_count': inst_seq.get('unique_ngram_count', 0),
        'top_5_bigrams': top_bigrams
    }
    features['N-gram features'] = str(ngram_features)
    
    # Total instructions (sum of all instruction counts)
    features['total_instructions'] = node_features.get('instruction_count', 0)
    
    # Binary-level features (these aren't in the current JSON at function level)
    # Setting to 0 or empty as placeholders - these would need to be extracted at binary level
    features['text_size'] = 0
    features['rodata_size'] = 0
    features['data_size'] = 0
    features['large_table_flag'] = 0
    features['string_count'] = features['string_refs_count']  # Use string_refs_count from data_references
    features['string_density'] = 0
    features['number_of_tables'] = 0
    
    return features


def extract_features_from_json(json_path):
    """
    Extract features from a JSON file for all functions.
    
    Args:
        json_path: Path to the JSON file
    
    Returns:
        list: List of feature dictionaries, one per function
    """
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        functions = data.get('functions', [])
        
        # Extract features for each function
        function_features = []
        for func in functions:
            features = extract_features_for_function(func)
            function_features.append(features)
        
        return function_features
        
    except Exception as e:
        print(f"  Error processing {json_path}: {e}")
        return []


def get_csv_feature_columns(csv_path):
    """
    Read the CSV file and extract the feature column names.
    
    Args:
        csv_path: Path to the CSV file
    
    Returns:
        list: List of feature column names (excluding arch, algo, optimization, compiler)
    """
    try:
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader)
            
        # Remove metadata columns (architecture, algorithm, optimization, compiler if present)
        metadata_columns = ['archietecture', 'architecture', 'algorithm', 'optimization', 'compiler']
        feature_columns = [h.strip() for h in headers if h.strip().lower() not in [m.lower() for m in metadata_columns]]
        
        return feature_columns
        
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return []


def map_feature_to_json(feature_name, json_features):
    """
    Map a CSV feature column name to the corresponding value from JSON features.
    
    Args:
        feature_name: Name of the feature column from CSV
        json_features: Dictionary of features extracted from JSON
    
    Returns:
        Feature value or empty string if not found
    """
    # Direct mapping for simple features
    if feature_name in json_features:
        value = json_features[feature_name]
        # Handle special cases like dict/list values
        if isinstance(value, (dict, list)):
            return str(value)
        return value
    
    # Handle special feature names or transformations
    # Add custom mappings here as needed
    
    return ''  # Return empty if feature not found


def process_all_json_files(json_dir, csv_feature_columns):
    """
    Process all JSON files in the directory and extract features for each function.
    
    Args:
        json_dir: Directory containing JSON files
        csv_feature_columns: List of feature column names from CSV
    
    Returns:
        list: List of dictionaries, each containing a row of data (one per function)
    """
    json_path = Path(json_dir)
    results = []
    
    # Process each JSON file
    for json_file in sorted(json_path.glob('*.json')):
        print(f"Processing: {json_file.name}")
        
        # Parse filename to get metadata
        parsed = parse_filename(json_file.name)
        if not parsed:
            print(f"  Skipping - unable to parse filename: {json_file.name}")
            continue
        
        algorithm, architecture, compiler, optimization = parsed
        
        # Extract features from JSON (returns list of function features)
        functions_features = extract_features_from_json(json_file)
        
        if not functions_features:
            print(f"  Warning: No functions found in {json_file.name}")
            continue
        
        # Create one row per function
        for func_features in functions_features:
            row = {
                'archietecture': architecture,
                'algorithm': algorithm.upper(),
                'optimization': optimization,
                'compiler': compiler,
            }
            
            # Map CSV feature columns to JSON features
            for feature_col in csv_feature_columns:
                row[feature_col] = map_feature_to_json(feature_col, func_features)
            
            results.append(row)
        
        print(f"  ✓ Extracted features from {len(functions_features)} functions")
    
    return results


def write_to_csv(results, output_path, csv_feature_columns):
    """
    Write results to CSV file.
    
    Args:
        results: List of dictionaries containing row data
        output_path: Path to output CSV file
        csv_feature_columns: List of feature column names
    """
    if not results:
        print("No results to write!")
        return
    
    # Define column order: metadata columns + feature columns
    columns = ['archietecture', 'algorithm', 'optimization', 'compiler'] + csv_feature_columns
    
    try:
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(results)
        
        print(f"\n✓ Successfully wrote {len(results)} rows to {output_path}")
        
    except Exception as e:
        print(f"Error writing CSV: {e}")


def main():
    """Main function to run the script."""
    
    # Define paths
    script_dir = Path(__file__).parent
    csv_path = script_dir / 'features.csv'
    json_dir = script_dir / 'ghidra_output'
    output_path = script_dir / 'features_output.csv'
    
    print("=" * 70)
    print("JSON to CSV Feature Matching Script")
    print("=" * 70)
    
    # Check if paths exist
    if not csv_path.exists():
        print(f"Error: CSV file not found at {csv_path}")
        return
    
    if not json_dir.exists():
        print(f"Error: JSON directory not found at {json_dir}")
        return
    
    # Step 1: Read CSV feature columns
    print(f"\n1. Reading feature columns from CSV: {csv_path}")
    csv_feature_columns = get_csv_feature_columns(csv_path)
    print(f"   Found {len(csv_feature_columns)} feature columns")
    
    if not csv_feature_columns:
        print("   Error: No feature columns found in CSV")
        return
    
    # Step 2: Process all JSON files
    print(f"\n2. Processing JSON files from: {json_dir}")
    results = process_all_json_files(json_dir, csv_feature_columns)
    
    if not results:
        print("   Error: No results generated")
        return
    
    # Step 3: Write results to CSV
    print(f"\n3. Writing results to: {output_path}")
    write_to_csv(results, output_path, csv_feature_columns)
    
    print("\n" + "=" * 70)
    print("Processing complete!")
    print("=" * 70)
    
    # Summary statistics
    architectures = set(r['archietecture'] for r in results)
    algorithms = set(r['algorithm'] for r in results)
    compilers = set(r['compiler'] for r in results)
    optimizations = set(r['optimization'] for r in results)
    
    # Count unique binaries
    binaries = set((r['algorithm'], r['archietecture'], r['compiler'], r['optimization']) for r in results)
    
    print(f"\nSummary:")
    print(f"  Total rows (functions): {len(results)}")
    print(f"  Total unique binaries: {len(binaries)}")
    print(f"  Architectures: {', '.join(sorted(architectures))}")
    print(f"  Algorithms: {', '.join(sorted(algorithms))}")
    print(f"  Compilers: {', '.join(sorted(compilers))}")
    print(f"  Optimizations: {', '.join(sorted(optimizations))}")


if __name__ == '__main__':
    main()
