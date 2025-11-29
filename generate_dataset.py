#!/usr/bin/env python3
"""
generate_dataset.py

Process all JSON files in ghidra_output/, extract features for each function using OpenAI,
and generate a complete CSV dataset for ML training.

Filename format: {algorithm}_{architecture}_{compiler}_{optimization}.elf.json
Output: One CSV row per function with all features from features.txt plus label column.

Usage:
  export OPENAI_API_KEY="sk-..."
  python3 generate_dataset.py --input-dir ghidra_output --output dataset_output.csv
"""
import os
import json
import csv
import argparse
import logging
import glob
import re
from pathlib import Path

try:
    import openai
except ImportError:
    print("Missing 'openai' package. Install with: pip install openai")
    raise

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configure logging
logging.basicConfig(
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)
logger = logging.getLogger('generate-dataset')

# Feature columns from features.txt
FEATURE_COLUMNS = [
    'architecture', 'algorithm', 'compiler', 'optimization', 'filename',
    'function_name', 'function_address', 'label',
    'num_basic_blocks', 'num_edges', 'cyclomatic_complexity', 'loop_count',
    'loop_depth', 'branch_density', 'average_block_size', 'num_entry_exit_paths',
    'strongly_connected_components', 'instruction_count', 'immediate_entropy',
    'bitwise_op_density', 'table_lookup_presence', 'crypto_constant_hits',
    'branch_condition_complexity', 'add_ratio', 'logical_ratio', 'load_store_ratio',
    'xor_ratio', 'multiply_ratio', 'rotate_ratio', 'num_conditional_edges',
    'num_unconditional_edges', 'num_loop_edges', 'avg_edge_branch_condition_complexplexity',
    'has_aes_sbox', 'rsa_bigint_detected', 'has_aes_rcon', 'has_sha_constants',
    'rodata_refs_count', 'string_refs_count', 'stack_frame_size', 'bitwise_ops',
    'crypto_like_ops', 'arithmetic_ops', 'mem_ops_ratio', 'function_byte_entropy',
    'opcode_entropy', 'cyclomatic_complexity_density', 'unique_ngram_count'
]

# Algorithm label mapping (filename prefix → CSV label)
ALGORITHM_MAP = {
    'aes128': 'AES-128',
    'aes192': 'AES-192',
    'aes256': 'AES-256',
    'ecc': 'ECC',
    'prng': 'PRNG',
    'rsa1024': 'RSA-1024',
    'rsa4096': 'RSA-4096',
    'sha1': 'SHA-1',
    'sha224': 'SHA-224',
    'xor': 'MD5(XOR)',
}


def parse_filename(filename):
    """
    Parse filename like 'aes128_ARM_clang_O0.elf.json' into metadata dict.
    Returns: {'algorithm': 'aes128', 'architecture': 'ARM', 'compiler': 'clang', 'optimization': 'O0'}
    """
    basename = Path(filename).stem.replace('.elf', '')
    parts = basename.split('_')
    if len(parts) < 4:
        logger.warning('Unexpected filename format: %s', filename)
        return {}
    return {
        'algorithm': parts[0].lower(),
        'architecture': parts[1],
        'compiler': parts[2],
        'optimization': parts[3]
    }


def extract_features_from_function(func_data):
    """
    Extract available features from the function JSON data into a dict.
    Returns a dict mapping feature column names to values (or None if not present).
    """
    features = {}
    
    # function-level
    features['function_name'] = func_data.get('name')
    features['function_address'] = func_data.get('address')
    
    # graph_level
    graph = func_data.get('graph_level', {}) or {}
    features['num_basic_blocks'] = graph.get('num_basic_blocks')
    features['num_edges'] = graph.get('num_edges')
    features['cyclomatic_complexity'] = graph.get('cyclomatic_complexity')
    features['loop_count'] = graph.get('loop_count')
    features['loop_depth'] = graph.get('loop_depth')
    features['branch_density'] = graph.get('branch_density')
    features['average_block_size'] = graph.get('average_block_size')
    features['num_entry_exit_paths'] = graph.get('num_entry_exit_paths')
    features['strongly_connected_components'] = graph.get('strongly_connected_components')
    
    # advanced_features
    adv = func_data.get('advanced_features', {}) or {}
    features['rodata_refs_count'] = adv.get('rodata_refs_count')
    features['string_refs_count'] = adv.get('string_refs_count')
    features['stack_frame_size'] = adv.get('stack_frame_size')
    features['has_aes_sbox'] = adv.get('has_aes_sbox')
    features['has_aes_rcon'] = adv.get('has_aes_rcon')
    features['rsa_bigint_detected'] = adv.get('bigint_op_count', 0) > 0 if adv.get('bigint_op_count') is not None else None
    
    # node_level aggregated (if array provided)
    node_level = func_data.get('node_level', [])
    if isinstance(node_level, list) and len(node_level) > 0:
        # aggregate statistics from node_level array
        total_instr = sum(n.get('instruction_count', 0) for n in node_level)
        features['instruction_count'] = total_instr
        # immediate_entropy: average if present
        entropies = [n.get('immediate_entropy') for n in node_level if n.get('immediate_entropy') is not None]
        features['immediate_entropy'] = sum(entropies) / len(entropies) if entropies else None
        # bitwise_op_density: average
        densities = [n.get('bitwise_op_density') for n in node_level if n.get('bitwise_op_density') is not None]
        features['bitwise_op_density'] = sum(densities) / len(densities) if densities else None
        # table_lookup_presence: any node has it
        features['table_lookup_presence'] = any(n.get('table_lookup_presence') for n in node_level)
        # crypto_constant_hits: sum
        features['crypto_constant_hits'] = sum(n.get('crypto_constant_hits', 0) for n in node_level)
    
    # edge_level aggregated (if array provided)
    edge_level = func_data.get('edge_level', [])
    if isinstance(edge_level, list) and len(edge_level) > 0:
        features['num_conditional_edges'] = sum(1 for e in edge_level if e.get('edge_type') == 'conditional')
        features['num_unconditional_edges'] = sum(1 for e in edge_level if e.get('edge_type') == 'unconditional')
        features['num_loop_edges'] = sum(1 for e in edge_level if e.get('is_loop_edge'))
        complexities = [e.get('branch_condition_complexity') for e in edge_level if e.get('branch_condition_complexity') is not None]
        features['avg_edge_branch_condition_complexplexity'] = sum(complexities) / len(complexities) if complexities else None
    
    return features


def call_openai_for_classification(func_data, metadata, extracted_features, api_key=None):
    """
    Call OpenAI to classify the function and fill any missing features.
    
    Returns a dict with all feature columns filled (or empty string if unavailable).
    """
    key = api_key or os.getenv('OPENAI_API_KEY')
    if not key:
        raise RuntimeError('OPENAI_API_KEY not set')
    
    # Decide which client to use
    use_new = hasattr(openai, 'OpenAI') and hasattr(openai, '__version__') and int(openai.__version__.split('.')[0]) >= 1
    
    # Prepare prompt
    algo_ground_truth = metadata.get('algorithm', 'unknown')
    expected_label = ALGORITHM_MAP.get(algo_ground_truth, 'Non-Crypto')
    
    prompt_text = f"""You are analyzing a function from a binary compiled with:
- Architecture: {metadata.get('architecture')}
- Compiler: {metadata.get('compiler')}
- Optimization: {metadata.get('optimization')}
- Ground truth algorithm: {expected_label}

Function data (JSON):
{json.dumps(func_data, indent=2)[:2000]}

Already extracted features (may be incomplete):
{json.dumps(extracted_features, indent=2)}

Task:
1) Classify this function: is it a crypto function implementing the ground-truth algorithm, or is it Non-Crypto (helper/library function)?
2) For each feature in the list below, provide a value. If a feature is already extracted, keep it. If missing, infer from the function data or mark as 'false' (for boolean) or leave empty.

Required features (must return ALL):
{', '.join(FEATURE_COLUMNS[8:])}  # skip metadata columns

Output format (strict JSON):
{{
  "label": "AES-128" or "Non-Crypto" or one of ["AES-128", "AES-192", "AES-256", "ECC", "PRNG", "RSA-1024", "RSA-4096", "SHA-1", "SHA-224", "MD5(XOR)"],
  "features": {{
    "num_basic_blocks": <value or null>,
    "num_edges": <value or null>,
    ...
    "unique_ngram_count": <value or null>
  }}
}}

Rules:
- label: if the function implements crypto logic for the ground-truth algorithm, use the algorithm label; else "Non-Crypto"
- For boolean features (has_aes_sbox, rsa_bigint_detected, etc.), return true/false or 1/0.
- For numeric features, return the number or null if unavailable.
- Do NOT invent data; if a feature is not computable from the JSON, return null or false.
"""

    messages = [
        {'role': 'system', 'content': 'You are a binary analysis assistant. Return only valid JSON.'},
        {'role': 'user', 'content': prompt_text}
    ]
    
    try:
        if use_new:
            client = openai.OpenAI(api_key=key)
            resp = client.chat.completions.create(
                model='gpt-4',
                messages=messages,
                temperature=0.0,
                max_tokens=1500
            )
            content = resp.choices[0].message.content
        else:
            openai.api_key = key
            resp = openai.ChatCompletion.create(
                model='gpt-4',
                messages=messages,
                temperature=0.0,
                max_tokens=1500
            )
            content = resp['choices'][0]['message']['content']
        
        # Parse JSON response
        # Strip markdown code fences if present
        content = content.strip()
        if content.startswith('```'):
            lines = content.splitlines()
            content = '\n'.join(lines[1:-1]) if len(lines) > 2 else content
        
        result = json.loads(content)
        return result
    
    except Exception as e:
        logger.error('OpenAI call failed: %s', str(e).splitlines()[0])
        # Return a default dict with label=Non-Crypto and features empty
        return {'label': 'Non-Crypto', 'features': {}}


def process_file(json_path, api_key=None, batch_size=5):
    """
    Process one JSON file: parse filename, load functions, classify each function via LLM.
    Returns a list of CSV row dicts.
    """
    metadata = parse_filename(os.path.basename(json_path))
    if not metadata:
        logger.warning('Skipping file with unparseable name: %s', json_path)
        return []
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        logger.error('Failed to load JSON %s: %s', json_path, e)
        return []
    
    functions = data.get('functions', [])
    if not functions:
        logger.warning('No functions found in %s', json_path)
        return []
    
    rows = []
    logger.info('Processing %s: %d functions', os.path.basename(json_path), len(functions))
    
    # Process in small batches to manage token limits
    for i in range(0, len(functions), batch_size):
        batch = functions[i:i+batch_size]
        for func in batch:
            # Extract what we can locally
            local_features = extract_features_from_function(func)
            
            # Call LLM for classification + missing features
            try:
                llm_result = call_openai_for_classification(func, metadata, local_features, api_key=api_key)
            except Exception as e:
                logger.error('LLM call failed for function %s: %s', func.get('name'), str(e).splitlines()[0])
                llm_result = {'label': 'Non-Crypto', 'features': {}}
            
            label = llm_result.get('label', 'Non-Crypto')
            llm_features = llm_result.get('features', {})
            
            # Merge: local_features + llm_features → final row
            row = {
                'architecture': metadata.get('architecture', ''),
                'algorithm': metadata.get('algorithm', ''),
                'compiler': metadata.get('compiler', ''),
                'optimization': metadata.get('optimization', ''),
                'filename': os.path.basename(json_path),
                'function_name': func.get('name', ''),
                'function_address': func.get('address', ''),
                'label': label
            }
            
            # Fill feature columns: prefer local, fallback to LLM, then empty
            for col in FEATURE_COLUMNS[8:]:  # skip first 8 metadata/label columns
                val = local_features.get(col)
                if val is None:
                    val = llm_features.get(col)
                # Convert booleans to string or 'false' default
                if val is None:
                    if col.startswith('has_') or col.endswith('_detected') or col == 'table_lookup_presence':
                        val = 'false'
                    else:
                        val = ''
                elif isinstance(val, bool):
                    val = 'true' if val else 'false'
                row[col] = str(val) if val != '' else ''
            
            rows.append(row)
    
    return rows


def main():
    parser = argparse.ArgumentParser(description='Generate ML dataset CSV from ghidra_output JSONs')
    parser.add_argument('--input-dir', default='ghidra_output', help='Directory containing JSON files')
    parser.add_argument('--output', '-o', default='dataset_output.csv', help='Output CSV file')
    parser.add_argument('--api-key', default=None, help='OpenAI API key')
    parser.add_argument('--batch-size', type=int, default=5, help='Functions per LLM call batch')
    parser.add_argument('--limit', type=int, default=None, help='Limit number of files to process (for testing)')
    args = parser.parse_args()
    
    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        logger.error('Input directory not found: %s', input_dir)
        return
    
    # Find all JSON files
    json_files = sorted(input_dir.glob('*.json'))
    if args.limit:
        json_files = json_files[:args.limit]
    
    logger.info('Found %d JSON files to process', len(json_files))
    
    all_rows = []
    for idx, json_path in enumerate(json_files, 1):
        logger.info('[%d/%d] Processing %s...', idx, len(json_files), json_path.name)
        rows = process_file(str(json_path), api_key=args.api_key, batch_size=args.batch_size)
        all_rows.extend(rows)
        logger.info('  → Extracted %d function rows', len(rows))
    
    # Write CSV
    output_path = Path(args.output)
    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()
        writer.writerows(all_rows)
    
    logger.info('Wrote %d rows to %s', len(all_rows), output_path)


if __name__ == '__main__':
    main()
