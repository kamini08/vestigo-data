#!/usr/bin/env python3
"""
Enhanced Training Dataset Generator

Generates ML-ready JSONL dataset with:
1. Instruction sequences
2. Operation patterns
3. Structural features (SPN, NTT, MODEXP, Feistel)
4. Runtime characteristics (memory access, timing, footprint)
5. Instruction grouping for round detection
"""

import json
import argparse
from pathlib import Path
from typing import List, Dict, Any
from collections import Counter


def generate_enhanced_jsonl(trace_path: str, 
                            windowed_features_path: str,
                            output_path: str,
                            label: str):
    """
    Generate enhanced JSONL training dataset
    
    Args:
        trace_path: Path to trace.jsonl
        windowed_features_path: Path to windowed features JSON
        output_path: Path to output JSONL file
        label: Crypto algorithm label (e.g., 'AES128', 'RSA2048', 'KYBER512')
    """
    
    # Load trace
    trace_events = []
    with open(trace_path, 'r') as f:
        for line in f:
            trace_events.append(json.loads(line))
    
    # Load windowed features (support both JSONL and JSON dict formats)
    windows = []
    with open(windowed_features_path, 'r') as f:
        first_line = f.readline()
        if not first_line:
            print("[!] Warning: Empty windowed features file")
            return
        
        # Reset file pointer
        f.seek(0)
        
        # Try to detect format
        try:
            # Try parsing as JSON dict first
            f.seek(0)
            windowed_data = json.load(f)
            windows = windowed_data.get('windows', [])
        except json.JSONDecodeError:
            # It's JSONL format - one window per line
            f.seek(0)
            for line in f:
                if line.strip():
                    windows.append(json.loads(line))
    
    if not windows:
        print("[!] Warning: No windows found in windowed features file")
        return
    
    # Generate enhanced entries
    enhanced_entries = []
    
    for window_idx, window_features in enumerate(windows):
        # Extract instruction sequences from window
        window_start = window_idx * 25  # Assuming stride of 25
        window_end = window_start + 50  # Assuming window size of 50
        window_events = trace_events[window_start:window_end]
        
        # Collect instructions
        instructions = []
        operations = []
        
        for event in window_events:
            if event.get('type') == 'basic_block':
                data = event.get('data', {})
                mnemonics = data.get('mnemonics', [])
                instructions.extend(mnemonics)
                
                # Extract operation types
                for mnem in mnemonics:
                    op_type = classify_operation(mnem)
                    operations.append(op_type)
        
        # Create enhanced entry
        entry = {
            # Original sequences
            'instructions': instructions,
            'operations': operations,
            
            # Structural pattern scores
            'structural_pattern': {
                'spn_score': window_features.get('advanced_spn_score', window_features.get('spn_block_ratio', 0.0)),
                'ntt_score': window_features.get('advanced_ntt_score', window_features.get('ntt_block_ratio', 0.0)),
                'modexp_score': window_features.get('advanced_modexp_score', window_features.get('modexp_block_ratio', 0.0)),
                'feistel_score': window_features.get('advanced_feistel_score', 0.0),
                'bigint_density': window_features.get('advanced_bigint_density', 0.0),
            },
            
            # Determine dominant pattern
            'dominant_pattern': determine_dominant_pattern(window_features),
            
            # Confidence in crypto detection
            'crypto_structure_confidence': window_features.get('crypto_confidence_max', 0.0),
            
            # Round detection
            'round_detected': window_features.get('has_tight_loop', 0.0) > 0,
            'max_repetitions': int(window_features.get('max_block_repetition', 1)),
            
            # Runtime characteristics
            'runtime_metrics': {
                'memory_accesses': int(window_features.get('advanced_memory_reads', 0) + 
                                     window_features.get('advanced_memory_writes', 0)),
                'memory_reads': int(window_features.get('advanced_memory_reads', 0)),
                'memory_writes': int(window_features.get('advanced_memory_writes', 0)),
                'memory_footprint_bytes': int(window_features.get('advanced_memory_footprint', 0)),
                'unique_memory_addresses': int(window_features.get('advanced_unique_addresses', 0)),
                'instruction_count': int(window_features.get('total_events', 0)),
                'execution_count': int(window_features.get('total_executions', 0)),
            },
            
            # Instruction grouping (for detecting crypto rounds)
            'instruction_groups': group_instructions(instructions, operations),
            
            # Statistical features
            'statistical_features': {
                'xor_density': window_features.get('xor_density', 0.0),
                'shift_density': window_features.get('shift_density', 0.0),
                'add_sub_density': window_features.get('add_sub_density', 0.0),
                'mnemonic_entropy': window_features.get('mnemonic_entropy', 0.0),
                'loop_repetition_score': window_features.get('loop_repetition_score', 0.0),
                'register_volatility': window_features.get('register_volatility', 0.0),
            },
            
            # Algorithm classification hints
            'algorithm_hints': {
                'is_aes_like': window_features.get('is_aes_like', 0.0),
                'is_rsa_like': window_features.get('is_rsa_like', 0.0),
                'is_kyber_like': window_features.get('is_kyber_like', 0.0),
                'is_custom_block_cipher': window_features.get('is_custom_block_cipher', 0.0),
                'is_custom_asymmetric': window_features.get('is_custom_asymmetric', 0.0),
            },
            
            # Label
            'label': label,
            'crypto_type': classify_crypto_type(label),
        }
        
        enhanced_entries.append(entry)
    
    # Write to JSONL
    with open(output_path, 'w') as f:
        for entry in enhanced_entries:
            f.write(json.dumps(entry) + '\n')
    
    print(f"[+] Generated {len(enhanced_entries)} enhanced training samples")
    print(f"[+] Output: {output_path}")


def classify_operation(mnemonic: str) -> str:
    """Classify instruction into operation type"""
    mnem_lower = mnemonic.lower()
    
    # XOR operations
    if 'xor' in mnem_lower or 'eor' in mnem_lower:
        return 'XOR'
    
    # Shift/Rotate
    if any(op in mnem_lower for op in ['shl', 'shr', 'rol', 'ror', 'lsl', 'lsr', 'asr']):
        return 'SHIFT'
    
    # Add/Sub
    if any(op in mnem_lower for op in ['add', 'sub', 'adc', 'sbc']):
        return 'ARITH'
    
    # Multiply/Divide
    if any(op in mnem_lower for op in ['mul', 'div', 'imul', 'idiv']):
        return 'MULDIV'
    
    # AND/OR
    if any(op in mnem_lower for op in ['and', 'orr', 'bic', 'orn']):
        return 'LOGIC'
    
    # Load/Store
    if any(op in mnem_lower for op in ['mov', 'ldr', 'str', 'ld', 'st']):
        return 'LOAD'
    
    # Comparison
    if any(op in mnem_lower for op in ['cmp', 'test', 'tst']):
        return 'CMP'
    
    # Branch
    if any(op in mnem_lower for op in ['jmp', 'je', 'jne', 'call', 'ret', 'b', 'bl']):
        return 'BRANCH'
    
    return 'OTHER'


def group_instructions(instructions: List[str], operations: List[str], window_size: int = 10) -> List[Dict]:
    """Group instructions into functional blocks"""
    groups = []
    
    for i in range(0, len(instructions), window_size):
        window = instructions[i:i + window_size]
        ops_window = operations[i:i + window_size] if i < len(operations) else []
        
        # Count operation types in this group
        op_counts = Counter(ops_window)
        
        # Classify pattern
        pattern_type = 'UNKNOWN'
        if op_counts.get('XOR', 0) >= 3 and op_counts.get('SHIFT', 0) >= 2:
            pattern_type = 'SPN_ROUND'
        elif op_counts.get('MULDIV', 0) >= 3 and op_counts.get('ARITH', 0) >= 2:
            pattern_type = 'MODEXP_SEQUENCE'
        elif op_counts.get('ARITH', 0) >= 5 and op_counts.get('LOAD', 0) >= 3:
            pattern_type = 'NTT_BUTTERFLY'
        elif op_counts.get('LOAD', 0) >= 5:
            pattern_type = 'MEMORY_INTENSIVE'
        
        group = {
            'operations': list(ops_window),
            'operation_counts': dict(op_counts),
            'pattern_type': pattern_type,
            'instruction_count': len(window),
        }
        
        groups.append(group)
    
    return groups


def determine_dominant_pattern(window_features: Dict) -> str:
    """Determine the dominant cryptographic pattern"""
    spn_score = window_features.get('advanced_spn_score', window_features.get('spn_block_ratio', 0.0))
    ntt_score = window_features.get('advanced_ntt_score', window_features.get('ntt_block_ratio', 0.0))
    modexp_score = window_features.get('advanced_modexp_score', window_features.get('modexp_block_ratio', 0.0))
    feistel_score = window_features.get('advanced_feistel_score', 0.0)
    
    scores = {
        'SPN': spn_score,
        'NTT': ntt_score,
        'MODEXP': modexp_score,
        'FEISTEL': feistel_score,
    }
    
    max_score = max(scores.values())
    if max_score < 0.3:
        return 'UNKNOWN'
    
    return max(scores, key=scores.get)


def classify_crypto_type(label: str) -> str:
    """Classify crypto algorithm into broad categories"""
    label_upper = label.upper()
    
    # Block ciphers
    if any(algo in label_upper for algo in ['AES', 'DES', 'BLOWFISH', 'TWOFISH', 'CAMELLIA']):
        return 'BLOCK_CIPHER'
    
    # Stream ciphers
    if any(algo in label_upper for algo in ['CHACHA', 'SALSA', 'RC4']):
        return 'STREAM_CIPHER'
    
    # Hash functions
    if any(algo in label_upper for algo in ['SHA', 'MD5', 'BLAKE', 'KECCAK']):
        return 'HASH'
    
    # Public key crypto (pre-quantum)
    if any(algo in label_upper for algo in ['RSA', 'ECC', 'ECDSA', 'DSA', 'DH', 'ECDH']):
        return 'PUBLIC_KEY'
    
    # Post-quantum crypto
    if any(algo in label_upper for algo in ['KYBER', 'DILITHIUM', 'FALCON', 'NTRU', 'CRYSTALS']):
        return 'POST_QUANTUM'
    
    return 'PROPRIETARY'


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate enhanced training dataset')
    parser.add_argument('--trace', required=True, help='Path to trace.jsonl')
    parser.add_argument('--windowed-features', required=True, help='Path to windowed features JSON')
    parser.add_argument('--output', required=True, help='Output JSONL path')
    parser.add_argument('--label', required=True, help='Crypto algorithm label (e.g., AES128, RSA2048)')
    
    args = parser.parse_args()
    
    generate_enhanced_jsonl(
        trace_path=args.trace,
        windowed_features_path=args.windowed_features,
        output_path=args.output,
        label=args.label
    )
