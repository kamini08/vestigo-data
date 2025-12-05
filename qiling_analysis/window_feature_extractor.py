#!/usr/bin/env python3
"""
Window Feature Extractor for ML-Based Crypto Detection
Converts raw trace.jsonl into ML-ready windowed features

This is the bridge between raw execution traces and ML training/inference.
Each window becomes one training sample with aggregated statistical features.

Enhanced with advanced pattern detection for SPN, NTT, MODEXP, and BigInt operations.
"""

import json
import numpy as np
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional
from pathlib import Path

# Import advanced pattern detector
try:
    from advanced_pattern_detector import AdvancedPatternDetector, InstructionContext
    ADVANCED_DETECTOR_AVAILABLE = True
except ImportError:
    print("⚠️  Warning: advanced_pattern_detector not available. Using basic heuristics only.")
    ADVANCED_DETECTOR_AVAILABLE = False


class WindowFeatureExtractor:
    """
    Converts raw trace.jsonl into ML-ready windowed features.
    This is the bridge between extraction and training.
    """
    
    def __init__(self, window_size: int = 50, stride: int = 25):
        """
        Args:
            window_size: Number of events per window (default: 50)
            stride: Step size for sliding window (default: 25, 50% overlap)
        """
        self.window_size = window_size
        self.stride = stride
    
    def load_trace(self, trace_path: str) -> List[Dict]:
        """Load raw trace from JSONL"""
        events = []
        with open(trace_path) as f:
            for line in f:
                events.append(json.loads(line))
        return events
    
    def extract_window_features(self, window: List[Dict]) -> Dict[str, float]:
        """
        Extract aggregated features from a window of events.
        THIS is what your ML model will consume.
        
        Returns:
            Dictionary of feature_name -> feature_value pairs
        """
        features = {}
        
        # Separate blocks and syscalls
        blocks = [e for e in window if e['type'] == 'basic_block']
        syscalls = [e for e in window if e['type'] == 'syscall']
        
        # Basic counts
        features['block_count'] = len(blocks)
        features['syscall_count'] = len(syscalls)
        features['total_events'] = len(window)
        
        # === INSTRUCTION FEATURES ===
        all_mnemonics = []
        all_instructions = []
        for block in blocks:
            mnemonics = block['data'].get('mnemonics', [])
            all_mnemonics.extend(mnemonics)
            
            # Get full instructions with operands if available
            instructions = block['data'].get('instructions', [])
            if instructions:
                all_instructions.extend(instructions)
        
        total_instructions = len(all_mnemonics)
        
        # XOR density (key crypto indicator)
        xor_count = sum(1 for m in all_mnemonics if 'xor' in m.lower())
        features['xor_density'] = xor_count / max(total_instructions, 1)
        
        # Shift/rotate density (crypto mixing operations)
        shift_ops = ['shl', 'shr', 'rol', 'ror', 'sal', 'sar', 'lsl', 'lsr', 'asr']
        shift_count = sum(1 for m in all_mnemonics if any(op in m.lower() for op in shift_ops))
        features['shift_density'] = shift_count / max(total_instructions, 1)
        
        # ADD/SUB density (arithmetic mixing)
        add_sub_ops = ['add', 'sub', 'adc', 'sbc']
        add_sub_count = sum(1 for m in all_mnemonics if any(op in m.lower() for op in add_sub_ops))
        features['add_sub_density'] = add_sub_count / max(total_instructions, 1)
        
        # AND/OR density (bit manipulation)
        and_or_ops = ['and', 'orr', 'eor', 'bic']
        and_or_count = sum(1 for m in all_mnemonics if any(op in m.lower() for op in and_or_ops))
        features['and_or_density'] = and_or_count / max(total_instructions, 1)
        
        # AES-specific hardware instructions
        aes_ops = ['aesenc', 'aesenclast', 'aesdec', 'aesdeclast', 'aeskeygenassist', 'aesimc', 'aes']
        features['aes_instruction_count'] = sum(1 for m in all_mnemonics if any(op in m.lower() for op in aes_ops))
        features['has_aes_instructions'] = float(features['aes_instruction_count'] > 0)
        
        # SHA-specific instructions
        sha_ops = ['sha1', 'sha256', 'sha512']
        features['sha_instruction_count'] = sum(1 for m in all_mnemonics if any(op in m.lower() for op in sha_ops))
        
        # Mnemonic diversity (entropy) - high entropy = varied operations (good for crypto)
        if all_mnemonics:
            mnemonic_counts = Counter(all_mnemonics)
            total = len(all_mnemonics)
            entropy = -sum((count/total) * np.log2(count/total) for count in mnemonic_counts.values())
            features['mnemonic_entropy'] = entropy
            features['unique_mnemonic_ratio'] = len(mnemonic_counts) / total
        else:
            features['mnemonic_entropy'] = 0.0
            features['unique_mnemonic_ratio'] = 0.0
        
        # === LOOP DETECTION ===
        # Count repeated blocks (same bytes_hash)
        block_hashes = [b['data'].get('bytes_hash') for b in blocks if 'bytes_hash' in b['data']]
        if block_hashes:
            hash_counts = Counter(block_hashes)
            max_repetition = max(hash_counts.values())
            features['loop_repetition_score'] = max_repetition / len(blocks)
            features['unique_block_ratio'] = len(hash_counts) / len(blocks)
            
            # Detect tight loops (same block executed many times)
            features['max_block_repetition'] = max_repetition
        else:
            features['loop_repetition_score'] = 0.0
            features['unique_block_ratio'] = 1.0
            features['max_block_repetition'] = 1
        
        # Execution count patterns (from coalescing)
        exec_counts = [b['data'].get('execution_count', 1) for b in blocks]
        if exec_counts:
            features['avg_execution_count'] = np.mean(exec_counts)
            features['max_execution_count'] = max(exec_counts)
            features['total_executions'] = sum(exec_counts)
        else:
            features['avg_execution_count'] = 1.0
            features['max_execution_count'] = 1
            features['total_executions'] = 0
        
        # === MEMORY MUTATION ===
        stack_hashes = []
        stack_entropies = []
        stack_nonzero = []
        heap_sizes = []
        
        for block in blocks:
            mem_state = block['data'].get('memory_state', {})
            if 'stack_hash' in mem_state:
                stack_hashes.append(mem_state['stack_hash'])
            if 'stack_entropy' in mem_state:
                stack_entropies.append(mem_state['stack_entropy'])
            if 'stack_nonzero_bytes' in mem_state:
                stack_nonzero.append(mem_state['stack_nonzero_bytes'])
            if 'heap_size' in mem_state:
                heap_sizes.append(mem_state['heap_size'])
        
        # Stack mutation rate (how often stack changes)
        if stack_hashes:
            unique_stack_hashes = len(set(stack_hashes))
            features['stack_mutation_rate'] = unique_stack_hashes / len(stack_hashes)
        else:
            features['stack_mutation_rate'] = 0.0
        
        # Stack entropy trend (increasing = data accumulation, crypto operations)
        if len(stack_entropies) >= 2:
            features['stack_entropy_mean'] = np.mean(stack_entropies)
            features['stack_entropy_std'] = np.std(stack_entropies)
            features['stack_entropy_slope'] = (stack_entropies[-1] - stack_entropies[0]) / len(stack_entropies)
            features['stack_entropy_max'] = max(stack_entropies)
        else:
            features['stack_entropy_mean'] = 0.0
            features['stack_entropy_std'] = 0.0
            features['stack_entropy_slope'] = 0.0
            features['stack_entropy_max'] = 0.0
        
        # Stack usage patterns
        if stack_nonzero:
            features['stack_nonzero_mean'] = np.mean(stack_nonzero)
            features['stack_nonzero_max'] = max(stack_nonzero)
            features['stack_usage_slope'] = (stack_nonzero[-1] - stack_nonzero[0]) / len(stack_nonzero) if len(stack_nonzero) > 1 else 0.0
        else:
            features['stack_nonzero_mean'] = 0.0
            features['stack_nonzero_max'] = 0.0
            features['stack_usage_slope'] = 0.0
        
        # Heap growth (indicates dynamic allocation)
        if heap_sizes:
            features['heap_growth'] = heap_sizes[-1] - heap_sizes[0] if len(heap_sizes) > 1 else 0
            features['heap_size_max'] = max(heap_sizes)
        else:
            features['heap_growth'] = 0
            features['heap_size_max'] = 0
        
        # === REGISTER AVALANCHE ===
        register_states = [b['data'].get('register_state', {}) for b in blocks if 'register_state' in b['data']]
        if len(register_states) >= 2:
            # Count how many registers changed between first and last
            first_regs = set(register_states[0].items())
            last_regs = set(register_states[-1].items())
            changed_regs = len(first_regs.symmetric_difference(last_regs))
            features['register_mutation_count'] = changed_regs
            
            # Register volatility (how often any register changes)
            total_changes = 0
            for i in range(1, len(register_states)):
                prev_regs = set(register_states[i-1].items())
                curr_regs = set(register_states[i].items())
                total_changes += len(prev_regs.symmetric_difference(curr_regs))
            features['register_volatility'] = total_changes / len(register_states)
        else:
            features['register_mutation_count'] = 0
            features['register_volatility'] = 0.0
        
        # === SYSCALL PATTERNS ===
        # Basic syscall metrics
        features['syscall_ratio'] = len(syscalls) / max(len(window), 1)
        
        # Syscall diversity
        if syscalls:
            syscall_names = [s['data'].get('name', 'unknown') for s in syscalls]
            syscall_counts = Counter(syscall_names)
            features['unique_syscall_count'] = len(syscall_counts)
            features['syscall_diversity'] = len(syscall_counts) / len(syscalls)
        else:
            features['unique_syscall_count'] = 0
            features['syscall_diversity'] = 0.0
        
        # Entropy of syscall buffers (high entropy = encrypted data)
        buffer_entropies = []
        for s in syscalls:
            if 'entropy' in s['data']:
                buffer_entropies.append(s['data']['entropy'])
            # Check buffer_data for entropy calculation
            elif 'buffer_data' in s['data'] and s['data']['buffer_data']:
                # Calculate entropy if not pre-calculated
                buffer_data = s['data']['buffer_data']
                if isinstance(buffer_data, str):
                    buffer_data = bytes.fromhex(buffer_data)
                if len(buffer_data) > 0:
                    entropy = self._calculate_entropy(buffer_data)
                    buffer_entropies.append(entropy)
        
        if buffer_entropies:
            features['avg_buffer_entropy'] = np.mean(buffer_entropies)
            features['max_buffer_entropy'] = np.max(buffer_entropies)
            features['min_buffer_entropy'] = np.min(buffer_entropies)
            features['high_entropy_buffer_ratio'] = sum(1 for e in buffer_entropies if e > 7.0) / len(buffer_entropies)
        else:
            features['avg_buffer_entropy'] = 0.0
            features['max_buffer_entropy'] = 0.0
            features['min_buffer_entropy'] = 0.0
            features['high_entropy_buffer_ratio'] = 0.0
        
        # Network syscalls (send/recv/connect)
        network_syscalls = ['send', 'recv', 'sendto', 'recvfrom', 'connect', 'accept', 'socket']
        network_count = sum(1 for s in syscalls if s['data'].get('name') in network_syscalls)
        features['network_syscall_count'] = network_count
        features['network_syscall_ratio'] = network_count / max(len(syscalls), 1)
        
        # File I/O syscalls
        file_syscalls = ['read', 'write', 'open', 'close', 'lseek']
        file_count = sum(1 for s in syscalls if s['data'].get('name') in file_syscalls)
        features['file_syscall_count'] = file_count
        features['file_syscall_ratio'] = file_count / max(len(syscalls), 1)
        
        # === CRYPTO HEURISTICS ===
        # NEW: Structural pattern detection aggregation
        spn_blocks = [b for b in blocks if b['data'].get('metadata', {}).get('has_spn', False)]
        modexp_blocks = [b for b in blocks if b['data'].get('metadata', {}).get('has_modexp', False)]
        ntt_blocks = [b for b in blocks if b['data'].get('metadata', {}).get('has_ntt', False)]
        
        # Pattern counts and ratios
        features['spn_block_count'] = len(spn_blocks)
        features['modexp_block_count'] = len(modexp_blocks)
        features['ntt_block_count'] = len(ntt_blocks)
        
        features['spn_block_ratio'] = len(spn_blocks) / max(len(blocks), 1)
        features['modexp_block_ratio'] = len(modexp_blocks) / max(len(blocks), 1)
        features['ntt_block_ratio'] = len(ntt_blocks) / max(len(blocks), 1)
        
        # Binary flags for pattern detection
        features['has_spn_pattern'] = float(len(spn_blocks) > 0)
        features['has_modexp_pattern'] = float(len(modexp_blocks) > 0)
        features['has_ntt_pattern'] = float(len(ntt_blocks) > 0)
        
        # Aggregate crypto confidence score from blocks
        crypto_confidences = [
            b['data']['metadata'].get('crypto_confidence', 0.0)
            for b in blocks if 'metadata' in b['data']
        ]
        if crypto_confidences:
            features['crypto_confidence_mean'] = np.mean(crypto_confidences)
            features['crypto_confidence_max'] = np.max(crypto_confidences)
        else:
            features['crypto_confidence_mean'] = 0.0
            features['crypto_confidence_max'] = 0.0
        
        # NEW: Algorithm classification heuristics
        # These help identify specific crypto algorithm types
        
        # AES-like: SPN structure + low memory intensity + XOR heavy
        features['is_aes_like'] = float(
            features['has_spn_pattern'] > 0 and
            features['xor_density'] > 0.15 and
            features['has_aes_instructions'] > 0  # Hardware AES if available
        )
        
        # RSA-like: Modular exponentiation + high instruction count
        features['is_rsa_like'] = float(
            features['has_modexp_pattern'] > 0 and
            total_instructions > 50  # RSA operations are computationally heavy
        )
        
        # KYBER-like (Post-Quantum): NTT operations + balanced add/sub
        features['is_kyber_like'] = float(
            features['has_ntt_pattern'] > 0 and
            features['add_sub_density'] > 0.20  # High arithmetic density
        )
        
        # Generic block cipher: SPN without specific hardware instructions
        features['is_custom_block_cipher'] = float(
            features['has_spn_pattern'] > 0 and
            features['has_aes_instructions'] == 0 and  # No hardware AES
            features['xor_density'] > 0.10
        )
        
        # Generic asymmetric crypto: Modexp without RSA-specific patterns
        features['is_custom_asymmetric'] = float(
            features['has_modexp_pattern'] > 0 and
            features['is_rsa_like'] == 0
        )
        
        # Combined heuristic score (weighted features that indicate crypto)
        features['crypto_heuristic_score'] = (
            features['xor_density'] * 0.20 +
            features['shift_density'] * 0.15 +
            features['loop_repetition_score'] * 0.10 +
            min(features['mnemonic_entropy'] / 5.0, 1.0) * 0.10 +
            features['high_entropy_buffer_ratio'] * 0.15 +
            features['register_volatility'] / 100.0 * 0.05 +
            features['spn_block_ratio'] * 0.10 +  # NEW: SPN contribution
            features['modexp_block_ratio'] * 0.10 +  # NEW: ModExp contribution
            features['ntt_block_ratio'] * 0.05  # NEW: NTT contribution
        )
        
        # Pattern indicators
        features['has_xor_shift_pattern'] = float(
            features['xor_density'] > 0.15 and features['shift_density'] > 0.10
        )
        features['has_tight_loop'] = float(features['max_execution_count'] > 10)
        features['has_high_entropy_io'] = float(features['avg_buffer_entropy'] > 6.5)
        
        # === ADVANCED PATTERN DETECTION ===
        # Use advanced pattern detector if available for deeper structural analysis
        if ADVANCED_DETECTOR_AVAILABLE:
            instruction_contexts = self._convert_to_instruction_contexts(window)
            if instruction_contexts:
                detector = AdvancedPatternDetector()
                advanced_results = detector.analyze_instruction_window(instruction_contexts)
                
                # Add advanced pattern scores
                features['advanced_spn_score'] = advanced_results.get('spn_score', 0.0)
                features['advanced_ntt_score'] = advanced_results.get('ntt_score', 0.0)
                features['advanced_modexp_score'] = advanced_results.get('modexp_score', 0.0)
                features['advanced_bigint_density'] = advanced_results.get('bigint_density', 0.0)
                features['advanced_feistel_score'] = advanced_results.get('feistel_score', 0.0)
                
                # Memory profiling from advanced detector
                mem_profile = advanced_results.get('memory_profile', {})
                features['advanced_memory_reads'] = mem_profile.get('total_memory_reads', 0)
                features['advanced_memory_writes'] = mem_profile.get('total_memory_writes', 0)
                features['advanced_memory_footprint'] = mem_profile.get('memory_footprint_bytes', 0)
                features['advanced_unique_addresses'] = mem_profile.get('unique_addresses', 0)
                
                # Structural evidence count
                features['structural_evidence_count'] = len(advanced_results.get('structural_evidence', []))
        
        return features
    
    def _convert_to_instruction_contexts(self, window: List[Dict]) -> List:
        """Convert trace window to instruction contexts for advanced pattern detector"""
        if not ADVANCED_DETECTOR_AVAILABLE:
            return []
        
        instruction_contexts = []
        timestamp = 0
        
        for event in window:
            if event.get('type') == 'basic_block':
                ctx = InstructionContext.from_trace_event(event, timestamp)
                if ctx:
                    instruction_contexts.append(ctx)
                timestamp += 1
        
        return instruction_contexts
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def create_windows(self, events: List[Dict]) -> List[Dict]:
        """
        Create sliding windows with features.
        Each window = 1 training sample.
        """
        windows = []
        
        for i in range(0, len(events) - self.window_size + 1, self.stride):
            window_events = events[i:i + self.window_size]
            features = self.extract_window_features(window_events)
            
            windows.append({
                'window_id': i // self.stride,
                'start_seq': window_events[0]['seq'],
                'end_seq': window_events[-1]['seq'],
                'features': features,
                'raw_events': window_events  # Keep for explainability
            })
        
        return windows
    
    def save_windowed_dataset(self, windows: List[Dict], output_path: str, include_raw: bool = False):
        """
        Save ML-ready dataset
        
        Args:
            windows: List of window dictionaries
            output_path: Output file path
            include_raw: If True, include raw events (large files!)
        """
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            for window in windows:
                # Prepare output
                output = {
                    'window_id': window['window_id'],
                    'start_seq': window['start_seq'],
                    'end_seq': window['end_seq'],
                    'features': window['features']
                }
                
                # Optionally include raw events (WARNING: large files!)
                if include_raw:
                    output['raw_events'] = window['raw_events']
                
                f.write(json.dumps(output) + '\n')
    
    def get_feature_names(self) -> List[str]:
        """Get list of all feature names for ML model input ordering"""
        # Create a dummy window to extract feature names
        dummy_window = [
            {
                'seq': 0,
                'type': 'basic_block',
                'data': {
                    'mnemonics': ['mov_reg_reg'],
                    'bytes_hash': 'dummy',
                    'execution_count': 1,
                    'memory_state': {},
                    'register_state': {}
                }
            }
        ]
        features = self.extract_window_features(dummy_window)
        return sorted(features.keys())


def main():
    """
    Example usage: Process single trace file
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Extract ML-ready windowed features from execution traces"
    )
    parser.add_argument(
        'trace_path',
        help='Path to trace JSONL file'
    )
    parser.add_argument(
        '--output',
        help='Output path for windowed features (default: auto-generate)'
    )
    parser.add_argument(
        '--window-size',
        type=int,
        default=50,
        help='Number of events per window (default: 50)'
    )
    parser.add_argument(
        '--stride',
        type=int,
        default=25,
        help='Stride for sliding window (default: 25)'
    )
    parser.add_argument(
        '--include-raw',
        action='store_true',
        help='Include raw events in output (warning: large files!)'
    )
    
    args = parser.parse_args()
    
    # Auto-generate output path if not provided
    if not args.output:
        trace_path = Path(args.trace_path)
        output_dir = trace_path.parent.parent / 'windowed_features'
        output_dir.mkdir(parents=True, exist_ok=True)
        args.output = output_dir / f"{trace_path.stem}_windowed.jsonl"
    
    print(f"[*] Processing trace: {args.trace_path}")
    print(f"[*] Window size: {args.window_size}, Stride: {args.stride}")
    
    # Create extractor
    extractor = WindowFeatureExtractor(
        window_size=args.window_size,
        stride=args.stride
    )
    
    # Load trace
    print("[*] Loading trace...")
    events = extractor.load_trace(args.trace_path)
    print(f"[+] Loaded {len(events)} events")
    
    # Create windows
    print("[*] Creating windows...")
    windows = extractor.create_windows(events)
    print(f"[+] Created {len(windows)} windows")
    
    # Show sample features
    if windows:
        print("\n[*] Sample window features:")
        feature_names = sorted(windows[0]['features'].keys())
        print(f"[+] Total features: {len(feature_names)}")
        print(f"[+] Feature names: {', '.join(feature_names[:10])}...")
        
        print("\n[*] First window feature values:")
        for name, value in list(windows[0]['features'].items())[:10]:
            print(f"    {name}: {value:.4f}" if isinstance(value, float) else f"    {name}: {value}")
    
    # Save windowed dataset
    print(f"\n[*] Saving windowed features to: {args.output}")
    extractor.save_windowed_dataset(windows, str(args.output), include_raw=args.include_raw)
    print(f"[+] Done! Windowed dataset saved.")
    
    # Print feature names for ML model reference
    print("\n[*] Feature names for ML model (ordered):")
    feature_names = extractor.get_feature_names()
    for i, name in enumerate(feature_names, 1):
        print(f"    {i:2d}. {name}")


if __name__ == '__main__':
    main()
