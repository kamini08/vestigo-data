#!/usr/bin/env python3
"""
Advanced Pattern Detection for Cryptographic Structures

Implements sophisticated detection of:
- SPN (Substitution-Permutation Networks)
- NTT (Number Theoretic Transforms)
- MODEXP (Modular Exponentiation for RSA/DH)
- Feistel Networks
- BigInt operations (multi-precision arithmetic)

This module enhances basic heuristics with structural and temporal analysis.
"""

import numpy as np
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
import json


@dataclass
class InstructionContext:
    """Rich context for each instruction"""
    address: int
    mnemonic: str
    operands: str
    memory_read_addrs: List[int] = field(default_factory=list)
    memory_write_addrs: List[int] = field(default_factory=list)
    registers_used: List[str] = field(default_factory=list)
    flags_affected: List[str] = field(default_factory=list)
    timestamp: float = 0.0
    
    @classmethod
    def from_trace_event(cls, event: Dict, timestamp: float = 0.0) -> Optional['InstructionContext']:
        """Create InstructionContext from trace event"""
        if event.get('type') != 'basic_block':
            return None
        
        data = event.get('data', {})
        
        # Extract instructions
        instructions = data.get('instructions', [])
        mnemonics = data.get('mnemonics', [])
        
        if not mnemonics:
            return None
        
        # For now, we'll create a simplified context
        # In production, parse operands for memory addresses and registers
        return cls(
            address=int(event.get('address', 0), 16) if isinstance(event.get('address'), str) else event.get('address', 0),
            mnemonic=mnemonics[0] if mnemonics else '',
            operands='',
            timestamp=timestamp
        )


class AdvancedPatternDetector:
    """
    Detects cryptographic structural patterns using temporal and spatial analysis
    """
    
    def __init__(self, 
                 spn_threshold: float = 0.85,
                 ntt_threshold: float = 0.80,
                 bigint_threshold: float = 0.75,
                 feistel_threshold: float = 0.80):
        """
        Initialize pattern detector with confidence thresholds
        
        Args:
            spn_threshold: Minimum confidence for SPN detection
            ntt_threshold: Minimum confidence for NTT detection
            bigint_threshold: Minimum confidence for BigInt operations
            feistel_threshold: Minimum confidence for Feistel networks
        """
        self.spn_threshold = spn_threshold
        self.ntt_threshold = ntt_threshold
        self.bigint_threshold = bigint_threshold
        self.feistel_threshold = feistel_threshold
        
    def analyze_instruction_window(self, 
                                   instructions: List[InstructionContext], 
                                   window_size: int = 16) -> Dict:
        """
        Analyze instructions in sliding windows to detect cryptographic patterns
        
        Args:
            instructions: List of instruction contexts
            window_size: Size of analysis window
            
        Returns:
            Dictionary with pattern scores and evidence
        """
        
        scores = {
            'spn_score': 0.0,
            'feistel_score': 0.0,
            'ntt_score': 0.0,
            'modexp_score': 0.0,
            'bigint_density': 0.0,
            'memory_profile': {},
            'structural_evidence': []
        }
        
        if not instructions:
            return scores
        
        # Analyze in overlapping windows for round detection
        for i in range(0, len(instructions) - window_size, window_size // 2):
            window = instructions[i:i + window_size]
            
            # SPN Analysis
            spn_result = self.detect_spn_pattern(window)
            scores['spn_score'] = max(scores['spn_score'], spn_result['score'])
            if spn_result['detected']:
                scores['structural_evidence'].append(spn_result)
            
            # NTT Analysis (needs extended context)
            extended_window = instructions[max(0, i-32):min(len(instructions), i+window_size+32)]
            ntt_result = self.detect_ntt_pattern(window, extended_window)
            scores['ntt_score'] = max(scores['ntt_score'], ntt_result['score'])
            if ntt_result['detected']:
                scores['structural_evidence'].append(ntt_result)
            
            # BigInt/MODEXP Analysis
            bigint_result = self.detect_bigint_operations(window)
            scores['bigint_density'] = max(scores['bigint_density'], bigint_result['score'])
            scores['modexp_score'] = max(scores['modexp_score'], bigint_result['modexp_score'])
            if bigint_result['detected']:
                scores['structural_evidence'].append(bigint_result)
            
            # Feistel Analysis
            feistel_result = self.detect_feistel_pattern(window)
            scores['feistel_score'] = max(scores['feistel_score'], feistel_result['score'])
            if feistel_result['detected']:
                scores['structural_evidence'].append(feistel_result)
        
        # Memory profiling across entire instruction set
        scores['memory_profile'] = self.profile_memory_access(instructions)
        
        return scores
    
    def detect_spn_pattern(self, window: List[InstructionContext]) -> Dict:
        """
        IMPROVED SPN Detection:
        1. Look for XOR/ADD followed by table lookups (S-Box)
        2. Detect round structure (repeating patterns)
        3. Identify P-Box patterns (bit permutations)
        
        Args:
            window: List of instructions in current window
            
        Returns:
            Detection result with score and evidence
        """
        
        # Phase 1: Identify mixing operations
        mixing_ops = ['xor', 'add', 'sub', 'or', 'and', 'eor']
        mixing_indices = [i for i, ins in enumerate(window) 
                         if any(op in ins.mnemonic.lower() for op in mixing_ops)]
        
        # Phase 2: Identify S-Box lookups (memory reads from small, fixed regions)
        sbox_evidence = []
        unique_read_regions = set()
        
        for i, ins in enumerate(window):
            if ins.memory_read_addrs:
                for addr in ins.memory_read_addrs:
                    # S-Boxes are typically 256-byte tables
                    region = addr // 256
                    unique_read_regions.add(region)
                    
                    # Check if this read follows a mixing operation
                    if any(mix_idx < i <= mix_idx + 3 for mix_idx in mixing_indices):
                        sbox_evidence.append({
                            'index': i,
                            'addr': addr,
                            'region': region,
                            'preceding_mix': True
                        })
        
        # Phase 3: Detect bit permutations (P-Box)
        pbox_ops = ['rol', 'ror', 'shl', 'shr', 'shld', 'shrd', 'bswap', 'lsl', 'lsr', 'asr']
        pbox_count = sum(1 for ins in window if any(op in ins.mnemonic.lower() for op in pbox_ops))
        
        # Phase 4: Detect load operations (table lookups)
        load_ops = ['mov', 'ldr', 'ld', 'movzx', 'movsx']
        load_count = sum(1 for ins in window 
                        if any(op in ins.mnemonic.lower() for op in load_ops) 
                        and ins.memory_read_addrs)
        
        # Scoring
        score = 0.0
        reasons = []
        
        # Criterion 1: Mixing operations present
        if len(mixing_indices) >= 3:
            score += 0.25
            reasons.append(f"Mixing operations: {len(mixing_indices)}")
        
        # Criterion 2: S-Box pattern (small memory region, multiple accesses)
        if len(unique_read_regions) <= 8 and len(sbox_evidence) >= 4:
            score += 0.35
            reasons.append(f"S-Box evidence: {len(sbox_evidence)} lookups in {len(unique_read_regions)} regions")
        
        # Criterion 3: Permutation operations
        if pbox_count >= 2:
            score += 0.20
            reasons.append(f"P-Box operations: {pbox_count}")
        
        # Criterion 4: Sequential structure (mix -> substitute -> permute)
        if self._has_spn_sequence(window):
            score += 0.20
            reasons.append("Sequential SPN structure detected")
        
        return {
            'detected': score >= self.spn_threshold,
            'score': min(score, 1.0),
            'pattern_type': 'SPN',
            'evidence': {
                'mixing_ops': len(mixing_indices),
                'sbox_lookups': len(sbox_evidence),
                'pbox_ops': pbox_count,
                'unique_regions': len(unique_read_regions),
                'load_count': load_count
            },
            'reasons': reasons,
            'window_start': window[0].address if window else 0
        }
    
    def detect_ntt_pattern(self, 
                          window: List[InstructionContext],
                          extended_context: List[InstructionContext]) -> Dict:
        """
        IMPROVED NTT Detection:
        1. Detect butterfly memory access pattern
        2. Identify stride patterns (powers of 2)
        3. Detect twiddle factor multiplications
        4. Recognize polynomial arithmetic
        
        Args:
            window: Current analysis window
            extended_context: Extended context for memory pattern analysis
            
        Returns:
            Detection result with score and evidence
        """
        
        # Phase 1: Extract all memory accesses
        memory_reads = []
        memory_writes = []
        
        for ins in extended_context:
            for addr in ins.memory_read_addrs:
                memory_reads.append((ins.address, addr))
            for addr in ins.memory_write_addrs:
                memory_writes.append((ins.address, addr))
        
        # Phase 2: Detect butterfly pattern (power-of-2 strides)
        butterfly_evidence = []
        stride_patterns = defaultdict(int)
        
        for i in range(len(memory_reads) - 1):
            _, addr1 = memory_reads[i]
            _, addr2 = memory_reads[i + 1]
            
            stride = abs(addr2 - addr1)
            
            # Butterfly accesses are at distance = power of 2
            if stride > 0 and self._is_power_of_2(stride):
                stride_patterns[stride] += 1
                butterfly_evidence.append({
                    'indices': (i, i+1),
                    'addresses': (addr1, addr2),
                    'stride': stride
                })
        
        # Phase 3: Detect modular multiplication (twiddle factors)
        mod_mul_ops = ['imul', 'mul', 'mulx', 'smull', 'umull']
        mod_mul_count = sum(1 for ins in window 
                           if any(op in ins.mnemonic.lower() for op in mod_mul_ops))
        
        # Phase 4: Detect addition chains (butterfly adds)
        add_ops = ['add', 'sub', 'adc', 'sbc']
        add_count = sum(1 for ins in window 
                       if any(op in ins.mnemonic.lower() for op in add_ops))
        
        # Phase 5: Large array operations (NTT works on large polynomials)
        address_range = self._get_address_range(memory_reads + memory_writes)
        large_array = address_range > 1024  # Typical polynomial size
        
        # Scoring
        score = 0.0
        reasons = []
        
        # Criterion 1: Butterfly pattern with power-of-2 strides
        dominant_strides = [s for s, count in stride_patterns.items() if count >= 3]
        if len(dominant_strides) >= 2:
            score += 0.35
            reasons.append(f"Butterfly pattern: {len(dominant_strides)} power-of-2 strides")
        
        # Criterion 2: Modular multiplications (twiddle factors)
        if mod_mul_count >= 4:
            score += 0.25
            reasons.append(f"Twiddle multiplications: {mod_mul_count}")
        
        # Criterion 3: Addition operations (butterfly structure)
        if add_count >= 6:
            score += 0.20
            reasons.append(f"Butterfly additions: {add_count}")
        
        # Criterion 4: Large memory footprint
        if large_array:
            score += 0.20
            reasons.append(f"Large polynomial array: {address_range} bytes")
        
        return {
            'detected': score >= self.ntt_threshold,
            'score': min(score, 1.0),
            'pattern_type': 'NTT',
            'evidence': {
                'butterfly_pairs': len(butterfly_evidence),
                'stride_patterns': dict(stride_patterns),
                'mod_multiplications': mod_mul_count,
                'array_size': address_range,
                'add_operations': add_count
            },
            'reasons': reasons,
            'window_start': window[0].address if window else 0
        }
    
    def detect_bigint_operations(self, window: List[InstructionContext]) -> Dict:
        """
        IMPROVED BigInt/MODEXP Detection:
        1. Count carry-flag operations (ADC, SBB)
        2. Detect wide register usage (64-bit, 128-bit)
        3. Identify multi-precision arithmetic patterns
        4. Detect Montgomery multiplication patterns
        5. Recognize modular reduction sequences
        
        Args:
            window: List of instructions in current window
            
        Returns:
            Detection result with score and MODEXP-specific score
        """
        
        # Phase 1: Carry-chain operations (hallmark of multi-precision arithmetic)
        carry_ops = ['adc', 'sbb', 'adcx', 'adox']
        carry_chain = []
        
        for i, ins in enumerate(window):
            if any(op in ins.mnemonic.lower() for op in carry_ops):
                carry_chain.append(i)
        
        # Detect consecutive carry operations (multi-word arithmetic)
        consecutive_carries = self._find_consecutive_sequences(carry_chain)
        max_carry_chain = max([len(seq) for seq in consecutive_carries], default=0)
        
        # Phase 2: Wide register usage
        wide_registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 
                         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        xmm_registers = [f'xmm{i}' for i in range(16)]  # 128-bit
        
        wide_reg_usage = sum(1 for ins in window 
                            for reg in ins.registers_used 
                            if reg.lower() in wide_registers + xmm_registers)
        
        # Phase 3: Multiplication-heavy sequences (modular exponentiation)
        mul_ops = ['mul', 'imul', 'mulx', 'smull', 'umull']
        mul_count = sum(1 for ins in window if any(op in ins.mnemonic.lower() for op in mul_ops))
        
        # Phase 4: Modular reduction patterns
        div_mod_ops = ['div', 'idiv']
        div_count = sum(1 for ins in window if any(op in ins.mnemonic.lower() for op in div_mod_ops))
        
        # Phase 5: Conditional moves (constant-time implementations)
        cmov_ops = ['cmov', 'csel']
        cmov_count = sum(1 for ins in window if any(op in ins.mnemonic.lower() for op in cmov_ops))
        
        # Scoring for BigInt operations
        bigint_score = 0.0
        bigint_reasons = []
        
        # Criterion 1: Carry chains (strong indicator)
        if max_carry_chain >= 4:
            bigint_score += 0.40
            bigint_reasons.append(f"Carry chain length: {max_carry_chain}")
        elif max_carry_chain >= 2:
            bigint_score += 0.20
            bigint_reasons.append(f"Short carry chain: {max_carry_chain}")
        
        # Criterion 2: Wide register usage
        if wide_reg_usage >= len(window) * 0.5:
            bigint_score += 0.20
            bigint_reasons.append(f"Wide register usage: {wide_reg_usage}")
        
        # Criterion 3: Multiplication density
        mul_density = mul_count / max(len(window), 1)
        if mul_density > 0.25:
            bigint_score += 0.25
            bigint_reasons.append(f"Multiplication density: {mul_density:.2f}")
        
        # Criterion 4: Conditional moves (side-channel resistance)
        if cmov_count >= 2:
            bigint_score += 0.15
            bigint_reasons.append(f"Constant-time ops: {cmov_count}")
        
        # MODEXP-specific scoring (subset of BigInt)
        modexp_score = 0.0
        modexp_reasons = []
        
        # MODEXP has specific characteristics:
        # 1. Many multiplications in loops
        # 2. Division/modulo operations
        # 3. Carry chains for multi-precision
        
        if mul_count >= 5 and max_carry_chain >= 3:
            modexp_score += 0.50
            modexp_reasons.append("Multiplication-heavy with carry chains")
        
        if div_count >= 2:
            modexp_score += 0.30
            modexp_reasons.append(f"Modular reduction: {div_count} divisions")
        
        if cmov_count >= 2:
            modexp_score += 0.20
            modexp_reasons.append("Side-channel resistant implementation")
        
        return {
            'detected': bigint_score >= self.bigint_threshold,
            'score': min(bigint_score, 1.0),
            'modexp_score': min(modexp_score, 1.0),
            'pattern_type': 'BIGINT',
            'evidence': {
                'carry_chain_length': max_carry_chain,
                'total_carry_ops': len(carry_chain),
                'wide_register_usage': wide_reg_usage,
                'multiplication_count': mul_count,
                'division_count': div_count,
                'cmov_count': cmov_count
            },
            'reasons': bigint_reasons + modexp_reasons,
            'window_start': window[0].address if window else 0
        }
    
    def detect_feistel_pattern(self, window: List[InstructionContext]) -> Dict:
        """
        Detect Feistel network structure:
        1. XOR operations (combining left/right halves)
        2. Function calls or complex operations (F-function)
        3. Alternating patterns
        
        Args:
            window: List of instructions in current window
            
        Returns:
            Detection result with score and evidence
        """
        
        # Phase 1: XOR operations (Feistel combines halves with XOR)
        xor_ops = ['xor', 'eor']
        xor_indices = [i for i, ins in enumerate(window) 
                      if any(op in ins.mnemonic.lower() for op in xor_ops)]
        
        # Phase 2: Complex operations between XORs (F-function)
        # Look for clusters of operations between XOR operations
        f_function_complexity = 0
        if len(xor_indices) >= 2:
            for i in range(len(xor_indices) - 1):
                ops_between = xor_indices[i+1] - xor_indices[i]
                if ops_between > 5:  # Significant computation
                    f_function_complexity += 1
        
        # Phase 3: Register swapping patterns
        mov_ops = ['mov', 'xchg']
        swap_count = sum(1 for ins in window if any(op in ins.mnemonic.lower() for op in mov_ops))
        
        # Scoring
        score = 0.0
        reasons = []
        
        # Criterion 1: Multiple XOR operations
        if len(xor_indices) >= 4:
            score += 0.35
            reasons.append(f"XOR operations: {len(xor_indices)}")
        
        # Criterion 2: Complex F-function
        if f_function_complexity >= 2:
            score += 0.40
            reasons.append(f"F-function complexity: {f_function_complexity}")
        
        # Criterion 3: Register swapping
        if swap_count >= 4:
            score += 0.25
            reasons.append(f"Register swaps: {swap_count}")
        
        return {
            'detected': score >= self.feistel_threshold,
            'score': min(score, 1.0),
            'pattern_type': 'FEISTEL',
            'evidence': {
                'xor_count': len(xor_indices),
                'f_function_complexity': f_function_complexity,
                'swap_count': swap_count
            },
            'reasons': reasons,
            'window_start': window[0].address if window else 0
        }
    
    def profile_memory_access(self, instructions: List[InstructionContext]) -> Dict:
        """
        Profile memory access patterns across entire instruction sequence
        
        Returns:
            Memory profiling metrics
        """
        
        total_reads = sum(len(ins.memory_read_addrs) for ins in instructions)
        total_writes = sum(len(ins.memory_write_addrs) for ins in instructions)
        
        # Calculate memory footprint
        all_addresses = set()
        for ins in instructions:
            all_addresses.update(ins.memory_read_addrs)
            all_addresses.update(ins.memory_write_addrs)
        
        if all_addresses:
            footprint = max(all_addresses) - min(all_addresses)
        else:
            footprint = 0
        
        return {
            'total_memory_reads': total_reads,
            'total_memory_writes': total_writes,
            'memory_footprint_bytes': footprint,
            'unique_addresses': len(all_addresses),
            'read_write_ratio': total_reads / max(total_writes, 1)
        }
    
    # Helper methods
    
    def _has_spn_sequence(self, window: List[InstructionContext]) -> bool:
        """Check if window has sequential SPN structure (mix -> substitute -> permute)"""
        # Simplified check: look for mixing followed by load followed by shift
        mixing_ops = ['xor', 'add', 'eor']
        load_ops = ['mov', 'ldr', 'ld']
        pbox_ops = ['rol', 'ror', 'shl', 'shr', 'lsl', 'lsr']
        
        for i in range(len(window) - 3):
            has_mix = any(op in window[i].mnemonic.lower() for op in mixing_ops)
            has_load = any(op in window[i+1].mnemonic.lower() or op in window[i+2].mnemonic.lower() for op in load_ops)
            has_pbox = any(op in window[i+2].mnemonic.lower() or op in window[i+3].mnemonic.lower() for op in pbox_ops)
            
            if has_mix and has_load and has_pbox:
                return True
        
        return False
    
    def _is_power_of_2(self, n: int) -> bool:
        """Check if number is power of 2"""
        return n > 0 and (n & (n - 1)) == 0
    
    def _get_address_range(self, addresses: List[Tuple[int, int]]) -> int:
        """Calculate address range from list of (instruction_addr, memory_addr) tuples"""
        if not addresses:
            return 0
        
        mem_addrs = [addr for _, addr in addresses]
        return max(mem_addrs) - min(mem_addrs) if mem_addrs else 0
    
    def _find_consecutive_sequences(self, indices: List[int]) -> List[List[int]]:
        """Find consecutive sequences in a list of indices"""
        if not indices:
            return []
        
        sequences = []
        current_seq = [indices[0]]
        
        for i in range(1, len(indices)):
            if indices[i] == indices[i-1] + 1:
                current_seq.append(indices[i])
            else:
                sequences.append(current_seq)
                current_seq = [indices[i]]
        
        sequences.append(current_seq)
        return sequences


def analyze_trace_for_patterns(trace_path: str, 
                               output_path: Optional[str] = None) -> Dict:
    """
    Analyze a trace file for cryptographic patterns
    
    Args:
        trace_path: Path to trace.jsonl file
        output_path: Optional path to save analysis results
        
    Returns:
        Analysis results dictionary
    """
    
    # Load trace
    instructions = []
    with open(trace_path, 'r') as f:
        for i, line in enumerate(f):
            event = json.loads(line)
            ctx = InstructionContext.from_trace_event(event, timestamp=i)
            if ctx:
                instructions.append(ctx)
    
    # Analyze patterns
    detector = AdvancedPatternDetector()
    results = detector.analyze_instruction_window(instructions)
    
    # Save results if requested
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
    
    return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python advanced_pattern_detector.py <trace.jsonl> [output.json]")
        sys.exit(1)
    
    trace_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"[*] Analyzing trace: {trace_path}")
    results = analyze_trace_for_patterns(trace_path, output_path)
    
    print(f"\n[+] Pattern Detection Results:")
    print(f"    SPN Score: {results['spn_score']:.2f}")
    print(f"    NTT Score: {results['ntt_score']:.2f}")
    print(f"    MODEXP Score: {results['modexp_score']:.2f}")
    print(f"    BigInt Density: {results['bigint_density']:.2f}")
    print(f"    Feistel Score: {results['feistel_score']:.2f}")
    
    if results['structural_evidence']:
        print(f"\n[+] Structural Evidence Found: {len(results['structural_evidence'])} patterns")
        for evidence in results['structural_evidence'][:3]:  # Show first 3
            print(f"    - {evidence['pattern_type']}: {evidence['score']:.2f} ({', '.join(evidence['reasons'])})")
