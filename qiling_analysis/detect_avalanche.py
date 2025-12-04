#!/usr/bin/env python3
"""
Avalanche Effect Detector for Cryptographic Function Identification
Based on CipherXRay Methodology

This script automates the detection of crypto functions by observing how a 
1-bit input change propagates through execution traces (the "avalanche effect").

Methodology:
1. Run target binary with controlled input (all 0x41 'A's)
2. Run again with 1-bit flipped input (0x40 instead of first 0x41)
3. Compare execution traces to identify:
   - Control flow divergence (execution path changes)
   - Data flow divergence (register/memory differences)
4. Report basic blocks exhibiting high sensitivity (likely crypto)

Citation: CipherXRay - "One-Bit-Flip-Based Binary Analysis"
"""

import os
import sys
import json
import subprocess
from typing import Dict, List, Tuple, Set
from collections import defaultdict


class AvalancheDetector:
    """
    Compares two execution traces and identifies crypto-sensitive blocks.
    """
    
    def __init__(self, trace_original: str, trace_flipped: str):
        self.trace_original = trace_original
        self.trace_flipped = trace_flipped
        self.original_events = []
        self.flipped_events = []
        
    def load_traces(self):
        """Load JSONL traces into memory."""
        print(f"[*] Loading original trace: {self.trace_original}")
        with open(self.trace_original, 'r') as f:
            self.original_events = [json.loads(line) for line in f]
        
        print(f"[*] Loading flipped trace: {self.trace_flipped}")
        with open(self.trace_flipped, 'r') as f:
            self.flipped_events = [json.loads(line) for line in f]
        
        print(f"[+] Loaded {len(self.original_events)} original events")
        print(f"[+] Loaded {len(self.flipped_events)} flipped events")
    
    def find_divergence_point(self) -> Tuple[int, str]:
        """
        Find the first point where execution paths diverge (Control Flow Divergence).
        
        Returns:
            (sequence_number, divergence_type)
        """
        min_len = min(len(self.original_events), len(self.flipped_events))
        
        for i in range(min_len):
            orig_event = self.original_events[i]
            flip_event = self.flipped_events[i]
            
            # Check if event types differ
            if orig_event["type"] != flip_event["type"]:
                print(f"[!] Control Flow Divergence at seq={i}")
                print(f"    Original: {orig_event['type']}")
                print(f"    Flipped:  {flip_event['type']}")
                return (i, "event_type_mismatch")
            
            # For basic blocks, check if addresses differ
            if orig_event["type"] == "basic_block":
                orig_addr = orig_event["data"]["address"]
                flip_addr = flip_event["data"]["address"]
                
                if orig_addr != flip_addr:
                    print(f"[!] Control Flow Divergence at seq={i}")
                    print(f"    Original block: {orig_addr}")
                    print(f"    Flipped block:  {flip_addr}")
                    return (i, "address_divergence")
            
            # For syscalls, check if names differ
            elif orig_event["type"] == "syscall":
                orig_name = orig_event["data"]["name"]
                flip_name = flip_event["data"]["name"]
                
                if orig_name != flip_name:
                    print(f"[!] Control Flow Divergence at seq={i} (syscall)")
                    print(f"    Original: {orig_name}")
                    print(f"    Flipped:  {flip_name}")
                    return (i, "syscall_divergence")
        
        # Check if one trace is longer
        if len(self.original_events) != len(self.flipped_events):
            print(f"[!] Trace length divergence:")
            print(f"    Original: {len(self.original_events)} events")
            print(f"    Flipped:  {len(self.flipped_events)} events")
            return (min_len, "length_divergence")
        
        print("[+] No control flow divergence detected (traces are identical)")
        return (-1, "no_divergence")
    
    def detect_data_flow_divergence(self) -> List[Dict]:
        """
        Identify blocks where data differs despite same control flow.
        This is the "avalanche" - same code, different data.
        
        Returns:
            List of {address, divergence_score, evidence} dicts
        """
        print("\n[*] Analyzing Data Flow Divergence (Avalanche Effect)...")
        
        # Group events by address (for basic blocks)
        original_blocks = defaultdict(list)
        flipped_blocks = defaultdict(list)
        
        for event in self.original_events:
            if event["type"] == "basic_block":
                addr = event["data"]["address"]
                original_blocks[addr].append(event)
        
        for event in self.flipped_events:
            if event["type"] == "basic_block":
                addr = event["data"]["address"]
                flipped_blocks[addr].append(event)
        
        # Find blocks present in both traces
        common_addresses = set(original_blocks.keys()) & set(flipped_blocks.keys())
        print(f"[+] Found {len(common_addresses)} common basic blocks")
        
        divergent_blocks = []
        
        for addr in common_addresses:
            orig_executions = original_blocks[addr]
            flip_executions = flipped_blocks[addr]
            
            # Compare features (mnemonics, entropy, etc.)
            divergence_score = 0
            evidence = []
            
            # Check execution count difference (crypto loops may repeat differently)
            orig_count = sum(e["data"].get("execution_count", 1) for e in orig_executions)
            flip_count = sum(e["data"].get("execution_count", 1) for e in flip_executions)
            
            if orig_count != flip_count:
                divergence_score += 1
                evidence.append(f"exec_count: {orig_count} → {flip_count}")
            
            # Check if block has crypto patterns
            has_crypto = False
            for e in orig_executions:
                if e["data"].get("metadata", {}).get("has_crypto_patterns", False):
                    has_crypto = True
                    divergence_score += 2
                    evidence.append("crypto_patterns_detected")
                    break
            
            # NEW: Compare register states (AVALANCHE EFFECT!)
            register_changes = 0
            if orig_executions and flip_executions:
                # Compare first execution of this block
                orig_data = orig_executions[0]["data"]
                flip_data = flip_executions[0]["data"]
                
                if "register_state" in orig_data and "register_state" in flip_data:
                    orig_regs = orig_data["register_state"]
                    flip_regs = flip_data["register_state"]
                    
                    # Count how many registers changed
                    for reg_name in orig_regs.keys():
                        if reg_name in flip_regs and orig_regs[reg_name] != flip_regs[reg_name]:
                            register_changes += 1
                    
                    if register_changes > 0:
                        divergence_score += register_changes  # +1 per changed register
                        evidence.append(f"registers_changed: {register_changes}")
            
            # NEW: Compare memory states (stack entropy)
            memory_divergence = False
            if orig_executions and flip_executions:
                orig_data = orig_executions[0]["data"]
                flip_data = flip_executions[0]["data"]
                
                if "memory_state" in orig_data and "memory_state" in flip_data:
                    orig_mem = orig_data["memory_state"]
                    flip_mem = flip_data["memory_state"]
                    
                    # Compare stack hashes
                    if orig_mem.get("stack_hash") != flip_mem.get("stack_hash"):
                        divergence_score += 3  # Significant indicator
                        evidence.append("stack_state_differs")
                        memory_divergence = True
                    
                    # Compare stack entropy
                    orig_entropy = orig_mem.get("stack_entropy", 0)
                    flip_entropy = flip_mem.get("stack_entropy", 0)
                    entropy_diff = abs(orig_entropy - flip_entropy)
                    
                    if entropy_diff > 0.5:
                        divergence_score += 2
                        evidence.append(f"stack_entropy_delta: {entropy_diff:.2f}")
            
            # Check mnemonic changes (shouldn't happen, but worth checking)
            if orig_executions and flip_executions:
                orig_mnemonics = set(orig_executions[0]["data"].get("mnemonics", []))
                flip_mnemonics = set(flip_executions[0]["data"].get("mnemonics", []))
                
                if orig_mnemonics != flip_mnemonics:
                    divergence_score += 5  # High score - shouldn't happen
                    evidence.append("mnemonic_change_anomaly")
            
            if divergence_score > 0:
                divergent_blocks.append({
                    "address": addr,
                    "divergence_score": divergence_score,
                    "evidence": evidence,
                    "has_crypto_patterns": has_crypto,
                    "original_exec_count": orig_count,
                    "flipped_exec_count": flip_count,
                    "register_changes": register_changes,
                    "memory_divergence": memory_divergence
                })
        
        # Sort by divergence score (highest first)
        divergent_blocks.sort(key=lambda x: x["divergence_score"], reverse=True)
        
        return divergent_blocks
    
    def analyze_syscall_avalanche(self) -> List[Dict]:
        """
        Analyze syscalls for data differences (entropy, buffer sizes).
        Crypto operations often produce high-entropy outputs.
        """
        print("\n[*] Analyzing Syscall Data Avalanche...")
        
        original_syscalls = [e for e in self.original_events if e["type"] == "syscall"]
        flipped_syscalls = [e for e in self.flipped_events if e["type"] == "syscall"]
        
        min_len = min(len(original_syscalls), len(flipped_syscalls))
        divergent_syscalls = []
        
        for i in range(min_len):
            orig = original_syscalls[i]
            flip = flipped_syscalls[i]
            
            # Must be same syscall type
            if orig["data"]["name"] != flip["data"]["name"]:
                continue
            
            # Compare entropy (if available)
            orig_entropy = orig["data"].get("entropy", 0)
            flip_entropy = flip["data"].get("entropy", 0)
            
            entropy_diff = abs(orig_entropy - flip_entropy)
            
            if entropy_diff > 0.5:  # Significant entropy change
                divergent_syscalls.append({
                    "syscall": orig["data"]["name"],
                    "sequence": orig["seq"],
                    "original_entropy": orig_entropy,
                    "flipped_entropy": flip_entropy,
                    "entropy_delta": round(entropy_diff, 3),
                    "is_crypto_candidate": orig_entropy > 7.0 or flip_entropy > 7.0
                })
        
        divergent_syscalls.sort(key=lambda x: x["entropy_delta"], reverse=True)
        
        return divergent_syscalls
    
    def generate_report(self) -> Dict:
        """
        Generate comprehensive avalanche analysis report.
        """
        print("\n" + "="*70)
        print("AVALANCHE EFFECT ANALYSIS REPORT")
        print("="*70)
        
        # Control flow divergence
        divergence_seq, divergence_type = self.find_divergence_point()
        
        # Data flow divergence
        divergent_blocks = self.detect_data_flow_divergence()
        
        # Syscall divergence
        divergent_syscalls = self.analyze_syscall_avalanche()
        
        report = {
            "control_flow": {
                "divergence_point": divergence_seq,
                "divergence_type": divergence_type
            },
            "data_flow": {
                "total_divergent_blocks": len(divergent_blocks),
                "crypto_candidate_blocks": [
                    b for b in divergent_blocks if b["has_crypto_patterns"]
                ],
                "top_divergent_blocks": divergent_blocks[:20]  # Top 20
            },
            "syscall_divergence": {
                "total_divergent_syscalls": len(divergent_syscalls),
                "crypto_candidate_syscalls": [
                    s for s in divergent_syscalls if s["is_crypto_candidate"]
                ],
                "top_divergent_syscalls": divergent_syscalls[:10]
            }
        }
        
        # Print summary
        print(f"\n[CONTROL FLOW]")
        print(f"  Divergence Point: seq={divergence_seq} ({divergence_type})")
        
        print(f"\n[DATA FLOW - BASIC BLOCKS]")
        print(f"  Total Divergent Blocks: {len(divergent_blocks)}")
        print(f"  Crypto Candidate Blocks: {len(report['data_flow']['crypto_candidate_blocks'])}")
        
        # NEW: Statistics on register/memory changes
        blocks_with_reg_changes = sum(1 for b in divergent_blocks if b.get("register_changes", 0) > 0)
        blocks_with_mem_changes = sum(1 for b in divergent_blocks if b.get("memory_divergence", False))
        
        print(f"  Blocks with Register Changes: {blocks_with_reg_changes}")
        print(f"  Blocks with Memory Divergence: {blocks_with_mem_changes}")
        
        if divergent_blocks:
            print(f"\n  Top 10 Avalanche-Sensitive Blocks:")
            for i, block in enumerate(divergent_blocks[:10], 1):
                print(f"    {i}. {block['address']} "
                      f"(score={block['divergence_score']}, "
                      f"crypto={block['has_crypto_patterns']}, "
                      f"reg_changes={block.get('register_changes', 0)})")
                print(f"       Evidence: {', '.join(block['evidence'])}")
        
        print(f"\n[SYSCALL DIVERGENCE]")
        print(f"  Total Divergent Syscalls: {len(divergent_syscalls)}")
        print(f"  Crypto Candidate Syscalls: {len(report['syscall_divergence']['crypto_candidate_syscalls'])}")
        
        if divergent_syscalls:
            print(f"\n  Top 5 Entropy Changes:")
            for i, sc in enumerate(divergent_syscalls[:5], 1):
                print(f"    {i}. {sc['syscall']} (seq={sc['sequence']})")
                print(f"       Entropy: {sc['original_entropy']:.2f} → {sc['flipped_entropy']:.2f} "
                      f"(Δ={sc['entropy_delta']:.2f})")
        
        print("\n" + "="*70)
        
        return report


class AvalancheExperiment:
    """
    Orchestrates the full avalanche detection experiment.
    """
    
    def __init__(self, binary_path: str, feature_extractor_path: str):
        self.binary_path = binary_path
        self.feature_extractor_path = feature_extractor_path
        self.output_dir = "avalanche_traces"
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
    def generate_input_bytes(self, flip_bit: bool = False) -> str:
        """
        Generate 64-byte hex input string.
        
        Args:
            flip_bit: If True, flip 1 bit in the first byte
        
        Returns:
            Hex string (128 chars = 64 bytes)
        """
        if flip_bit:
            # Original: 0x41 = 01000001
            # Flipped:  0x40 = 01000000 (flip LSB)
            first_byte = "40"
        else:
            first_byte = "41"
        
        # 64 bytes total
        return first_byte + "41" * 63
    
    def run_feature_extractor(self, input_hex: str, output_trace: str) -> bool:
        """
        Run feature_extractor.py with controlled input override.
        
        Args:
            input_hex: Hex string to inject into recv/read syscalls
            output_trace: Path to save JSONL trace
        
        Returns:
            True if successful, False otherwise
        """
        print(f"[*] Running feature extractor with input: {input_hex[:16]}...")
        print(f"[*] Output trace: {output_trace}")
        
        env = os.environ.copy()
        env["QILING_OVERRIDE_INPUT_HEX"] = input_hex
        env["QILING_OUTPUT_TRACE"] = output_trace
        
        cmd = [
            sys.executable,
            self.feature_extractor_path,
            self.binary_path
        ]
        
        try:
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            if result.returncode == 0:
                print(f"[+] Feature extraction successful")
                return True
            else:
                print(f"[!] Feature extraction failed with code {result.returncode}")
                print(f"[!] STDERR: {result.stderr[:500]}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"[!] Feature extraction timed out (>120s)")
            return False
        except Exception as e:
            print(f"[!] Feature extraction error: {e}")
            return False
    
    def run_experiment(self) -> Dict:
        """
        Execute the full avalanche detection experiment.
        
        Returns:
            Analysis report dict
        """
        print("="*70)
        print("AVALANCHE EFFECT DETECTION EXPERIMENT")
        print("="*70)
        print(f"Target Binary: {self.binary_path}")
        print(f"Feature Extractor: {self.feature_extractor_path}")
        print()
        
        # Step A: Original input (all 0x41)
        print("[STEP A] Running with original input (all 'A's)...")
        original_input = self.generate_input_bytes(flip_bit=False)
        original_trace = os.path.join(self.output_dir, "trace_original.jsonl")
        
        if not self.run_feature_extractor(original_input, original_trace):
            print("[!] EXPERIMENT FAILED at Step A")
            return None
        
        # Step B: Flipped input (first byte 0x40)
        print("\n[STEP B] Running with 1-bit flipped input...")
        flipped_input = self.generate_input_bytes(flip_bit=True)
        flipped_trace = os.path.join(self.output_dir, "trace_flipped.jsonl")
        
        if not self.run_feature_extractor(flipped_input, flipped_trace):
            print("[!] EXPERIMENT FAILED at Step B")
            return None
        
        # Step C: Analysis
        print("\n[STEP C] Analyzing avalanche effect...")
        detector = AvalancheDetector(original_trace, flipped_trace)
        detector.load_traces()
        
        report = detector.generate_report()
        
        # Save report
        report_path = os.path.join(self.output_dir, "avalanche_report.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Full report saved to: {report_path}")
        
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: ./detect_avalanche.py <binary_path> [feature_extractor.py]")
        print()
        print("Example:")
        print("  ./detect_avalanche.py /path/to/crypto_binary")
        print("  ./detect_avalanche.py /path/to/crypto_binary ./custom_extractor.py")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    # Default feature_extractor.py location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_extractor = os.path.join(script_dir, "feature_extractor.py")
    
    feature_extractor = sys.argv[2] if len(sys.argv) > 2 else default_extractor
    
    if not os.path.exists(binary_path):
        print(f"[!] Binary not found: {binary_path}")
        sys.exit(1)
    
    if not os.path.exists(feature_extractor):
        print(f"[!] Feature extractor not found: {feature_extractor}")
        sys.exit(1)
    
    # Run experiment
    experiment = AvalancheExperiment(binary_path, feature_extractor)
    report = experiment.run_experiment()
    
    if report:
        print("\n[SUCCESS] Avalanche detection complete!")
        
        # Print actionable summary
        crypto_blocks = report["data_flow"]["crypto_candidate_blocks"]
        if crypto_blocks:
            print("\n[CRYPTO CANDIDATES] The following blocks exhibit avalanche behavior:")
            for block in crypto_blocks[:5]:
                print(f"  • {block['address']} (divergence_score={block['divergence_score']})")
        else:
            print("\n[INFO] No strong crypto candidates found in basic blocks")
            print("       This may indicate:")
            print("       1. Binary doesn't perform cryptography")
            print("       2. Crypto is in library code (not traced)")
            print("       3. Input didn't trigger crypto path")
    else:
        print("\n[FAILURE] Avalanche detection failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
