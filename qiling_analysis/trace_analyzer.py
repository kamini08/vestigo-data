#!/usr/bin/env python3
"""
Trace Analyzer - Visualization and Statistics for Training Data

This script analyzes the trace.jsonl output from feature_extractor.py
to validate data quality and visualize patterns for ML training.
"""

import json
import sys
from collections import Counter, defaultdict
from typing import List, Dict, Any


class TraceAnalyzer:
    """Analyzes execution traces for ML training data quality."""
    
    def __init__(self, trace_path: str):
        self.trace_path = trace_path
        self.events = []
        self.load_trace()
    
    def load_trace(self):
        """Load trace from JSONL file."""
        print(f"[*] Loading trace from: {self.trace_path}")
        with open(self.trace_path, 'r') as f:
            for line in f:
                self.events.append(json.loads(line))
        print(f"[+] Loaded {len(self.events)} events\n")
    
    def basic_statistics(self) -> Dict[str, Any]:
        """Calculate basic statistics about the trace."""
        stats = {
            "total_events": len(self.events),
            "basic_blocks": 0,
            "syscalls": 0,
            "crypto_blocks": 0,
            "high_entropy_io": 0,
            "unique_blocks": set(),
            "syscall_types": Counter(),
            "avg_block_size": [],
            "avg_instruction_count": []
        }
        
        for event in self.events:
            if event["type"] == "basic_block":
                stats["basic_blocks"] += 1
                data = event["data"]
                if data.get("bytes_hash"):
                    stats["unique_blocks"].add(data["bytes_hash"])
                if data.get("has_crypto_patterns"):
                    stats["crypto_blocks"] += 1
                if "size" in data:
                    stats["avg_block_size"].append(data["size"])
                if "instruction_count" in data:
                    stats["avg_instruction_count"].append(data["instruction_count"])
            
            elif event["type"] == "syscall":
                stats["syscalls"] += 1
                data = event["data"]
                stats["syscall_types"][data["name"]] += 1
                if data.get("likely_encrypted"):
                    stats["high_entropy_io"] += 1
        
        # Calculate averages
        stats["unique_blocks"] = len(stats["unique_blocks"])
        if stats["avg_block_size"]:
            stats["avg_block_size"] = sum(stats["avg_block_size"]) / len(stats["avg_block_size"])
        else:
            stats["avg_block_size"] = 0
        
        if stats["avg_instruction_count"]:
            stats["avg_instruction_count"] = sum(stats["avg_instruction_count"]) / len(stats["avg_instruction_count"])
        else:
            stats["avg_instruction_count"] = 0
        
        return stats
    
    def print_statistics(self, stats: Dict[str, Any]):
        """Pretty print statistics."""
        print("="*70)
        print("TRACE STATISTICS")
        print("="*70)
        print(f"Total Events:              {stats['total_events']:>10,}")
        print(f"  - Basic Blocks:          {stats['basic_blocks']:>10,}")
        print(f"  - Syscalls:              {stats['syscalls']:>10,}")
        print(f"Unique Blocks (by hash):   {stats['unique_blocks']:>10,}")
        print(f"Crypto Pattern Blocks:     {stats['crypto_blocks']:>10,}")
        print(f"High-Entropy I/O Events:   {stats['high_entropy_io']:>10,}")
        print(f"Avg Block Size (bytes):    {stats['avg_block_size']:>10.2f}")
        print(f"Avg Instructions/Block:    {stats['avg_instruction_count']:>10.2f}")
        print("="*70)
        print("\nSYSCALL DISTRIBUTION:")
        print("-"*70)
        for syscall, count in stats['syscall_types'].most_common():
            print(f"  {syscall:<25} {count:>6,} ({count/stats['syscalls']*100:>5.1f}%)")
        print("="*70)
    
    def analyze_crypto_patterns(self):
        """Analyze sequences of crypto operations."""
        print("\nCRYPTO PATTERN ANALYSIS:")
        print("="*70)
        
        crypto_sequences = []
        current_sequence = []
        
        for i, event in enumerate(self.events):
            if event["type"] == "basic_block" and event["data"].get("has_crypto_patterns"):
                current_sequence.append(i)
            else:
                if current_sequence:
                    crypto_sequences.append(current_sequence)
                    current_sequence = []
        
        if current_sequence:
            crypto_sequences.append(current_sequence)
        
        print(f"Crypto Sequences Found:    {len(crypto_sequences)}")
        if crypto_sequences:
            lengths = [len(seq) for seq in crypto_sequences]
            print(f"Avg Sequence Length:       {sum(lengths)/len(lengths):.2f} blocks")
            print(f"Longest Sequence:          {max(lengths)} blocks")
            print(f"Shortest Sequence:         {min(lengths)} blocks")
        
        # Analyze what happens after crypto blocks
        crypto_followed_by_io = 0
        crypto_followed_by_high_entropy = 0
        
        for i, event in enumerate(self.events):
            if event["type"] == "basic_block" and event["data"].get("has_crypto_patterns"):
                # Look at next few events
                for j in range(i+1, min(i+5, len(self.events))):
                    next_event = self.events[j]
                    if next_event["type"] == "syscall":
                        if next_event["data"]["name"] in ["send", "write", "sendto"]:
                            crypto_followed_by_io += 1
                            if next_event["data"].get("likely_encrypted"):
                                crypto_followed_by_high_entropy += 1
                        break
        
        print(f"\nCrypto → I/O Patterns:")
        print(f"  Crypto followed by I/O:  {crypto_followed_by_io}")
        print(f"  → High entropy I/O:      {crypto_followed_by_high_entropy}")
        if crypto_followed_by_io > 0:
            print(f"  Encryption likelihood:   {crypto_followed_by_high_entropy/crypto_followed_by_io*100:.1f}%")
        print("="*70)
    
    def analyze_instruction_patterns(self):
        """Analyze common instruction patterns."""
        print("\nINSTRUCTION PATTERN ANALYSIS:")
        print("="*70)
        
        all_mnemonics = []
        crypto_mnemonics = []
        
        for event in self.events:
            if event["type"] == "basic_block":
                mnemonics = event["data"].get("mnemonics", [])
                all_mnemonics.extend(mnemonics)
                if event["data"].get("has_crypto_patterns"):
                    crypto_mnemonics.extend(mnemonics)
        
        print(f"Total Instructions:        {len(all_mnemonics):,}")
        print(f"Unique Mnemonics:          {len(set(all_mnemonics))}")
        
        print(f"\nTop 10 Most Common Instructions:")
        for mnemonic, count in Counter(all_mnemonics).most_common(10):
            print(f"  {mnemonic:<15} {count:>8,} ({count/len(all_mnemonics)*100:>5.2f}%)")
        
        if crypto_mnemonics:
            print(f"\nCrypto Block Instructions:")
            print(f"  Total:                   {len(crypto_mnemonics):,}")
            print(f"  Top 5:")
            for mnemonic, count in Counter(crypto_mnemonics).most_common(5):
                print(f"    {mnemonic:<15} {count:>6,}")
        
        print("="*70)
    
    def analyze_entropy_distribution(self):
        """Analyze entropy distribution of I/O operations."""
        print("\nENTROPY ANALYSIS:")
        print("="*70)
        
        entropies = []
        io_syscalls = []
        
        for event in self.events:
            if event["type"] == "syscall":
                data = event["data"]
                if "entropy" in data:
                    entropies.append(data["entropy"])
                    io_syscalls.append((data["name"], data["entropy"], data.get("buffer_size", 0)))
        
        if not entropies:
            print("No entropy data found in trace.")
            print("="*70)
            return
        
        print(f"Total I/O with entropy:    {len(entropies)}")
        print(f"Avg Entropy:               {sum(entropies)/len(entropies):.4f}")
        print(f"Min Entropy:               {min(entropies):.4f}")
        print(f"Max Entropy:               {max(entropies):.4f}")
        
        # Entropy buckets
        low = sum(1 for e in entropies if e < 3.0)
        medium = sum(1 for e in entropies if 3.0 <= e < 7.0)
        high = sum(1 for e in entropies if e >= 7.0)
        
        print(f"\nEntropy Distribution:")
        print(f"  Low (<3.0):              {low:>6} ({low/len(entropies)*100:>5.1f}%)")
        print(f"  Medium (3.0-7.0):        {medium:>6} ({medium/len(entropies)*100:>5.1f}%)")
        print(f"  High (≥7.0):             {high:>6} ({high/len(entropies)*100:>5.1f}%)")
        
        print(f"\nHigh-Entropy Events (likely encrypted):")
        for name, entropy, size in sorted(io_syscalls, key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {name:<10} entropy={entropy:.4f}  size={size:>6} bytes")
        
        print("="*70)
    
    def find_protocol_signatures(self):
        """Attempt to identify protocol signatures from patterns."""
        print("\nPROTOCOL SIGNATURE DETECTION:")
        print("="*70)
        
        signatures = {
            "TLS_handshake": 0,
            "encrypted_stream": 0,
            "plaintext_config": 0,
            "crypto_computation": 0
        }
        
        for i, event in enumerate(self.events):
            # TLS handshake: low entropy send followed by recv
            if event["type"] == "syscall" and event["data"]["name"] in ["send", "sendto"]:
                entropy = event["data"].get("entropy", 0)
                if entropy < 5.0 and i + 1 < len(self.events):
                    next_event = self.events[i + 1]
                    if next_event["type"] == "syscall" and next_event["data"]["name"] in ["recv", "recvfrom"]:
                        signatures["TLS_handshake"] += 1
            
            # Encrypted stream: crypto block → high entropy send
            if event["type"] == "basic_block" and event["data"].get("has_crypto_patterns"):
                signatures["crypto_computation"] += 1
                for j in range(i+1, min(i+5, len(self.events))):
                    next_event = self.events[j]
                    if next_event["type"] == "syscall":
                        if next_event["data"]["name"] in ["send", "write"]:
                            if next_event["data"].get("likely_encrypted"):
                                signatures["encrypted_stream"] += 1
                        break
            
            # Plaintext config: read with low entropy
            if event["type"] == "syscall" and event["data"]["name"] == "read":
                entropy = event["data"].get("entropy", 0)
                if entropy < 4.0:
                    signatures["plaintext_config"] += 1
        
        print("Detected Patterns:")
        for sig_name, count in signatures.items():
            print(f"  {sig_name:<25} {count:>6}")
        
        # Simple protocol prediction
        print(f"\nLikely Protocol Characteristics:")
        if signatures["encrypted_stream"] > 5 and signatures["TLS_handshake"] > 0:
            print("  ✓ TLS/SSL-like encrypted communication")
        elif signatures["encrypted_stream"] > 3:
            print("  ✓ Custom encrypted protocol")
        if signatures["crypto_computation"] > 10:
            print("  ✓ Heavy cryptographic operations (AES/ChaCha likely)")
        if signatures["plaintext_config"] > 0:
            print("  ✓ Configuration file parsing detected")
        
        print("="*70)
    
    def run_full_analysis(self):
        """Run all analysis modules."""
        stats = self.basic_statistics()
        self.print_statistics(stats)
        self.analyze_crypto_patterns()
        self.analyze_instruction_patterns()
        self.analyze_entropy_distribution()
        self.find_protocol_signatures()
        
        print("\n" + "="*70)
        print("ML TRAINING DATA QUALITY ASSESSMENT")
        print("="*70)
        
        # Quality metrics
        quality_score = 0
        max_score = 5
        
        # 1. Sufficient events
        if stats["total_events"] > 100:
            print("✓ Sufficient events for training (>100)")
            quality_score += 1
        else:
            print("✗ Insufficient events (<100)")
        
        # 2. Good block diversity
        if stats["unique_blocks"] > 50:
            print("✓ Good block diversity (>50 unique)")
            quality_score += 1
        else:
            print("✗ Low block diversity (<50 unique)")
        
        # 3. Crypto patterns present
        if stats["crypto_blocks"] > 0:
            print(f"✓ Crypto patterns detected ({stats['crypto_blocks']} blocks)")
            quality_score += 1
        else:
            print("✗ No crypto patterns detected")
        
        # 4. Syscall variety
        if len(stats["syscall_types"]) > 3:
            print(f"✓ Good syscall variety ({len(stats['syscall_types'])} types)")
            quality_score += 1
        else:
            print("✗ Limited syscall variety")
        
        # 5. Entropy data available
        if stats["high_entropy_io"] > 0:
            print(f"✓ High-entropy I/O detected ({stats['high_entropy_io']} events)")
            quality_score += 1
        else:
            print("⚠ No high-entropy I/O (may be plaintext-only)")
        
        print(f"\nQuality Score: {quality_score}/{max_score}")
        if quality_score >= 4:
            print("Status: ✓ EXCELLENT - Ready for ML training")
        elif quality_score >= 3:
            print("Status: ✓ GOOD - Suitable for ML training")
        elif quality_score >= 2:
            print("Status: ⚠ FAIR - May need longer traces")
        else:
            print("Status: ✗ POOR - Binary may need different inputs/environment")
        
        print("="*70)


def main():
    if len(sys.argv) < 2:
        print("Usage: python trace_analyzer.py <trace.jsonl>")
        print("\nExample:")
        print("  python trace_analyzer.py trace.jsonl")
        sys.exit(1)
    
    trace_path = sys.argv[1]
    
    try:
        analyzer = TraceAnalyzer(trace_path)
        analyzer.run_full_analysis()
    except FileNotFoundError:
        print(f"[!] Error: Trace file not found: {trace_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Error: Invalid JSON in trace file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
