#!/usr/bin/env python3
"""
Crypto Loop Analyzer - Identifies crypto algorithms by loop iteration counts

This tool analyzes execution traces to find loops with iteration counts that
match known cryptographic algorithm round counts.

Common patterns:
- 64 iterations  → SHA-256 compression function
- 80 iterations  → SHA-1 compression function
- 10 iterations  → AES-128 encryption (10 rounds)
- 12 iterations  → AES-192 encryption (12 rounds)
- 14 iterations  → AES-256 encryption (14 rounds)
- 20 iterations  → ChaCha20/Salsa20 cipher rounds
- 16 iterations  → MD5 compression function
- 32 iterations  → Common block processing (AES 2-pass, SHA partial)
"""

import os
import sys
import json
from typing import Dict, List, Tuple
from collections import defaultdict


class CryptoLoopAnalyzer:
    """Analyzes execution traces for crypto-indicative loop patterns."""
    
    # Known crypto algorithm signatures
    CRYPTO_SIGNATURES = {
        64: {
            "algorithms": ["SHA-256", "SHA-512"],
            "confidence": "HIGH",
            "description": "SHA-2 family compression function (64 rounds)"
        },
        80: {
            "algorithms": ["SHA-1"],
            "confidence": "HIGH",
            "description": "SHA-1 compression function (80 rounds)"
        },
        10: {
            "algorithms": ["AES-128"],
            "confidence": "HIGH",
            "description": "AES-128 encryption (10 rounds)"
        },
        12: {
            "algorithms": ["AES-192"],
            "confidence": "HIGH",
            "description": "AES-192 encryption (12 rounds)"
        },
        14: {
            "algorithms": ["AES-256"],
            "confidence": "HIGH",
            "description": "AES-256 encryption (14 rounds)"
        },
        20: {
            "algorithms": ["ChaCha20", "Salsa20"],
            "confidence": "HIGH",
            "description": "ChaCha20/Salsa20 cipher (20 rounds)"
        },
        16: {
            "algorithms": ["MD5"],
            "confidence": "MEDIUM",
            "description": "MD5 compression function (16 rounds × 4 = 64 steps)"
        },
        32: {
            "algorithms": ["AES (2-pass)", "SHA (partial)", "Custom"],
            "confidence": "MEDIUM",
            "description": "Block processing or partial rounds"
        },
        8: {
            "algorithms": ["ChaCha8", "DES round"],
            "confidence": "MEDIUM",
            "description": "Reduced-round cipher or DES iteration"
        },
        # High iteration counts (likely main loops)
        128: {
            "algorithms": ["SHA-256 (2 blocks)", "AES-CTR mode"],
            "confidence": "MEDIUM",
            "description": "Multiple block processing"
        },
        256: {
            "algorithms": ["Bulk encryption loop"],
            "confidence": "LOW",
            "description": "Likely outer loop over multiple blocks"
        }
    }
    
    def __init__(self, trace_path: str):
        self.trace_path = trace_path
        self.events = []
        self.loop_blocks = defaultdict(int)
        
    def load_trace(self):
        """Load JSONL trace file."""
        print(f"[*] Loading trace: {self.trace_path}")
        with open(self.trace_path, 'r') as f:
            self.events = [json.loads(line) for line in f]
        print(f"[+] Loaded {len(self.events)} events")
    
    def find_crypto_loops(self) -> List[Dict]:
        """
        Find blocks with high execution counts that match crypto signatures.
        """
        print("\n[*] Analyzing loop iteration counts...")
        
        # Collect all basic blocks with execution counts
        for event in self.events:
            if event["type"] == "basic_block":
                addr = event["data"]["address"]
                exec_count = event["data"].get("execution_count", 1)
                
                # Only track blocks executed multiple times
                if exec_count > 1:
                    self.loop_blocks[addr] = max(self.loop_blocks[addr], exec_count)
        
        print(f"[+] Found {len(self.loop_blocks)} blocks with multiple executions")
        
        # Match against crypto signatures
        matches = []
        
        for addr, count in sorted(self.loop_blocks.items(), key=lambda x: x[1], reverse=True):
            # Find event with this address to get crypto patterns
            has_crypto = False
            mnemonics = []
            
            for event in self.events:
                if event["type"] == "basic_block" and event["data"]["address"] == addr:
                    has_crypto = event["data"].get("metadata", {}).get("has_crypto_patterns", False)
                    mnemonics = event["data"].get("mnemonics_simple", [])
                    break
            
            # Check if count matches known signature
            signature = self.CRYPTO_SIGNATURES.get(count)
            
            match_info = {
                "address": addr,
                "execution_count": count,
                "has_crypto_patterns": has_crypto,
                "mnemonics": mnemonics,
                "signature_match": signature,
                "confidence_score": 0
            }
            
            # Calculate confidence score
            if signature:
                match_info["confidence_score"] += 5  # Known signature
                if signature["confidence"] == "HIGH":
                    match_info["confidence_score"] += 3
                elif signature["confidence"] == "MEDIUM":
                    match_info["confidence_score"] += 1
            
            if has_crypto:
                match_info["confidence_score"] += 3  # Has crypto patterns
            
            if count >= 10:  # Significant iteration count
                match_info["confidence_score"] += 1
            
            if match_info["confidence_score"] > 0 or count >= 10:
                matches.append(match_info)
        
        return matches
    
    def analyze_loop_nesting(self) -> Dict:
        """
        Detect nested loops (outer loop × inner loop = total iterations).
        E.g., 987 = 47 × 21? Could be ChaCha20 (20 rounds) × 47 blocks.
        """
        print("\n[*] Analyzing potential nested loop structures...")
        
        nested_patterns = []
        
        # Look for multiplication patterns
        loop_counts = sorted(self.loop_blocks.values(), reverse=True)
        
        for i, outer_count in enumerate(loop_counts[:10]):  # Check top 10
            for inner_count in [8, 10, 12, 14, 16, 20, 32, 64, 80]:
                if outer_count % inner_count == 0:
                    blocks_processed = outer_count // inner_count
                    
                    nested_patterns.append({
                        "total_iterations": outer_count,
                        "possible_inner_loop": inner_count,
                        "possible_outer_loop": blocks_processed,
                        "hypothesis": f"{blocks_processed} blocks × {inner_count} rounds",
                        "crypto_match": self.CRYPTO_SIGNATURES.get(inner_count, {}).get("algorithms", [])
                    })
        
        return {"nested_loop_candidates": nested_patterns[:5]}  # Top 5 candidates
    
    def generate_report(self) -> Dict:
        """Generate comprehensive crypto loop analysis report."""
        print("\n" + "="*70)
        print("CRYPTO LOOP ANALYSIS REPORT")
        print("="*70)
        
        matches = self.find_crypto_loops()
        nesting = self.analyze_loop_nesting()
        
        # Separate by confidence
        high_confidence = [m for m in matches if m["confidence_score"] >= 8]
        medium_confidence = [m for m in matches if 5 <= m["confidence_score"] < 8]
        low_confidence = [m for m in matches if m["confidence_score"] < 5]
        
        report = {
            "high_confidence_crypto": high_confidence,
            "medium_confidence_crypto": medium_confidence,
            "low_confidence_loops": low_confidence,
            "nested_loop_analysis": nesting
        }
        
        # Print HIGH confidence matches
        if high_confidence:
            print(f"\n[HIGH CONFIDENCE CRYPTO LOOPS] ({len(high_confidence)} found)")
            for i, match in enumerate(high_confidence, 1):
                sig = match["signature_match"]
                print(f"\n  {i}. Block: {match['address']}")
                print(f"     Iterations: {match['execution_count']}")
                print(f"     Confidence Score: {match['confidence_score']}/11")
                
                if sig:
                    print(f"     ✓ SIGNATURE MATCH: {', '.join(sig['algorithms'])}")
                    print(f"     Description: {sig['description']}")
                
                if match['has_crypto_patterns']:
                    print(f"     ✓ Crypto patterns detected: {', '.join(match['mnemonics'][:5])}")
        
        # Print MEDIUM confidence matches
        if medium_confidence:
            print(f"\n[MEDIUM CONFIDENCE] ({len(medium_confidence)} found)")
            for i, match in enumerate(medium_confidence[:5], 1):
                sig = match["signature_match"]
                print(f"  {i}. {match['address']}: {match['execution_count']} iterations "
                      f"(score={match['confidence_score']})")
                if sig:
                    print(f"     Possible: {', '.join(sig['algorithms'])}")
        
        # Print nested loop analysis
        if nesting["nested_loop_candidates"]:
            print(f"\n[NESTED LOOP ANALYSIS]")
            for i, pattern in enumerate(nesting["nested_loop_candidates"][:3], 1):
                print(f"\n  {i}. Total: {pattern['total_iterations']} iterations")
                print(f"     Hypothesis: {pattern['hypothesis']}")
                if pattern["crypto_match"]:
                    print(f"     Possible: {', '.join(pattern['crypto_match'])}")
        
        # Summary statistics
        print(f"\n[SUMMARY]")
        print(f"  Total loops analyzed: {len(self.loop_blocks)}")
        print(f"  High confidence crypto: {len(high_confidence)}")
        print(f"  Medium confidence: {len(medium_confidence)}")
        print(f"  Low confidence: {len(low_confidence)}")
        
        print("\n" + "="*70)
        
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: ./analyze_crypto_loops.py <trace.jsonl>")
        print()
        print("Example:")
        print("  ./analyze_crypto_loops.py traces/wolfssl_chacha_20251204.jsonl")
        sys.exit(1)
    
    trace_path = sys.argv[1]
    
    if not os.path.exists(trace_path):
        print(f"[!] Trace file not found: {trace_path}")
        sys.exit(1)
    
    # Run analysis
    analyzer = CryptoLoopAnalyzer(trace_path)
    analyzer.load_trace()
    report = analyzer.generate_report()
    
    # Save report
    output_path = trace_path.replace(".jsonl", "_loop_analysis.json")
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] Full report saved to: {output_path}")


if __name__ == "__main__":
    main()
