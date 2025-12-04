#!/usr/bin/env python3
"""
YARA-based Crypto Scanner
Ultra-fast static analysis using YARA rules to detect crypto constants.
Works on stripped binaries, obfuscated code, and firmware images.
Execution time: < 1 second for most binaries.
"""

import os
import sys
import yara

class YaraCryptoScanner:
    """
    Fast static crypto detection using YARA rules.
    Detects S-boxes, IVs, round constants, magic numbers.
    """
    
    def __init__(self, rules_path=None):
        """Initialize scanner with YARA rules."""
        if rules_path is None:
            # Default to crypto.yar in same directory
            rules_path = os.path.join(os.path.dirname(__file__), 'crypto.yar')
        
        if not os.path.exists(rules_path):
            raise FileNotFoundError(f"YARA rules not found: {rules_path}")
        
        try:
            self.rules = yara.compile(filepath=rules_path)
        except Exception as e:
            raise RuntimeError(f"Failed to compile YARA rules: {e}")
    
    def scan_file(self, binary_path):
        """
        Scan binary file for crypto constants.
        Returns dict with detected algorithms and match details.
        
        Returns:
            {
                'detected': ['AES', 'SHA256', ...],
                'matches': [
                    {
                        'rule': 'AES_Sbox',
                        'algorithm': 'AES',
                        'confidence': 95,
                        'description': '...',
                        'offsets': [0x1000, 0x2000],
                        'strings': [...]
                    },
                    ...
                ]
            }
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        results = {
            'detected': set(),
            'matches': [],
            'total_matches': 0,
            'scan_time': 0
        }
        
        import time
        start_time = time.time()
        
        try:
            # Run YARA scan
            matches = self.rules.match(binary_path)
            
            for match in matches:
                # Extract metadata
                algo = match.meta.get('algorithm', 'Unknown')
                confidence = match.meta.get('confidence', 50)
                description = match.meta.get('description', match.rule)
                
                # Collect match offsets
                offsets = []
                string_matches = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        offsets.append(instance.offset)
                    string_matches.append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })
                
                results['detected'].add(algo)
                results['matches'].append({
                    'rule': match.rule,
                    'algorithm': algo,
                    'confidence': confidence,
                    'description': description,
                    'offsets': offsets,
                    'strings': string_matches,
                    'match_count': len(offsets)
                })
                results['total_matches'] += len(offsets)
        
        except Exception as e:
            print(f"[-] YARA scan error: {e}")
            return results
        
        finally:
            results['scan_time'] = time.time() - start_time
        
        # Convert set to sorted list
        results['detected'] = sorted(list(results['detected']))
        
        return results
    
    def scan_memory(self, memory_data):
        """
        Scan memory buffer for crypto constants.
        Useful for scanning extracted firmware sections.
        """
        results = {
            'detected': set(),
            'matches': [],
            'total_matches': 0
        }
        
        try:
            matches = self.rules.match(data=memory_data)
            
            for match in matches:
                algo = match.meta.get('algorithm', 'Unknown')
                confidence = match.meta.get('confidence', 50)
                description = match.meta.get('description', match.rule)
                
                offsets = []
                string_matches = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        offsets.append(instance.offset)
                    string_matches.append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })
                
                results['detected'].add(algo)
                results['matches'].append({
                    'rule': match.rule,
                    'algorithm': algo,
                    'confidence': confidence,
                    'description': description,
                    'offsets': offsets,
                    'strings': string_matches,
                    'match_count': len(offsets)
                })
                results['total_matches'] += len(offsets)
        
        except Exception as e:
            print(f"[-] YARA memory scan error: {e}")
        
        results['detected'] = sorted(list(results['detected']))
        return results


def format_results(results):
    """Format YARA scan results for display."""
    output = []
    
    output.append("=" * 80)
    output.append("YARA CRYPTO DETECTION RESULTS")
    output.append("=" * 80)
    
    if not results['matches']:
        output.append("[-] No cryptographic constants detected")
        return "\n".join(output)
    
    output.append(f"\n[+] Detected Algorithms: {', '.join(results['detected'])}")
    output.append(f"[+] Total Matches: {results['total_matches']}")
    if 'scan_time' in results:
        output.append(f"[+] Scan Time: {results['scan_time']:.3f} seconds")
    output.append("")
    
    # Group matches by algorithm
    by_algo = {}
    for match in results['matches']:
        algo = match['algorithm']
        if algo not in by_algo:
            by_algo[algo] = []
        by_algo[algo].append(match)
    
    # Display results grouped by algorithm
    for algo in sorted(by_algo.keys()):
        output.append(f"\n{'=' * 60}")
        output.append(f"Algorithm: {algo}")
        output.append(f"{'=' * 60}")
        
        for match in by_algo[algo]:
            output.append(f"\n  Rule: {match['rule']}")
            output.append(f"  Confidence: {match['confidence']}%")
            output.append(f"  Description: {match['description']}")
            output.append(f"  Match Count: {match['match_count']}")
            
            if match['offsets']:
                # Show first 5 offsets
                offsets_display = [f"0x{off:x}" for off in match['offsets'][:5]]
                if len(match['offsets']) > 5:
                    offsets_display.append(f"... (+{len(match['offsets']) - 5} more)")
                output.append(f"  Offsets: {', '.join(offsets_display)}")
            
            if match['strings']:
                output.append("  Matched Strings:")
                for sm in match['strings']:
                    output.append(f"    - {sm['identifier']}: {sm['instances']} instance(s)")
    
    output.append("\n" + "=" * 80)
    return "\n".join(output)


def print_scan_results(results):
    """Print formatted YARA scan results."""
    print(format_results(results))


def main():
    """CLI interface for YARA crypto scanner."""
    if len(sys.argv) < 2:
        print("Usage: python3 yara_scanner.py <binary_path>")
        print("\nQuick crypto detection using YARA rules.")
        print("Detects: AES, DES, SHA-1/256/512, MD5, ChaCha20, RC4, Blowfish, etc.")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if not os.path.exists(binary_path):
        print(f"[-] Error: File not found: {binary_path}")
        sys.exit(1)
    
    print(f"[*] Scanning: {binary_path}")
    print(f"[*] File size: {os.path.getsize(binary_path) / 1024:.2f} KB")
    print()
    
    try:
        scanner = YaraCryptoScanner()
        results = scanner.scan_file(binary_path)
        print_scan_results(results)
        
        # Exit code: 0 if crypto detected, 1 if not
        sys.exit(0 if results['detected'] else 1)
        
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
