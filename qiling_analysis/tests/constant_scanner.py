#!/usr/bin/env python3
"""
Constant Scanner - FindCrypt-style detection
Scans binaries for known cryptographic constants (S-Boxes, IVs, round constants).
Uses both direct binary search and YARA rules for maximum compatibility.
"""

import os
import sys
from crypto_constants import *

def scan_for_constants(binary_path):
    """
    Scan binary for crypto constants using direct byte search.
    Returns dict of detected algorithms with addresses.
    """
    detected = {}
    
    try:
        with open(binary_path, 'rb') as f:
            binary_data = f.read()
    except Exception as e:
        print(f"[-] Failed to read binary: {e}")
        return detected
    
    # Search patterns
    search_patterns = {
        'AES': [
            ('AES_SBOX', AES_SBOX, 64),          # First 64 bytes of S-Box
            ('AES_INV_SBOX', AES_INV_SBOX, 64),  # First 64 bytes of Inv S-Box
            ('AES_RCON', bytes(AES_RCON), 10),   # First 10 Rcon values
        ],
        'DES': [
            ('DES_SBOX1', DES_SBOX1, 32),
            ('DES_SBOX2', DES_SBOX2, 32),
            ('DES_IP', DES_IP, 32),
        ],
        'SHA256': [
            ('SHA256_H', b''.join(h.to_bytes(4, 'big') for h in SHA256_H), 16),
            ('SHA256_K', b''.join(k.to_bytes(4, 'big') for k in SHA256_K[:8]), 16),
        ],
        'SHA1': [
            ('SHA1_H', b''.join(h.to_bytes(4, 'big') for h in SHA1_H), 16),
        ],
        'MD5': [
            ('MD5_IV', b''.join(iv.to_bytes(4, 'little') for iv in MD5_IV), 16),
            ('MD5_K', b''.join(k.to_bytes(4, 'little') for k in MD5_K[:4]), 16),
        ],
        'ChaCha20': [
            ('CHACHA20', CHACHA20_CONSTANT, 16),
        ],
    }
    
    # RSA exponents - DISABLED due to false positives
    # Common values like 65537 appear in normal code too frequently
    # Only search for 65537 if found alongside other crypto constants
    # search_patterns['RSA'] = []
    
    # Search for each pattern
    for algo_name, patterns in search_patterns.items():
        for const_name, pattern, min_length in patterns:
            # Use only first min_length bytes for matching
            search_bytes = pattern[:min_length]
            
            offset = 0
            while True:
                idx = binary_data.find(search_bytes, offset)
                if idx == -1:
                    break
                
                # Found a match!
                if algo_name not in detected:
                    detected[algo_name] = []
                
                detected[algo_name].append({
                    'constant': const_name,
                    'offset': idx,
                    'size': len(search_bytes),
                })
                
                offset = idx + 1  # Continue searching
    
    return detected

def scan_with_yara(binary_path):
    """
    Scan binary using YARA rules (if available).
    Falls back to direct scan if YARA not installed.
    """
    try:
        import yara
    except ImportError:
        print("[*] YARA not installed, using direct byte search")
        return scan_for_constants(binary_path)
    
    # Define YARA rules for crypto constants
    yara_rules = '''
    rule AES_SBOX {
        meta:
            description = "AES S-Box detected"
            algorithm = "AES"
        strings:
            $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        condition:
            $sbox
    }
    
    rule AES_INV_SBOX {
        meta:
            description = "AES Inverse S-Box detected"
            algorithm = "AES"
        strings:
            $inv_sbox = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
        condition:
            $inv_sbox
    }
    
    rule SHA256_K {
        meta:
            description = "SHA-256 round constants detected"
            algorithm = "SHA256"
        strings:
            $k0 = { 42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5 }
        condition:
            $k0
    }
    
    rule SHA256_H {
        meta:
            description = "SHA-256 initial hash values detected"
            algorithm = "SHA256"
        strings:
            $h0 = { 6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A }
        condition:
            $h0
    }
    
    rule SHA1_H {
        meta:
            description = "SHA-1 initial hash values detected"
            algorithm = "SHA1"
        strings:
            $h0 = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 }
        condition:
            $h0
    }
    
    rule MD5_IV {
        meta:
            description = "MD5 initialization vector detected"
            algorithm = "MD5"
        strings:
            $iv = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
        condition:
            $iv
    }
    
    rule DES_SBOX {
        meta:
            description = "DES S-Box detected"
            algorithm = "DES"
        strings:
            $sbox1 = { 0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07 }
        condition:
            $sbox1
    }
    
    rule ChaCha20_Constant {
        meta:
            description = "ChaCha20 constant string detected"
            algorithm = "ChaCha20"
        strings:
            $constant = "expand 32-byte k"
        condition:
            $constant
    }
    
    rule RSA_Common_Exponent {
        meta:
            description = "RSA common public exponent (65537)"
            algorithm = "RSA"
        strings:
            $e_be = { 00 01 00 01 }  // 65537 in big-endian
            $e_le = { 01 00 01 00 }  // 65537 in little-endian
        condition:
            any of them
    }
    '''
    
    try:
        rules = yara.compile(source=yara_rules)
        matches = rules.match(binary_path)
        
        detected = {}
        for match in matches:
            algo = match.meta.get('algorithm', 'Unknown')
            if algo not in detected:
                detected[algo] = []
            
            for string_match in match.strings:
                detected[algo].append({
                    'constant': match.rule,
                    'offset': string_match.instances[0].offset,
                    'size': string_match.instances[0].length,
                })
        
        return detected
        
    except Exception as e:
        print(f"[*] YARA scan failed ({e}), falling back to direct search")
        return scan_for_constants(binary_path)

def print_scan_results(detected):
    """Pretty-print scan results."""
    if not detected:
        print("[-] No crypto constants detected")
        return 0
    
    print(f"\n[✓] Detected {len(detected)} cryptographic algorithm(s):")
    
    total_constants = 0
    for algo, constants in detected.items():
        print(f"\n  [{algo}]")
        
        # Group by constant name
        const_groups = {}
        for const_info in constants:
            name = const_info['constant']
            if name not in const_groups:
                const_groups[name] = []
            const_groups[name].append(const_info)
        
        for const_name, instances in const_groups.items():
            total_constants += len(instances)
            print(f"    {const_name}: {len(instances)} instance(s)")
            for inst in instances[:3]:  # Show first 3 addresses
                print(f"      @ offset {hex(inst['offset'])} ({inst['size']} bytes)")
            if len(instances) > 3:
                print(f"      ... and {len(instances) - 3} more")
    
    return total_constants

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 constant_scanner.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    if not os.path.exists(binary_path):
        print(f"[-] File not found: {binary_path}")
        sys.exit(1)
    
    print(f"[*] Scanning {os.path.basename(binary_path)} for crypto constants...")
    
    # Try YARA first, fallback to direct search
    detected = scan_with_yara(binary_path)
    
    total = print_scan_results(detected)
    
    print(f"\n[*] Total: {total} crypto constant(s) found")
    
    if total > 0:
        print("[✓] Binary likely contains cryptographic code")
    else:
        print("[-] No strong crypto indicators found")
