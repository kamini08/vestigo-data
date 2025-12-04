#!/usr/bin/env python3
import sys
import re
import struct
import argparse
import math
import json
from pathlib import Path
from collections import Counter


class SecureBootAnalyzer:
    def __init__(self, bootloader_path, json_output=False):
        self.path = Path(bootloader_path)
        self.json_output = json_output
        self.results = {}  # Store results for JSON output
        
        if not self.path.exists():
            raise FileNotFoundError(f"Bootloader file not found: {bootloader_path}")
        
        with open(self.path, 'rb') as f:
            self.binary_data = f.read()
        
        # Extract strings
        self.strings = self._extract_strings()
    
    def _extract_strings(self, min_length=4):
        """Extract printable ASCII strings from binary"""
        pattern = rb'[\x20-\x7E]{%d,}' % min_length
        strings = re.findall(pattern, self.binary_data)
        return [s.decode('ascii', errors='ignore') for s in strings]
    
    def check_secure_boot_logic(self):
        """Check for secure boot related strings (Chain of Trust indicators)"""
        print("\n[1] Secure Boot Logic Detection (Chain of Trust)")
        print("=" * 60)
        
        # Enhanced patterns including platform-specific implementations
        patterns = [
            r'verify',
            r'authenticate',
            r'signature',
            r'invalid',
            r'secure[\s_-]?boot',
            r'auth',
            r'signed',
            r'trust',
            r'valid',
            r'check',
            # Platform-specific
            r'hab_',           # NXP/Freescale i.MX High Assurance Boot
            r'avb_',           # Android Verified Boot
            r'fit_image',      # U-Boot Flattened Image Tree
            r'image_sign',     # Generic image signing
            r'rotpk',          # Root of Trust Public Key
            r'verified.?boot',
            r'hab_auth',
            r'hab_status',
            r'avb_slot_verify',
            r'fit_image_check_sig',
            r'fit_image_verify',
        ]
        
        findings = set()
        for string in self.strings:
            for pattern in patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    findings.add(string)
        
        if findings:
            print(f"✓ Found {len(findings)} secure boot related strings:")
            
            # Categorize findings
            hab_findings = [f for f in findings if re.search(r'hab_', f, re.IGNORECASE)]
            avb_findings = [f for f in findings if re.search(r'avb_', f, re.IGNORECASE)]
            fit_findings = [f for f in findings if re.search(r'fit_', f, re.IGNORECASE)]
            generic = [f for f in findings if f not in hab_findings + avb_findings + fit_findings]
            
            if hab_findings:
                print("\n  HAB (High Assurance Boot - NXP/Freescale):")
                for f in sorted(hab_findings)[:10]:
                    print(f"    - {f}")
            
            if avb_findings:
                print("\n  AVB (Android Verified Boot):")
                for f in sorted(avb_findings)[:10]:
                    print(f"    - {f}")
            
            if fit_findings:
                print("\n  FIT (Flattened Image Tree - U-Boot):")
                for f in sorted(fit_findings)[:10]:
                    print(f"    - {f}")
            
            if generic:
                print("\n  Generic Secure Boot:")
                for f in sorted(generic)[:30]:
                    print(f"    - {f}")
        else:
            print("✗ No secure boot strings found")
        
        return bool(findings)
    
    def detect_crypto_algorithms(self):
        """Detect cryptographic algorithm usage"""
        print("\n[2] Cryptographic Algorithm Detection")
        print("=" * 60)
        
        # Hash algorithms
        hash_patterns = {
            'SHA-256': [r'sha256', r'sha-256', r'SHA256'],
            'SHA-384': [r'sha384', r'sha-384', r'SHA384'],
            'SHA-512': [r'sha512', r'sha-512', r'SHA512'],
            'SHA-1': [r'sha1', r'sha-1', r'SHA1'],
            'MD5': [r'md5', r'MD5'],
        }
        
        # Signature algorithms
        sig_patterns = {
            'RSA': [r'rsa', r'RSA', r'pkcs', r'PKCS'],
            'ECDSA': [r'ecdsa', r'ECDSA', r'ecc', r'ECC', r'elliptic'],
            'Ed25519': [r'ed25519', r'Ed25519'],
        }
        
        print("\n--- Hash Functions ---")
        hash_found = {}
        for algo, patterns in hash_patterns.items():
            matches = []
            for string in self.strings:
                for pattern in patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        matches.append(string)
            if matches:
                hash_found[algo] = list(set(matches))
                print(f"✓ {algo}: {len(matches)} references")
                for match in matches[:3]:
                    print(f"    {match}")
        
        print("\n--- Signature Algorithms ---")
        sig_found = {}
        for algo, patterns in sig_patterns.items():
            matches = []
            for string in self.strings:
                for pattern in patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        matches.append(string)
            if matches:
                sig_found[algo] = list(set(matches))
                print(f"✓ {algo}: {len(matches)} references")
                for match in matches[:3]:
                    print(f"    {match}")
        
        # Check for crypto library references
        print("\n--- Crypto Libraries ---")
        libraries = ['openssl', 'mbedtls', 'wolfssl', 'libcrypto', 'tinycrypt', 'bearssl']
        for lib in libraries:
            matches = [s for s in self.strings if lib in s.lower()]
            if matches:
                print(f"✓ {lib.upper()}: {len(matches)} references")
        
        return hash_found, sig_found
    
    def find_root_of_trust(self):
        """Search for embedded keys and certificates"""
        print("\n[3] Root of Trust Analysis")
        print("=" * 60)
        
        # PEM format keys
        pem_patterns = [
            b'-----BEGIN PUBLIC KEY-----',
            b'-----BEGIN RSA PUBLIC KEY-----',
            b'-----BEGIN CERTIFICATE-----',
            b'-----BEGIN EC PRIVATE KEY-----',
        ]
        
        print("\n--- PEM Format Keys/Certificates ---")
        for pattern in pem_patterns:
            if pattern in self.binary_data:
                print(f"✓ Found: {pattern.decode()}")
                # Extract the full PEM block
                start = self.binary_data.find(pattern)
                end_pattern = pattern.replace(b'BEGIN', b'END')
                end = self.binary_data.find(end_pattern, start)
                if end != -1:
                    pem_block = self.binary_data[start:end + len(end_pattern)]
                    print(pem_block.decode('ascii', errors='ignore')[:500])
        
        # DER format (ASN.1) with validation
        print("\n--- DER Encoded Keys/Certificates ---")
        der_findings = self._find_valid_der_structures()
        
        if der_findings:
            for i, (pos, length, der_type) in enumerate(der_findings[:5]):
                print(f"✓ Valid DER {der_type} at offset 0x{pos:08x} (length: {length} bytes)")
            
            if len(der_findings) > 5:
                print(f"  ... and {len(der_findings) - 5} more valid DER structures")
        else:
            print("✗ No valid DER structures found")
        
        # SHA256 hash of public key (common in embedded systems)
        print("\n--- Potential Key Hashes (SHA256) ---")
        # Look for 32-byte aligned data that could be hashes
        hash_count = 0
        max_hashes = 10  # Limit output to first 10 potential hashes
        potential_hashes = []
        
        for i in range(0, len(self.binary_data) - 32, 4):
            chunk = self.binary_data[i:i+32]
            # Check if it looks like random data (potential hash)
            if self._looks_like_hash(chunk):
                potential_hashes.append((i, chunk.hex()))
                hash_count += 1
                if hash_count <= max_hashes:
                    print(f"Potential hash at offset 0x{i:08x}: {chunk.hex()}")
        
        if hash_count > max_hashes:
            print(f"  ... and {hash_count - max_hashes} more potential hashes")
        
        if hash_count == 0:
            print("✗ No potential key hashes found")
    
    def _looks_like_hash(self, data):
        """Heuristic to detect if data looks like a hash using entropy analysis"""
        if len(data) != 32:
            return False
        
        # Reject obvious non-hash patterns
        if data == b'\x00' * 32 or data == b'\xff' * 32:
            return False
        
        # Check for repeating patterns (e.g., 0xABABABAB...)
        if len(set(data[i:i+4].hex() for i in range(0, 32, 4))) < 4:
            return False
        
        # Calculate entropy - hashes should have high entropy (close to 1.0)
        entropy = self.calculate_entropy(data)
        
        # Hashes typically have entropy > 0.85 (very random)
        # Also check byte distribution - should have reasonable spread
        unique_bytes = len(set(data))
        
        return entropy > 0.85 and unique_bytes > 16
    
    def find_secure_storage_refs(self):
        """Find references to secure storage locations"""
        print("\n[4] Secure Storage Location References")
        print("=" * 60)
        
        storage_keywords = [
            r'boot[\s_-]?rom',
            r'otp',
            r'efuse',
            r'e-fuse',
            r'read[\s_-]?only',
            r'flash[\s_-]?protect',
            r'secure[\s_-]?region',
            r'fuse',
            r'trustzone',
            r'secure[\s_-]?world',
        ]
        
        findings = set()
        for string in self.strings:
            for keyword in storage_keywords:
                if re.search(keyword, string, re.IGNORECASE):
                    findings.add(string)
        
        if findings:
            print(f"✓ Found {len(findings)} secure storage references:")
            for finding in sorted(findings)[:30]:
                print(f"  - {finding}")
        else:
            print("✗ No secure storage references found")
        
        # Look for memory addresses
        print("\n--- Memory Addresses in Secure Context ---")
        addr_pattern = r'0x[0-9a-fA-F]{8}'
        secure_addrs = set()
        for string in self.strings:
            if any(kw in string.lower() for kw in ['rom', 'key', 'cert', 'secure', 'trust', 'fuse']):
                addrs = re.findall(addr_pattern, string)
                for addr in addrs:
                    secure_addrs.add(f"{addr} in context: {string[:60]}")
        
        for addr in list(secure_addrs)[:10]:
            print(f"  {addr}")
    
    def detect_crypto_constants(self):
        """Detect known cryptographic constants in binary"""
        print("\n[5] Cryptographic Constants Detection")
        print("=" * 60)
        
        # SHA256 K constants (first 4)
        sha256_k = [
            b'\x98\x2f\x8a\x42',  # 0x428a2f98
            b'\x91\x44\x37\x71',  # 0x71374491
            b'\xcf\xfb\xc0\xb5',  # 0xb5c0fbcf
            b'\xe9\xb5\xdb\xa5',  # 0xa5dbb5e9
        ]
        
        print("\n--- SHA256 Constants ---")
        for i, const in enumerate(sha256_k):
            positions = []
            offset = 0
            while True:
                pos = self.binary_data.find(const, offset)
                if pos == -1:
                    break
                positions.append(pos)
                offset = pos + 1
            
            if positions:
                print(f"✓ K[{i}] found at {len(positions)} location(s): {[f'0x{p:08x}' for p in positions[:3]]}")
        
        # SHA256 initial hash values (complete set)
        print("\n--- SHA256 Initial Hash Values ---")
        sha256_h = [
            b'\x67\xe6\x09\x6a',  # 0x6a09e667 (little endian)
            b'\x6a\x09\xe6\x67',  # 0x6a09e667 (big endian)
        ]
        for const in sha256_h:
            pos = self.binary_data.find(const)
            if pos != -1:
                print(f"✓ SHA256 H[0] constant found at offset 0x{pos:08x}")
                break
        
        # RSA PKCS#1 padding
        print("\n--- RSA Signature Padding (PKCS#1) ---")
        pkcs1_pattern = b'\x00\x01\xff\xff'
        pos = self.binary_data.find(pkcs1_pattern)
        if pos != -1:
            print(f"✓ PKCS#1 padding found at offset 0x{pos:08x}")
        
        # ASN.1 OID for RSA encryption (1.2.840.113549.1.1.1)
        print("\n--- RSA Algorithm OID ---")
        rsa_oid = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'
        pos = self.binary_data.find(rsa_oid)
        if pos != -1:
            print(f"✓ RSA encryption OID found at offset 0x{pos:08x}")
    
    def _find_valid_der_structures(self):
        """Find and validate DER/ASN.1 structures in binary"""
        valid_structures = []
        offset = 0
        
        while offset < len(self.binary_data) - 4:
            # Look for SEQUENCE tag (0x30)
            pos = self.binary_data.find(b'\x30', offset)
            if pos == -1 or pos >= len(self.binary_data) - 2:
                break
            
            # Parse length
            length_byte = self.binary_data[pos + 1]
            
            if length_byte < 0x80:
                # Short form: length is directly in this byte
                content_length = length_byte
                header_length = 2
            elif length_byte == 0x81:
                # Long form: 1 byte length
                if pos + 2 >= len(self.binary_data):
                    offset = pos + 1
                    continue
                content_length = self.binary_data[pos + 2]
                header_length = 3
            elif length_byte == 0x82:
                # Long form: 2 byte length
                if pos + 3 >= len(self.binary_data):
                    offset = pos + 1
                    continue
                content_length = struct.unpack('>H', self.binary_data[pos + 2:pos + 4])[0]
                header_length = 4
            elif length_byte == 0x83:
                # Long form: 3 byte length
                if pos + 4 >= len(self.binary_data):
                    offset = pos + 1
                    continue
                content_length = struct.unpack('>I', b'\x00' + self.binary_data[pos + 2:pos + 5])[0]
                header_length = 5
            else:
                offset = pos + 1
                continue
            
            total_length = header_length + content_length
            
            # Validate: reasonable length for crypto structures (64 bytes to 8KB)
            if 64 <= total_length <= 8192:
                # Additional validation: check if content has reasonable structure
                if pos + total_length <= len(self.binary_data):
                    # Check for nested ASN.1 structures (common in certs/keys)
                    inner_data = self.binary_data[pos + header_length:pos + header_length + min(10, content_length)]
                    
                    # Valid DER structures often start with nested SEQUENCE, INTEGER, or OID
                    if inner_data and inner_data[0] in [0x02, 0x03, 0x04, 0x05, 0x06, 0x30, 0x31, 0xA0, 0xA1]:
                        der_type = self._identify_der_type(content_length, inner_data)
                        valid_structures.append((pos, total_length, der_type))
            
            offset = pos + 1
        
        return valid_structures
    
    def _identify_der_type(self, length, inner_data):
        """Try to identify the type of DER structure"""
        if length > 1000:
            return "Certificate/Key"
        elif length > 256:
            return "PublicKey"
        elif length > 64:
            return "Signature/Data"
        else:
            return "Structure"
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data (0.0 to 1.0)"""
        if not data:
            return 0.0
        
        entropy = 0.0
        counter = Counter(data)
        length = len(data)
        
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        # Normalize to 0.0-1.0 (max entropy for bytes is log2(256) = 8)
        return entropy / 8.0
    
    def analyze_entropy(self):
        """Analyze entropy to find encrypted/compressed regions and keys"""
        print("\n[6] Entropy Analysis (High Entropy = Keys/Crypto)")
        print("=" * 60)
        
        chunk_size = 1024
        high_entropy_threshold = 0.95
        high_entropy_regions = []
        
        print("\nScanning for high-entropy regions (potential keys/encrypted data)...")
        
        for i in range(0, len(self.binary_data) - chunk_size, chunk_size):
            chunk = self.binary_data[i:i+chunk_size]
            entropy = self.calculate_entropy(chunk)
            
            if entropy >= high_entropy_threshold:
                high_entropy_regions.append((i, entropy))
        
        if high_entropy_regions:
            print(f"\n✓ Found {len(high_entropy_regions)} high-entropy regions:")
            for offset, entropy in high_entropy_regions[:10]:
                print(f"  Offset 0x{offset:08x}: entropy = {entropy:.4f}")
                # Check if this could be a key (256 bits = 32 bytes for SHA256/AES256)
                if offset + 32 <= len(self.binary_data):
                    potential_key = self.binary_data[offset:offset+32]
                    if self._looks_like_hash(potential_key):
                        print(f"    -> Potential 256-bit key: {potential_key.hex()[:64]}...")
            
            if len(high_entropy_regions) > 10:
                print(f"  ... and {len(high_entropy_regions) - 10} more regions")
        else:
            print("✗ No high-entropy regions found")
        
        return high_entropy_regions
    
    def find_hardware_anchor(self):
        """Search for OTP/eFuse hardware anchor references"""
        print("\n[7] Hardware Anchor Detection (OTP/eFuse)")
        print("=" * 60)
        
        # Common OTP/eFuse base addresses for popular SoCs
        known_otp_addresses = {
            '0x021BC000': 'NXP i.MX6 OCOTP',
            '0x021C0000': 'NXP i.MX7 OCOTP',
            '0x30350000': 'NXP i.MX8M OCOTP',
            '0x01C23800': 'Allwinner SID',
            '0x10206000': 'Rockchip OTP',
            '0x580C4000': 'STM32 OTP',
        }
        
        print("\n--- Known OTP/eFuse Addresses ---")
        findings = []
        
        for addr_str, desc in known_otp_addresses.items():
            # Search for address in various formats
            addr_int = int(addr_str, 16)
            
            # Little endian (most common)
            addr_bytes_le = struct.pack('<I', addr_int)
            # Big endian
            addr_bytes_be = struct.pack('>I', addr_int)
            
            pos_le = self.binary_data.find(addr_bytes_le)
            pos_be = self.binary_data.find(addr_bytes_be)
            
            if pos_le != -1:
                findings.append((addr_str, desc, pos_le, 'LE'))
                print(f"✓ {desc} address {addr_str} found at 0x{pos_le:08x} (little endian)")
            
            if pos_be != -1 and pos_be != pos_le:
                findings.append((addr_str, desc, pos_be, 'BE'))
                print(f"✓ {desc} address {addr_str} found at 0x{pos_be:08x} (big endian)")
            
            # Also search in strings
            for s in self.strings:
                if addr_str.lower() in s.lower():
                    print(f"  -> Found in string: {s[:80]}")
        
        if not findings:
            print("✗ No known OTP/eFuse addresses found")
            print("\nSearching for generic eFuse/OTP patterns...")
            
            # Look for high addresses (ROM regions typically > 0x20000000)
            addr_pattern = rb'[\x00-\xff]{1}[\x00-\x50][\x00-\xff]{2}'  # Simplified pattern
            otp_strings = [s for s in self.strings if any(kw in s.lower() for kw in 
                          ['otp', 'efuse', 'fuse', 'rom', 'bootrom'])]
            
            if otp_strings:
                print("\n✓ Generic OTP/ROM references:")
                for s in otp_strings[:15]:
                    print(f"  - {s}")
        
        return findings
    
    def detect_fit_image_format(self):
        """Detect U-Boot FIT (Flattened Image Tree) format"""
        print("\n[8] FIT Image Format Detection (U-Boot)")
        print("=" * 60)
        
        # FIT images use Device Tree format (DTB)
        fit_markers = [
            b'\xd0\x0d\xfe\xed',  # DTB magic (big endian)
            b'/signature',
            b'key-name-hint',
            b'algo',
            b'rsa2048',
            b'rsa4096',
            b'sha256,rsa',
        ]
        
        findings = []
        for marker in fit_markers:
            pos = self.binary_data.find(marker)
            if pos != -1:
                findings.append((marker, pos))
        
        if findings:
            print("✓ FIT Image format detected!")
            for marker, pos in findings:
                if marker == b'\xd0\x0d\xfe\xed':
                    print(f"  DTB Magic found at offset 0x{pos:08x}")
                    # Try to extract some context
                    context = self.binary_data[pos:pos+100]
                    print(f"    Context: {context[:50]}")
                else:
                    try:
                        print(f"  {marker.decode('ascii', errors='ignore')} at offset 0x{pos:08x}")
                    except:
                        print(f"  Pattern at offset 0x{pos:08x}")
        else:
            print("✗ No FIT image format detected")
        
        return bool(findings)
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "=" * 60)
        print("SECURE BOOT ANALYSIS REPORT")
        print("Chain of Trust: BootROM -> Bootloader -> OS/Kernel")
        print(f"File: {self.path.name}")
        print(f"Size: {len(self.binary_data)} bytes ({len(self.binary_data)/1024:.2f} KB)")
        print("=" * 60)
        
        has_secure_boot = self.check_secure_boot_logic()
        hash_algos, sig_algos = self.detect_crypto_algorithms()
        self.find_root_of_trust()
        self.find_secure_storage_refs()
        self.detect_crypto_constants()
        self.analyze_entropy()
        hw_anchors = self.find_hardware_anchor()
        has_fit = self.detect_fit_image_format()
        
        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY - CHAIN OF TRUST VERIFICATION")
        print("=" * 60)
        print(f"Secure Boot Logic Present: {'YES ✓' if has_secure_boot else 'NO ✗'}")
        print(f"Hash Algorithms Found: {', '.join(hash_algos.keys()) if hash_algos else 'None'}")
        print(f"Signature Algorithms Found: {', '.join(sig_algos.keys()) if sig_algos else 'None'}")
        print(f"Hardware Anchor Found: {'YES ✓' if hw_anchors else 'NO ✗'}")
        print(f"FIT Image Format: {'YES ✓' if has_fit else 'NO ✗'}")
        
        print("\n--- Chain of Trust Assessment ---")
        if has_secure_boot and (hash_algos or sig_algos):
            print("✓ Bootloader has verification logic")
        else:
            print("✗ Bootloader verification logic unclear")
        
        if hw_anchors:
            print("✓ Hardware root of trust references found")
        else:
            print("⚠ Hardware root of trust not clearly identified")
        
        if has_fit:
            print("✓ U-Boot FIT signed image format supported")
        
        print("=" * 60)
        
        # Store results for JSON output
        self.results = {
            'file': str(self.path.name),
            'size_bytes': len(self.binary_data),
            'secure_boot_logic': has_secure_boot,
            'hash_algorithms': list(hash_algos.keys()) if hash_algos else [],
            'signature_algorithms': list(sig_algos.keys()) if sig_algos else [],
            'hardware_anchor': bool(hw_anchors),
            'fit_image_format': has_fit,
            'chain_of_trust_verified': has_secure_boot and (bool(hash_algos) or bool(sig_algos))
        }


def main():
    parser = argparse.ArgumentParser(
        description='Analyze bootloader binaries for secure boot implementation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s bootloader.bin
  %(prog)s u-boot.bin
  %(prog)s firmware.img
        '''
    )
    parser.add_argument('bootloader', help='Path to bootloader binary file')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output with more details')
    parser.add_argument('--output', '-o', help='Save report to file')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Output results in JSON format')
    
    args = parser.parse_args()
    
    try:
        # Redirect output if requested
        original_stdout = sys.stdout
        
        if args.json:
            # Suppress normal output for JSON mode
            sys.stdout = open('/dev/null', 'w') if sys.platform != 'win32' else open('nul', 'w')
        elif args.output:
            sys.stdout = open(args.output, 'w')
        
        analyzer = SecureBootAnalyzer(args.bootloader, json_output=args.json)
        analyzer.generate_report()
        
        if args.json:
            sys.stdout.close()
            sys.stdout = original_stdout
            # Output JSON to stdout or file
            json_output = json.dumps(analyzer.results, indent=2)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(json_output)
                print(f"JSON report saved to: {args.output}", file=sys.stderr)
            else:
                print(json_output)
        elif args.output:
            sys.stdout.close()
            sys.stdout = original_stdout
            print(f"Report saved to: {args.output}")
    
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
