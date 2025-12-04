import os
import re
import struct
import math
import json
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

class BinaryAnalyzer:
    """
    Binary Analysis Module for Firmware Scanning Pipeline.
    Performs static analysis on ELF binaries to detect crypto, secrets, and unsafe functions.
    """

    def __init__(self):
        # AES Forward S-Box (first 16 bytes)
        self.AES_SBOX_SIG = bytes([
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
        ])
        
        # SHA-256 K-Constants (Big Endian)
        self.SHA256_K_SIG_BE = struct.pack('>IIII', 
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
        )
        # SHA-256 K-Constants (Little Endian)
        self.SHA256_K_SIG_LE = struct.pack('<IIII', 
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
        )

        # SHA-1 K-Constants (Big Endian)
        self.SHA1_K_SIG_BE = struct.pack('>IIII',
            0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
        )
        # SHA-1 K-Constants (Little Endian)
        self.SHA1_K_SIG_LE = struct.pack('<IIII',
            0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
        )
        
        # SHA-1 Initial Hash (Big Endian)
        self.SHA1_H_SIG_BE = struct.pack('>IIIII',
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        )
        # SHA-1 Initial Hash (Little Endian)
        self.SHA1_H_SIG_LE = struct.pack('<IIIII',
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        )

        self.UNSAFE_FUNCTIONS = {
            'rand', 'srand', 'strcpy', 'strcat', 'gets', 'system', 'popen'
        }

        self.SUSPICIOUS_STRINGS = [
            r'-----BEGIN .* PRIVATE KEY-----',
            r'AWS', r'AKIA', r'Bearer',
            r'password', r'admin', r'secret'
        ]

    def analyze(self, file_path):
        """
        Main entry point for analyzing a binary file or a list of files.
        
        Args:
            file_path (str or list): Path to the binary file or list of paths.
            
        Returns:
            dict or list: Structured security findings (single dict or list of dicts).
        """
        if isinstance(file_path, list):
            return [self._analyze_single(f) for f in file_path]
        return self._analyze_single(file_path)

    def _analyze_single(self, file_path):
        """
        Internal method to analyze a single file.
        """
        results = {
            "file_path": file_path,
            "is_elf": False,
            "arch": "Unknown",
            "crypto_findings": {
                "dynamic_libraries": [],
                "static_signatures": []
            },
            "security_risks": {
                "hardcoded_secrets": [],
                "high_entropy_blocks": [],
                "unsafe_functions": []
            }
        }

        if not os.path.exists(file_path):
            return results

        try:
            with open(file_path, 'rb') as f:
                # Check A: File Type Validation
                if not self._validate_elf(f):
                    return results
                
                results["is_elf"] = True
                
                # Reset pointer for pyelftools
                f.seek(0)
                elf = ELFFile(f)
                results["arch"] = self._get_arch(elf)

                # Check B: Cryptographic Implementation
                results["crypto_findings"]["dynamic_libraries"] = self._check_crypto_dynamic(elf)
                
                # Read full content for signature scanning
                f.seek(0)
                content = f.read()
                results["crypto_findings"]["static_signatures"] = self._check_crypto_static(content)

                # Check C: Hardcoded Secrets & Credentials
                # We need section data for entropy, but full content for string scan is okay too.
                # For entropy, we specifically look at .rodata if it exists.
                rodata_content = b""
                try:
                    rodata_section = elf.get_section_by_name('.rodata')
                    if rodata_section:
                        rodata_content = rodata_section.data()
                except Exception:
                    pass # Section might not exist or error reading
                
                results["security_risks"]["hardcoded_secrets"] = self._check_secrets_strings(content)
                results["security_risks"]["high_entropy_blocks"] = self._check_entropy(rodata_content)

                # Check D: Insecure Function Imports
                results["security_risks"]["unsafe_functions"] = self._check_unsafe_imports(elf)

        except Exception as e:
            # Log error but don't crash
            # print(f"Error analyzing {file_path}: {e}")
            pass

        return results

    def _validate_elf(self, file_handle):
        """Checks for ELF Magic bytes."""
        try:
            magic = file_handle.read(4)
            return magic == b'\x7fELF'
        except Exception:
            return False

    def _get_arch(self, elf):
        """Extracts architecture from ELF header."""
        try:
            machine = elf.header['e_machine']
            # If it's an int (unknown to pyelftools map), return it as string
            if isinstance(machine, int):
                return f"Unknown (ID: {machine})"
            return machine
        except Exception:
            return "Unknown"

    def _check_crypto_dynamic(self, elf):
        """Checks for crypto libraries in dynamic section."""
        libs = []
        try:
            for section in elf.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            lib_name = tag.needed
                            if any(x in lib_name for x in ['libssl', 'libcrypto', 'mbedtls', 'libsodium']):
                                libs.append(lib_name)
        except Exception:
            pass
        return libs

    def _check_crypto_static(self, content):
        """Scans for static crypto signatures."""
        findings = []
        
        # AES S-Box
        for match in re.finditer(re.escape(self.AES_SBOX_SIG), content):
            findings.append({
                "algorithm": "AES-256 (S-Box)",
                "offset": hex(match.start()),
                "confidence": "High"
            })

        # SHA-256 K-Constants
        for sig, label in [(self.SHA256_K_SIG_BE, "SHA-256 (K-Constants BE)"), (self.SHA256_K_SIG_LE, "SHA-256 (K-Constants LE)")]:
            for match in re.finditer(re.escape(sig), content):
                findings.append({
                    "algorithm": label,
                    "offset": hex(match.start()),
                    "confidence": "High"
                })

        # SHA-1 K-Constants
        for sig, label in [(self.SHA1_K_SIG_BE, "SHA-1 (K-Constants BE)"), (self.SHA1_K_SIG_LE, "SHA-1 (K-Constants LE)")]:
            for match in re.finditer(re.escape(sig), content):
                findings.append({
                    "algorithm": label,
                    "offset": hex(match.start()),
                    "confidence": "High"
                })

        # SHA-1 Initial Hash
        for sig, label in [(self.SHA1_H_SIG_BE, "SHA-1 (Initial Hash BE)"), (self.SHA1_H_SIG_LE, "SHA-1 (Initial Hash LE)")]:
            for match in re.finditer(re.escape(sig), content):
                findings.append({
                    "algorithm": label,
                    "offset": hex(match.start()),
                    "confidence": "High"
                })
            
        return findings

    def _check_secrets_strings(self, content):
        """Scans for suspicious strings."""
        findings = []
        try:
            # Decode with error replacement to handle binary data
            text = content.decode('utf-8', errors='replace')
            
            # Find strings >= 8 chars
            # This is a simple approximation of 'strings' command
            # We filter for our patterns within these
            
            for pattern in self.SUSPICIOUS_STRINGS:
                # We look for the pattern in the whole text. 
                # To be more like 'strings', we might want to extract strings first,
                # but regex on the whole binary decoded as text (with replacement) 
                # is a reasonable approximation for Python.
                
                # However, decoding the whole binary can be messy. 
                # Better: Find ASCII sequences first.
                ascii_strings = re.findall(r'[ -~]{8,}', text)
                
                for s in ascii_strings:
                    if re.search(pattern, s, re.IGNORECASE):
                        findings.append(s[:50]) # Truncate for report
                        
        except Exception:
            pass
            
        return list(set(findings)) # Deduplicate

    def _check_entropy(self, data):
        """Calculates entropy for blocks in data."""
        findings = []
        if not data:
            return findings

        block_size = 256 # Analyze in chunks
        threshold = 7.5
        
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            if len(chunk) < 32: continue
            
            entropy = self._calculate_shannon_entropy(chunk)
            if entropy > threshold:
                findings.append({
                    "offset": hex(i), # Relative to section start
                    "score": round(entropy, 2)
                })
        return findings

    def _calculate_shannon_entropy(self, data):
        """Helper to calculate Shannon Entropy."""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def _check_unsafe_imports(self, elf):
        """Checks for unsafe function imports."""
        unsafe = []
        # Symbol tables
        symbol_tables = [s for s in elf.iter_sections() if s['sh_type'] == 'SHT_DYNSYM']
        
        for section in symbol_tables:
            for symbol in section.iter_symbols():
                if symbol.name in self.UNSAFE_FUNCTIONS:
                    unsafe.append(symbol.name)
        
        return list(set(unsafe))

if __name__ == "__main__":
    # Demonstration
    analyzer = BinaryAnalyzer()
    
    # Use a dummy path or a real one if known
    # Looking at file list, 'test_dynamic_arm.elf' exists
    test_file = "/home/kamini08/projects/cfg-extractor/test_dynamic_arm.elf"
    
    print(f"Analyzing single file: {test_file}...")
    result = analyzer.analyze(test_file)
    print(json.dumps(result, indent=2))

    print("\nAnalyzing list of files...")
    # Passing the same file twice to test list handling
    results = analyzer.analyze([test_file, test_file])
    print(f"Analyzed {len(results)} files.")
    print(json.dumps(results[0], indent=2))
