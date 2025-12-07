#!/usr/bin/env python3
"""
Crypto Function Detector v4.0 - Advanced Classification System
Detects and classifies crypto functions via:
0. YARA static analysis (< 1 second, works on stripped binaries)
1. Constant scanning (FindCrypt-style)
2. Syscall monitoring (getrandom, key sizes, entropy requests)
3. Basic block profiling (10-100x faster than instruction hooks)
4. Loop detection (identifies round functions)
5. Algorithm classification (standard vs proprietary)
6. Pattern detection (XOR-based, PRNG-based, custom ciphers)
"""

import os
import sys
import subprocess
import shutil
import tempfile
import re
import math
import time
from collections import defaultdict
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT

# Import our new modules
from constant_scanner import scan_for_constants, print_scan_results
from crypto_logger import CryptoLogger
from yara_scanner import YaraCryptoScanner
from unpacker import BinaryUnpacker

# Configuration
BINARY_PATH = sys.argv[1] if len(sys.argv) > 1 else ""
UNPACKED_BINARY_PATH = None  # Will be set if binary is unpacked

# Global logger instance
logger = None

# Profiling stats (now for basic blocks)
stats_total_blocks = 0
stats_crypto_heavy_blocks = 0
basic_blocks = {}  # Track block execution for loop detection

# Syscall monitoring (NEW)
syscall_events = {
    'getrandom_calls': [],
    'random_reads': [],
    'memory_operations': [],
}

# Algorithm classification data
algo_evidence = {
    'standard_algorithms': {},  # AES, ChaCha20, RSA, etc.
    'proprietary_indicators': [],  # Custom/XOR-based/PRNG patterns
    'ruled_out': [],  # Algorithms we can eliminate
}

# Strace logging
strace_log_path = None

def run_with_strace(binary_path, rootfs_path, timeout=10):
    """
    Run binary natively with strace to capture system calls.
    Returns: (strace_log_path, success)
    """
    global strace_log_path
    
    # Check if strace is available
    try:
        subprocess.run(["which", "strace"], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        print("[!] strace not installed - skipping native syscall trace")
        print("    Install: sudo apt install strace (Debian/Ubuntu)")
        print("             sudo yum install strace (RHEL/CentOS)")
        return None, False
    
    # Create logs directory
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "strace_logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Generate timestamped log filename
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    binary_name = os.path.basename(binary_path).replace('.', '_')
    strace_log = os.path.join(log_dir, f"strace_{binary_name}_{timestamp}.log")
    
    print(f"[*] Running native strace on binary...")
    print(f"    Log: {strace_log}")
    
    # Run strace with comprehensive syscall tracking
    # -f: follow forks
    # -e trace=all: trace all syscalls
    # -s 256: capture up to 256 bytes of string arguments
    # -v: verbose mode (no abbreviations)
    # -tt: timestamps with microseconds
    # -o: output file
    strace_cmd = [
        "strace",
        "-f",              # Follow child processes
        "-e", "trace=all", # Trace all syscalls
        "-s", "256",       # String length
        "-v",              # Verbose
        "-tt",             # Timestamps
        "-o", strace_log,  # Output file
        binary_path
    ]
    
    try:
        # Run with timeout
        result = subprocess.run(
            strace_cmd,
            timeout=timeout,
            capture_output=True,
            text=True
        )
        
        # Check if log was created and has content
        if os.path.exists(strace_log) and os.path.getsize(strace_log) > 0:
            print(f"[✓] strace log captured: {os.path.getsize(strace_log)} bytes")
            strace_log_path = strace_log
            return strace_log, True
        else:
            print(f"[-] strace log empty or not created")
            return None, False
            
    except subprocess.TimeoutExpired:
        print(f"[*] strace timed out after {timeout}s (normal for servers)")
        # Log might still be useful even if timed out
        if os.path.exists(strace_log) and os.path.getsize(strace_log) > 0:
            print(f"[✓] Partial strace log captured: {os.path.getsize(strace_log)} bytes")
            strace_log_path = strace_log
            return strace_log, True
        return None, False
        
    except Exception as e:
        print(f"[!] strace failed: {e}")
        return None, False

def analyze_strace_log(strace_log_path):
    """
    Parse strace log and extract crypto-relevant syscalls.
    Returns: dict with syscall statistics
    """
    if not strace_log_path or not os.path.exists(strace_log_path):
        return None
    
    stats = {
        'getrandom_calls': [],
        'read_random': [],
        'open_files': [],
        'crypto_relevant': [],
        'total_syscalls': 0
    }
    
    crypto_files = ['/dev/random', '/dev/urandom', 'key', 'cert', 'crypt']
    
    try:
        with open(strace_log_path, 'r') as f:
            for line in f:
                stats['total_syscalls'] += 1
                
                # Extract getrandom calls
                if 'getrandom(' in line:
                    # Parse: getrandom(0x7ffd..., 8, GRND_NONBLOCK) = 8
                    match = re.search(r'getrandom\([^,]+,\s*(\d+),', line)
                    if match:
                        size = int(match.group(1))
                        stats['getrandom_calls'].append({'size': size, 'line': line.strip()})
                
                # Extract read from random devices
                elif 'read(' in line and any(dev in line for dev in ['/dev/random', '/dev/urandom']):
                    stats['read_random'].append(line.strip())
                
                # Extract file opens related to crypto
                elif 'open(' in line or 'openat(' in line:
                    if any(keyword in line.lower() for keyword in crypto_files):
                        stats['open_files'].append(line.strip())
                        stats['crypto_relevant'].append(line.strip())
                
                # Other crypto-relevant syscalls
                elif any(call in line for call in ['mmap(', 'mprotect(', 'madvise(']):
                    if 'PROT_EXEC' in line or 'PROT_WRITE' in line:
                        # Might indicate JIT or dynamic code generation
                        stats['crypto_relevant'].append(line.strip())
        
        return stats
        
    except Exception as e:
        print(f"[!] Failed to parse strace log: {e}")
        return None

def get_entropy(data):
    """Calculate Shannon entropy (Max 4.0 for byte-level entropy of 16 bytes)."""
    if not data: return 0
    entropy = 0
    length = len(data)
    for x in range(256):
        count = data.count(x)
        if count > 0:
            p_x = count / length
            entropy += - p_x * math.log2(p_x)
    return entropy

def classify_by_key_size(size_bytes):
    """
    Classify algorithm based on key/nonce/IV size.
    Returns: (likely_algorithms, ruled_out_algorithms)
    """
    likely = []
    ruled_out = []
    
    if size_bytes == 8:  # 64 bits - Too small for modern crypto
        likely.extend([
            "XOR-based cipher (8-byte key)",
            "PRNG-based stream cipher (8-byte seed)",
            "Custom/proprietary cipher",
            "Toy Feistel network",
            "Simple obfuscation cipher"
        ])
        ruled_out.extend([
            "AES (needs 16/24/32-byte key)",
            "ChaCha20 (needs 32-byte key + 12-byte nonce)",
            "RSA/ECC (needs much larger keys)",
            "DES/3DES (needs proper key schedule, not just 8 bytes)"
        ])
    elif size_bytes == 16:  # 128 bits
        likely.extend([
            "AES-128",
            "ChaCha20 (partial - needs 32-byte key)",
            "MD5 output (not encryption)",
        ])
    elif size_bytes == 24:  # 192 bits
        likely.append("AES-192")
    elif size_bytes == 32:  # 256 bits
        likely.extend([
            "AES-256",
            "ChaCha20 (with additional 12-byte nonce needed)",
            "SHA-256 output (not encryption)"
        ])
    elif size_bytes < 8:
        likely.extend([
            "Extremely weak custom cipher",
            "Simple XOR obfuscation"
        ])
        ruled_out.extend([
            "All standard algorithms (key too small)"
        ])
    else:
        likely.append("Unknown/Custom algorithm")
    
    return likely, ruled_out

def detect_cipher_patterns(ql, input_data, output_data):
    """
    Analyze input/output patterns to detect cipher type.
    Returns: list of detected patterns
    """
    patterns = []
    
    if len(input_data) != len(output_data):
        patterns.append("LENGTH_MISMATCH")
        return patterns
    
    if len(input_data) == len(output_data):
        patterns.append("SAME_LENGTH (stream cipher or XOR)")
    
    # Check for simple XOR pattern
    xor_result = bytes([a ^ b for a, b in zip(input_data[:16], output_data[:16])])
    xor_entropy = get_entropy(xor_result)
    
    if xor_entropy < 1.5:  # Low entropy in XOR = repeating key
        patterns.append("REPEATING_XOR_KEY (detected)")
    
    # Check for block alignment
    if len(input_data) % 16 == 0 and len(output_data) % 16 == 0:
        patterns.append("16_BYTE_BLOCKS (AES-like)")
    elif len(input_data) % 8 == 0 and len(output_data) % 8 == 0:
        patterns.append("8_BYTE_BLOCKS (DES-like or custom)")
    else:
        patterns.append("NO_BLOCK_ALIGNMENT (stream cipher)")
    
    # Check output entropy
    out_entropy = get_entropy(output_data[:32])
    if out_entropy > 3.5:
        patterns.append("HIGH_ENTROPY_OUTPUT (good diffusion)")
    elif out_entropy < 2.5:
        patterns.append("LOW_ENTROPY_OUTPUT (weak cipher)")
    
    return patterns

def hook_syscalls(ql):
    """
    Hook syscalls to monitor crypto-related operations.
    Tracks: getrandom, read from /dev/random, memory operations
    """
    global syscall_events
    
    def syscall_getrandom(ql, buf, buflen, flags):
        """Monitor getrandom() calls - critical for detecting key/nonce generation"""
        try:
            # Read the random data that will be generated
            random_data = os.urandom(buflen)
            ql.mem.write(buf, random_data)
            
            syscall_events['getrandom_calls'].append({
                'size': buflen,
                'data': random_data[:32],  # Store first 32 bytes
                'flags': flags,
                'entropy': get_entropy(random_data[:min(32, buflen)])
            })
            
            print(f"[SYSCALL] getrandom() called: {buflen} bytes (0x{buflen:x})")
            print(f"          Data: {random_data[:min(16, buflen)].hex()}")
            
            # Classify based on size
            likely, ruled_out = classify_by_key_size(buflen)
            if likely:
                print(f"          Likely: {likely[0]}")
            if ruled_out:
                algo_evidence['ruled_out'].extend(ruled_out)
            
            return buflen
        except Exception as e:
            print(f"[!] getrandom hook error: {e}")
            return -1
    
    def syscall_read(ql, fd, buf, count):
        """Monitor reads from /dev/random or /dev/urandom"""
        try:
            # Check if reading from random device
            if fd in [ql.os.fd.get('/dev/random'), ql.os.fd.get('/dev/urandom')]:
                random_data = os.urandom(count)
                ql.mem.write(buf, random_data)
                
                syscall_events['random_reads'].append({
                    'size': count,
                    'data': random_data[:32],
                    'source': '/dev/random' if fd == ql.os.fd.get('/dev/random') else '/dev/urandom'
                })
                
                print(f"[SYSCALL] read() from random device: {count} bytes")
                return count
        except:
            pass
        
        # Default behavior
        return ql.os.syscall_read_orig(ql, fd, buf, count)
    
    # Hook the syscalls
    try:
        ql.os.set_syscall("getrandom", syscall_getrandom)
        # Save original read for fallback
        ql.os.syscall_read_orig = ql.os.syscall_table.get("read", lambda *args: -1)
        ql.os.set_syscall("read", syscall_read)
    except Exception as e:
        print(f"[!] Warning: Could not hook syscalls: {e}")

def is_crypto_op(mnemonic):
    """Check if instruction mnemonic is a crypto operation."""
    crypto_ops = [
        'xor', 'eor', 'pxor', 'vpxor',           # XOR operations
        'rol', 'ror', 'rrx', 'rotr',             # Rotates
        'shl', 'shr', 'sal', 'sar',              # Shifts (x86)
        'lsl', 'lsr', 'asr',                     # Shifts (ARM)
        'sll', 'srl', 'sra',                     # Shifts (MIPS/RISC-V)
        'add', 'sub', 'adc', 'sbc', 'rsb',       # Arithmetic (key expansion)
        'and', 'or', 'orr', 'orn', 'bic',        # Logical/Masking
        'not', 'neg', 'mvn',                     # Negation
        'aes', 'sha',                            # Hardware crypto
    ]
    return any(mnemonic.startswith(op) for op in crypto_ops)

def analyze_algorithm_evidence(constant_results, syscall_events, basic_blocks, io_captures):
    """
    Comprehensive analysis to classify the crypto algorithm.
    Returns: classification report with confidence scores
    """
    report = {
        'standard_algorithms': {},
        'proprietary_likely': False,
        'proprietary_patterns': [],
        'ruled_out': set(),
        'confidence': 'UNKNOWN',
        'primary_classification': 'UNKNOWN'
    }
    
    # 1. Analyze syscall evidence (CRITICAL)
    if syscall_events['getrandom_calls']:
        for call in syscall_events['getrandom_calls']:
            size = call['size']
            likely, ruled_out = classify_by_key_size(size)
            
            if size <= 8:
                report['proprietary_likely'] = True
                report['proprietary_patterns'].append(
                    f"Small random key/nonce ({size} bytes) - too small for standard crypto"
                )
                report['ruled_out'].update(ruled_out)
            elif size in [16, 24, 32]:
                # Could be standard algorithm
                for algo in likely:
                    if algo not in report['standard_algorithms']:
                        report['standard_algorithms'][algo] = {'evidence': [], 'score': 0}
                    report['standard_algorithms'][algo]['evidence'].append(f"Key size: {size} bytes")
                    report['standard_algorithms'][algo]['score'] += 30
    
    # 2. Analyze constant detection
    if constant_results:
        for algo, constants in constant_results.items():
            if algo not in report['standard_algorithms']:
                report['standard_algorithms'][algo] = {'evidence': [], 'score': 0}
            report['standard_algorithms'][algo]['evidence'].append(
                f"Known constants detected ({len(constants)} matches)"
            )
            report['standard_algorithms'][algo]['score'] += 40
            
            # Rule out other algorithms
            if algo == 'AES':
                report['ruled_out'].update(['ChaCha20', 'DES', 'RSA'])
            elif algo == 'ChaCha20':
                report['ruled_out'].update(['AES', 'DES'])
    else:
        # No constants found = likely proprietary
        report['proprietary_patterns'].append("No known crypto constants detected")
        report['proprietary_likely'] = True
    
    # 3. Analyze I/O patterns
    if io_captures:
        for func_name, captures in io_captures.items():
            for capture in captures:
                patterns = detect_cipher_patterns(None, capture['input'], capture['output'])
                
                if 'SAME_LENGTH' in patterns:
                    report['proprietary_patterns'].append("Output length == input length (stream cipher pattern)")
                    report['ruled_out'].update(['RSA', 'ECC'])  # Asymmetric changes length
                
                if 'REPEATING_XOR_KEY' in patterns:
                    report['proprietary_likely'] = True
                    report['proprietary_patterns'].append("XOR-based cipher detected")
                    report['ruled_out'].update(['AES', 'ChaCha20', 'RSA', 'DES'])
                
                if 'NO_BLOCK_ALIGNMENT' in patterns:
                    report['ruled_out'].update(['AES', 'DES', '3DES'])
    
    # 4. Analyze execution patterns
    crypto_loops = [b for b in basic_blocks.values() 
                    if b.get('is_loop') and b.get('total_ops', 0) > 0 
                    and (b.get('crypto_ops', 0) / b['total_ops']) > 0.3]
    
    if len(crypto_loops) >= 10:
        # Many rounds = likely AES/DES
        if 'AES' in report['standard_algorithms']:
            report['standard_algorithms']['AES']['score'] += 20
    elif len(crypto_loops) <= 3:
        # Few rounds = likely simple cipher
        report['proprietary_patterns'].append("Few crypto loops (simple cipher)")
        report['proprietary_likely'] = True
    
    # 5. Final classification
    if report['standard_algorithms']:
        # Find highest scoring standard algorithm
        best_algo = max(report['standard_algorithms'].items(), 
                       key=lambda x: x[1]['score'])
        
        if best_algo[1]['score'] >= 70:
            report['primary_classification'] = f"STANDARD: {best_algo[0]}"
            report['confidence'] = 'HIGH'
        elif best_algo[1]['score'] >= 40:
            report['primary_classification'] = f"LIKELY STANDARD: {best_algo[0]}"
            report['confidence'] = 'MEDIUM'
        else:
            report['primary_classification'] = "PROPRIETARY/CUSTOM"
            report['confidence'] = 'MEDIUM'
    
    if report['proprietary_likely'] or not report['standard_algorithms']:
        # Determine proprietary type
        if any('XOR' in p for p in report['proprietary_patterns']):
            report['primary_classification'] = "PROPRIETARY: XOR-based cipher"
        elif any('Small random' in p for p in report['proprietary_patterns']):
            report['primary_classification'] = "PROPRIETARY: Lightweight/Custom cipher"
        else:
            report['primary_classification'] = "PROPRIETARY: Unknown custom algorithm"
        
        if len(report['proprietary_patterns']) >= 3:
            report['confidence'] = 'HIGH'
        elif len(report['proprietary_patterns']) >= 1:
            report['confidence'] = 'MEDIUM'
        else:
            report['confidence'] = 'LOW'
    
    return report

def print_classification_report(report, syscall_events=None):
    """Print a detailed classification report"""
    print("\n" + "="*70)
    print("   ALGORITHM CLASSIFICATION REPORT")
    print("="*70)
    
    print(f"\n[*] PRIMARY CLASSIFICATION: {report['primary_classification']}")
    print(f"    Confidence: {report['confidence']}")
    
    # Standard algorithms detected
    if report['standard_algorithms']:
        print("\n[*] Standard Algorithms Detected:")
        for algo, data in sorted(report['standard_algorithms'].items(), 
                                key=lambda x: x[1]['score'], reverse=True):
            print(f"\n    {algo} (Score: {data['score']}/100)")
            for evidence in data['evidence']:
                print(f"      ✓ {evidence}")
    
    # Proprietary indicators
    if report['proprietary_patterns']:
        print("\n[*] Proprietary/Custom Cipher Indicators:")
        for pattern in report['proprietary_patterns']:
            print(f"      ⚠ {pattern}")
    
    # Ruled out algorithms
    if report['ruled_out']:
        print("\n[*] Algorithms RULED OUT:")
        for algo in sorted(report['ruled_out']):
            print(f"      ❌ {algo}")
    
    # Dynamic Analysis Summary based on actual findings
    print("\n[*] Analysis Summary:")
    
    if 'STANDARD' in report['primary_classification']:
        # Extract the algorithm name
        algo_name = report['primary_classification'].split(': ')[-1] if ': ' in report['primary_classification'] else "Unknown"
        print(f"      → Binary uses STANDARD cryptography: {algo_name}")
        print(f"      → Well-documented algorithm with extensive cryptanalysis")
        
        # Show key size if detected from syscalls
        if syscall_events and syscall_events.get('getrandom_calls'):
            key_size = syscall_events['getrandom_calls'][0]['size'] * 8  # Convert to bits
            print(f"      → Key size: {key_size} bits")
        
        # Warn about implementation
        print(f"      → Security depends on proper implementation (padding, IV, etc.)")
        
        # Show specific recommendations for the algorithm
        if 'AES' in report['primary_classification']:
            print(f"      → Recommendation: Use AES-256-GCM for best security")
        elif 'ChaCha20' in report['primary_classification']:
            print(f"      → Recommendation: Use ChaCha20-Poly1305 for authenticated encryption")
    
    elif 'PROPRIETARY' in report['primary_classification']:
        print(f"      → Binary uses CUSTOM/PROPRIETARY cipher")
        
        # Show specific weaknesses detected
        if report['proprietary_patterns']:
            print(f"      → Detected {len(report['proprietary_patterns'])} weakness indicator(s):")
            for pattern in report['proprietary_patterns'][:3]:  # Show top 3
                print(f"         • {pattern}")
        
        # Specific warnings based on cipher type
        if 'XOR' in report['primary_classification']:
            print(f"      → ⚠ CRITICAL: XOR-based ciphers are trivially broken")
            print(f"      → Vulnerable to: Known-plaintext attacks, frequency analysis")
            print(f"      → Estimated strength: VERY WEAK (< 40 bits effective)")
        elif 'Lightweight' in report['primary_classification'] or 'Custom' in report['primary_classification']:
            print(f"      → ⚠ WARNING: Custom crypto is unvetted and likely weak")
            print(f"      → No peer review or cryptanalysis available")
            
            # Show key size weakness if detected
            if syscall_events and syscall_events.get('getrandom_calls'):
                key_size = syscall_events['getrandom_calls'][0]['size'] * 8
                if key_size <= 64:
                    print(f"      → Key size too small: {key_size} bits (need ≥128 bits)")
        
        # Actionable recommendations
        print(f"      → ⚠ URGENT: Replace with standard algorithms")
        print(f"      → Recommended alternatives:")
        print(f"         • AES-256-GCM (block cipher, hardware accelerated)")
        print(f"         • ChaCha20-Poly1305 (stream cipher, software optimized)")
    
    else:
        # Unknown classification
        print(f"      → Classification: {report['primary_classification']}")
        print(f"      → Unable to determine algorithm type conclusively")
        print(f"      → Recommendation: Manual code review required")
    
    print("="*70)

def profile_basic_block(ql, address, size):
    """
    Hook basic blocks (not individual instructions) for performance.
    Tracks execution counts to detect loops (crypto round functions).
    10-100x faster than instruction hooks!
    
    IMPORTANT: Only profile code in the main binary, not in libraries.
    """
    global stats_total_blocks, stats_crypto_heavy_blocks, basic_blocks, logger
    
    # Filter out library code (libc, ld-linux, etc.)
    # Only analyze the main binary to avoid false positives
    try:
        image = ql.loader.find_containing_image(address)
        if image and image.path:
            # Skip if this is library code
            if any(lib in image.path.lower() for lib in ['libc', 'ld-linux', 'libm', 'libpthread']):
                return
    except:
        pass
    
    stats_total_blocks += 1
    
    # Track this block
    if address not in basic_blocks:
        basic_blocks[address] = {
            'exec_count': 0,
            'crypto_ops': 0,
            'total_ops': 0,
            'is_loop': False,
            'size': size,
        }
    
    block_info = basic_blocks[address]
    block_info['exec_count'] += 1
    
    # Detect loops (block executed multiple times)
    if block_info['exec_count'] >= 3:
        block_info['is_loop'] = True
    
    # Profile entire basic block at once (only on first execution)
    if block_info['exec_count'] == 1:
        try:
            insn_bytes = ql.mem.read(address, size)
            for insn in ql.arch.disassembler.disasm(insn_bytes, address):
                block_info['total_ops'] += 1
                mnemonic = insn.mnemonic.lower()
                if is_crypto_op(mnemonic):
                    block_info['crypto_ops'] += 1
                    
                # Log instruction to logger
                if logger:
                    operands = insn.op_str if hasattr(insn, 'op_str') else ""
                    logger.log_instruction(insn.address, mnemonic, operands, True)
        except:
            pass
        
        # Mark as crypto-heavy if > 30% crypto ops
        if block_info['total_ops'] > 0:
            ratio = block_info['crypto_ops'] / block_info['total_ops']
            if ratio > 0.3:
                stats_crypto_heavy_blocks += 1
    
    # Log basic block to logger
    if logger:
        logger.log_basic_block(
            address, 
            size, 
            block_info['exec_count'],
            block_info['crypto_ops'],
            block_info['total_ops'],
            block_info['is_loop']
        )

def detect_architecture(binary_path):
    """Automatically detect architecture from ELF header."""
    import struct
    
    try:
        with open(binary_path, 'rb') as f:
            # Read ELF header
            elf_magic = f.read(4)
            if elf_magic != b'\x7fELF':
                return None  # Not an ELF file
            
            # Read EI_CLASS (32/64 bit)
            ei_class = f.read(1)[0]
            is_64bit = (ei_class == 2)
            
            # Read EI_DATA (endianness)
            ei_data = f.read(1)[0]
            is_little_endian = (ei_data == 1)
            
            # Skip to e_machine field (offset 0x12)
            f.seek(0x12)
            e_machine_bytes = f.read(2)
            
            # Unpack e_machine based on endianness
            endian = '<' if is_little_endian else '>'
            e_machine = struct.unpack(f'{endian}H', e_machine_bytes)[0]
            
            # Map e_machine to architecture
            # Reference: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
            arch_map = {
                0x03: 'x86',       # EM_386
                0x3E: 'x86_64',    # EM_X86_64
                0x28: 'arm',       # EM_ARM
                0xB7: 'arm64',     # EM_AARCH64
                0x08: 'mips',      # EM_MIPS
                0xF3: 'riscv',     # EM_RISCV
                0x14: 'powerpc',   # EM_PPC
                0x15: 'powerpc64', # EM_PPC64
            }
            
            arch = arch_map.get(e_machine)
            
            # Refine based on bitness
            if arch == 'mips' and is_64bit:
                arch = 'mips64'
            elif arch == 'riscv':
                arch = 'riscv64' if is_64bit else 'riscv32'
            
            return arch
            
    except Exception as e:
        print(f"[-] Failed to detect architecture: {e}")
        return None

def check_glibc_requirements(binary_path):
    """Check GLIBC version requirements of the binary."""
    try:
        result = subprocess.run(["objdump", "-T", binary_path], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            # Try readelf as fallback
            result = subprocess.run(["readelf", "-V", binary_path],
                                  capture_output=True, text=True, timeout=5)
        
        output = result.stdout
        glibc_versions = []
        
        # Look for GLIBC version requirements
        import re
        for match in re.finditer(r'GLIBC_(\d+\.\d+)', output):
            version = match.group(1)
            if version not in glibc_versions:
                glibc_versions.append(version)
        
        if glibc_versions:
            glibc_versions.sort(key=lambda v: tuple(map(int, v.split('.'))))
            return glibc_versions
        return []
    except Exception as e:
        return []

def get_rootfs(binary_path):
    """Determine rootfs based on automatically detected architecture."""
    arch = detect_architecture(binary_path)
    
    if not arch:
        print("[-] Could not detect architecture from binary")
        return None
    
    print(f"[+] Detected architecture: {arch}")
    
    # Map architecture to rootfs path (relative to qiling_analysis directory)
    # Get the directory where this script is located (qiling_analysis/tests)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level to qiling_analysis, then into rootfs
    rootfs_base = os.path.join(os.path.dirname(script_dir), "rootfs")
    
    rootfs_map = {
        'arm64': "arm64_linux",
        'arm': "arm_linux",
        'x86_64': "x8664_linux",
        'x86': "x86_linux",
        'mips': "mips32_linux",
        'mips64': "mips32_linux",  # Fallback
        'riscv64': "riscv64_linux",
        'riscv32': "riscv32_linux",
        'powerpc': "powerpc_linux",
    }
    
    rootfs_dir = rootfs_map.get(arch)
    rootfs = os.path.join(rootfs_base, rootfs_dir) if rootfs_dir else None
    
    if not rootfs:
        print(f"[-] No rootfs mapping found for architecture: {arch}")
        return None
    
    # Verify rootfs exists
    if not os.path.exists(rootfs):
        print(f"[-] Rootfs path does not exist: {rootfs}")
        return None
    
    return rootfs

def get_all_functions(binary_path):
    """Get all functions from binary using nm."""
    functions = []
    try:
        # Try dynamic symbols first (-D)
        result = subprocess.run(["nm", "-D", binary_path], capture_output=True, text=True)
        if not result.stdout:
            result = subprocess.run(["nm", binary_path], capture_output=True, text=True)
            
        for line in result.stdout.splitlines():
            parts = line.split()
            # Look for Text (code) section symbols
            if len(parts) >= 3 and parts[1].upper() in ['T', 'W']:
                try:
                    addr = int(parts[0], 16)
                    name = parts[2]
                    functions.append((name, addr))
                except: continue
    except: pass
    return functions

def detect_crypto_functions(binary_path):
    """Detect likely crypto functions using regex patterns."""
    all_funcs = get_all_functions(binary_path)
    
    crypto_patterns = [
        r'\baes\b|_aes_|^aes', 
        r'\bdes\b|_des_|^des(?!troy|criptor)', 
        r'\brsa\b', r'\bsha\d+', r'\bmd5\b', r'\bhmac\b', 
        r'\bcbc\b', r'\becb\b', r'\bgcm\b',
        r'encrypt', r'decrypt', r'cipher', 
        r'(?<!_)hash(?!_string)',
        r'\brc4\b', r'\bchacha\b', r'\bpoly1305\b', 
        r'subbytes', r'shiftrows', r'mixcolumns', r'keyexpansion'
    ]
    
    crypto_funcs = []
    for name, addr in all_funcs:
        name_lower = name.lower()
        if any(x in name_lower for x in ['destructor', 'printf', 'log', 'error']): continue
        
        if any(re.search(pattern, name_lower) for pattern in crypto_patterns):
            crypto_funcs.append((name, addr))
    
    return crypto_funcs

def run_stripped_binary_analysis(binary_path, rootfs_path, filename, constant_results):
    """Analyze stripped/obfuscated binaries through behavioral monitoring + constant detection."""
    global stats_total_blocks, stats_crypto_heavy_blocks, basic_blocks, logger, syscall_events, strace_log_path
    
    # Reset stats
    stats_total_blocks = 0
    stats_crypto_heavy_blocks = 0
    basic_blocks = {}
    syscall_events = {
        'getrandom_calls': [],
        'random_reads': [],
        'memory_operations': [],
    }
    
    # ===== STRACE: Native syscall tracing (NEW!) =====
    print("\n" + "="*70)
    print("   NATIVE STRACE ANALYSIS (Optional)")
    print("="*70)
    
    strace_log, strace_success = run_with_strace(binary_path, rootfs_path, timeout=5)
    strace_stats = None
    
    if strace_success and strace_log:
        print(f"[*] Analyzing strace log...")
        strace_stats = analyze_strace_log(strace_log)
        
        if strace_stats:
            print(f"[*] Strace Statistics:")
            print(f"    Total syscalls: {strace_stats['total_syscalls']}")
            
            if strace_stats['getrandom_calls']:
                print(f"    getrandom() calls: {len(strace_stats['getrandom_calls'])}")
                for call in strace_stats['getrandom_calls'][:3]:
                    print(f"      - {call['size']} bytes: {call['line'][:80]}...")
            
            if strace_stats['read_random']:
                print(f"    Random device reads: {len(strace_stats['read_random'])}")
            
            if strace_stats['crypto_relevant']:
                print(f"    Crypto-relevant calls: {len(strace_stats['crypto_relevant'])}")
        
        # Log strace path
        if logger:
            logger.data['metadata']['strace_log'] = strace_log
            logger.data['metadata']['strace_syscalls'] = strace_stats['total_syscalls'] if strace_stats else 0
    else:
        print("[*] Strace skipped or failed - continuing with Qiling emulation")
    
    # Check GLIBC requirements
    glibc_versions = check_glibc_requirements(binary_path)
    if glibc_versions:
        max_version = glibc_versions[-1]
        print(f"[*] Binary requires GLIBC: {', '.join(glibc_versions)} (max: {max_version})")
        
        # Warn if newer than typical rootfs (2.31 is common in Qiling rootfs)
        max_ver_tuple = tuple(map(int, max_version.split('.')))
        if max_ver_tuple >= (2, 34):
            print(f"[!] WARNING: Binary requires GLIBC {max_version}, but rootfs may have older version")
            print(f"    If execution fails, try:")
            print(f"    1. Compile binary with older GLIBC: gcc -static ...")
            print(f"    2. Update rootfs libraries from your system")
    
    tmp_path = os.path.join(rootfs_path, "tmp")
    os.makedirs(tmp_path, exist_ok=True)
    temp_dir = tempfile.mkdtemp(dir=tmp_path)
    temp_binary = os.path.join(temp_dir, "test_binary")
    shutil.copy(binary_path, temp_binary)
    
    try:
        ql = Qiling([temp_binary], rootfs_path, verbose=QL_VERBOSE.OFF, console=True)
        
        # Log architecture
        if logger:
            arch_str = f"{ql.arch.type.name}"
            logger.log_architecture(arch_str)
        
        # CRITICAL: Hook syscalls FIRST to catch getrandom() calls
        print("[*] Installing syscall hooks (getrandom, read)...")
        hook_syscalls(ql)
        
        # Track memory writes with high entropy
        high_entropy_writes = []
        io_captures = {}  # Track I/O for pattern detection
        
        def monitor_memory_write(ql, access, address, size, value):
            """Hook all memory writes to detect high-entropy data (encrypted output)."""
            try:
                if size >= 4:
                    data = ql.mem.read(address, min(size, 32))
                    entropy = get_entropy(data[:min(16, size)])
                    
                    # Log all memory writes
                    if logger:
                        logger.log_memory_write(address, size, data, entropy)
                    
                    if entropy > 3.5:
                        high_entropy_writes.append({
                            'address': address,
                            'size': size,
                            'entropy': entropy,
                            'data': data[:16]
                        })
            except:
                pass
        
        # Hook memory writes and BASIC BLOCKS (not instructions!)
        ql.hook_mem_write(monitor_memory_write)
        ql.hook_block(profile_basic_block)  # MUCH FASTER than hook_code
        
        print("[*] Executing binary with syscall + basic block monitoring...")
        print("    (Tracking: getrandom, memory writes, crypto operations)")
        
        execution_failed = False
        glibc_error = False
        
        try:
            ql.run(timeout=50000000)
        except Exception as e:
            execution_failed = True
            error_msg = str(e)
            
            # Check for GLIBC version mismatch
            if "GLIBC" in error_msg or "version" in error_msg.lower():
                glibc_error = True
                print("\n[!] GLIBC Version Mismatch Detected!")
                print("    The binary requires a newer GLIBC version than available in rootfs.")
                print("\n    Solutions:")
                print("    1. Update rootfs: cd rootfs && git pull")
                print("    2. Use static binary: compile with -static flag")
                print("    3. Copy system libraries: cp /lib/x86_64-linux-gnu/libc.so.6 rootfs/x8664_linux/lib/")
                print(f"\n    Error details: {error_msg}\n")
            
            if logger:
                logger.log_error(f"Execution error: {error_msg}", e)
        
        # ===== PHASE 1: Syscall Analysis =====
        print("\n" + "="*70)
        print("   PHASE 1: SYSCALL ANALYSIS")
        print("="*70)
        
        if execution_failed:
            print(f"\n[!] Binary execution failed or crashed early")
            if glibc_error:
                print(f"[!] Reason: GLIBC version incompatibility")
            print(f"[*] Falling back to static analysis results only\n")
        else:
            print(f"\n[✓] Binary executed successfully")
        
        # Syscall results
        if syscall_events['getrandom_calls']:
            print(f"\n[✓] Detected {len(syscall_events['getrandom_calls'])} getrandom() call(s):")
            for i, call in enumerate(syscall_events['getrandom_calls'], 1):
                print(f"    Call #{i}:")
                print(f"      Size: {call['size']} bytes (0x{call['size']:x})")
                print(f"      Data: {call['data'][:16].hex()}")
                print(f"      Entropy: {call['entropy']:.2f}")
                
                # Immediate classification
                likely, ruled_out = classify_by_key_size(call['size'])
                if call['size'] <= 8:
                    print(f"      ⚠ CRITICAL: Key/nonce too small for standard crypto!")
                    print(f"         Likely: {likely[0]}")
        else:
            print(f"\n[-] No getrandom() calls detected")
            print(f"    Note: Binary may use /dev/random or hardcoded keys")
        
        # ===== PHASE 2: Constant Detection =====
        print("\n" + "="*70)
        print("   PHASE 2: CONSTANT DETECTION")
        print("="*70)
        
        if constant_results:
            print(f"\n[✓] Detected {len(constant_results)} algorithm(s), "
                  f"{sum(len(consts) for consts in constant_results.values())} constant(s)")
            for algo, constants in constant_results.items():
                const_types = set(c['constant'] for c in constants)
                print(f"    {algo}: {', '.join(const_types)}")
        else:
            print(f"\n[-] No known crypto constants found")
            print(f"    → Likely proprietary or obfuscated algorithm")
        
        # ===== PHASE 3: Memory & Pattern Analysis =====
        print("\n" + "="*70)
        print("   PHASE 3: MEMORY & PATTERN ANALYSIS")
        print("="*70)
        
        # Memory entropy analysis
        print(f"\n[*] Memory Entropy Analysis:")
        if high_entropy_writes:
            print(f"    [✓] Detected {len(high_entropy_writes)} high-entropy memory write(s)")
            print(f"    [*] Sample encrypted data:")
            for i, write in enumerate(high_entropy_writes[:3]):
                print(f"      Write #{i+1}: {write['data'].hex()} (entropy: {write['entropy']:.2f})")
        else:
            print(f"    [-] No high-entropy memory writes detected")
        
        # Loop Detection (Crypto Round Functions)
        crypto_loops = [
            (addr, info) for addr, info in basic_blocks.items()
            if info['is_loop'] and info['total_ops'] > 0 and 
               (info['crypto_ops'] / info['total_ops']) > 0.3
        ]
        
        print(f"\n[*] Crypto Loop Detection (Round Functions):")
        if crypto_loops:
            crypto_loops.sort(key=lambda x: x[1]['exec_count'], reverse=True)
            print(f"    [✓] Found {len(crypto_loops)} crypto loop(s):")
            for addr, info in crypto_loops[:5]:
                ratio = info['crypto_ops'] / info['total_ops']
                print(f"      @ {hex(addr)}: {info['exec_count']} iterations, "
                      f"{ratio:.1%} crypto-ops ({info['crypto_ops']}/{info['total_ops']} ops)")
        else:
            print(f"    [-] No crypto loops detected")
        
        # Basic Block Analysis
        total_instructions = sum(b['total_ops'] * b['exec_count'] for b in basic_blocks.values())
        total_crypto_ops = sum(b['crypto_ops'] * b['exec_count'] for b in basic_blocks.values())
        
        ratio = 0
        if total_instructions > 0:
            ratio = total_crypto_ops / total_instructions
            print(f"\n[*] Basic Block Analysis:")
            print(f"    Total Basic Blocks: {len(basic_blocks)}")
            print(f"    Total Instructions Executed: {total_instructions}")
            print(f"    Crypto Operations: {total_crypto_ops}")
            print(f"    Crypto-Op Ratio: {ratio:.2%}")
            print(f"    Crypto-Heavy Blocks: {stats_crypto_heavy_blocks}")
            if execution_failed:
                print(f"    [!] Note: Analysis incomplete due to execution failure")
        elif execution_failed and glibc_error:
            print(f"\n[*] Basic Block Analysis:")
            print(f"    [!] Could not complete due to GLIBC incompatibility")
            print(f"    [*] Relying on static analysis (constants) only")
        
        # ===== PHASE 4: Algorithm Classification =====
        print("\n" + "="*70)
        print("   PHASE 4: ALGORITHM CLASSIFICATION")
        print("="*70)
        
        classification = analyze_algorithm_evidence(
            constant_results, 
            syscall_events, 
            basic_blocks,
            io_captures
        )
        
        print_classification_report(classification, syscall_events)
        
        # Log results
        if logger:
            # Calculate numeric confidence score for logging
            confidence_level = classification.get('confidence', 'UNKNOWN')
            confidence_map = {'HIGH': 80, 'MEDIUM': 50, 'LOW': 20, 'UNKNOWN': 0}
            confidence_score = confidence_map.get(confidence_level, 0)
            
            # Add standard algorithm scores if any
            if classification.get('standard_algorithms'):
                max_algo_score = max([algo['score'] for algo in classification['standard_algorithms'].values()])
                confidence_score = max(confidence_score, max_algo_score)
            
            reasons = classification.get('proprietary_patterns', [])
            # Add standard algorithm evidence to reasons
            for algo, data in classification.get('standard_algorithms', {}).items():
                if data['score'] >= 40:
                    reasons.extend(data['evidence'])
            
            logger.log_verdict(
                confidence_score,
                confidence_level,
                reasons
            )
            
            # Log crypto loops
            for addr, block_info in basic_blocks.items():
                if block_info['is_loop'] and block_info['exec_count'] >= 10:
                    crypto_ratio = block_info['crypto_ops'] / block_info['total_ops'] if block_info['total_ops'] > 0 else 0
                    if crypto_ratio > 0.3:
                        logger.log_crypto_loop(
                            addr,
                            block_info['exec_count'],
                            block_info['crypto_ops'],
                            block_info['total_ops'],
                            crypto_ratio
                        )
            
            # Log timing for this phase
            logger.log_timing("stripped_binary_analysis", time.time() - logger.start_time)
            
            # Finalize and save logs
            log_dir = logger.finalize()
            print(f"\n[*] Logs saved to: {log_dir}")
            
            # Report strace log location
            if strace_log_path:
                print(f"[*] Strace log saved to: {strace_log_path}")
        
    finally:
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

def analyze_binary():
    global logger, BINARY_PATH, UNPACKED_BINARY_PATH
    
    if not BINARY_PATH or not os.path.exists(BINARY_PATH):
        print("Usage: python3 verify_crypto.py <binary_path>")
        sys.exit(1)
    
    # Initialize logger
    logger = CryptoLogger(BINARY_PATH)
    
    filename = os.path.basename(BINARY_PATH)
    
    # PHASE -1: Automatic Unpacking (NEW!)
    print("\n" + "="*60)
    print("[*] PHASE -1: Checking for packed binary...")
    
    unpacker = BinaryUnpacker()
    packer_name, confidence = unpacker.detect_packer(BINARY_PATH)
    
    if packer_name:
        print(f"[+] Packed binary detected: {packer_name} ({confidence}% confidence)")
        print(f"[*] Attempting to unpack...")
        
        unpacked_path, success, _ = unpacker.unpack(BINARY_PATH)
        
        if success:
            print(f"[✓] Successfully unpacked!")
            print(f"[*] Analyzing unpacked binary: {unpacked_path}")
            UNPACKED_BINARY_PATH = unpacked_path
            
            # Use unpacked binary for analysis
            analysis_target = unpacked_path
            
            # Log unpacking success
            if logger:
                logger.data['metadata']['packed'] = True
                logger.data['metadata']['packer'] = packer_name
                logger.data['metadata']['unpacked'] = True
                logger.data['metadata']['unpacked_path'] = unpacked_path
        else:
            print(f"[!] Unpacking failed - analyzing packed binary")
            print(f"    Note: Detection accuracy will be significantly reduced!")
            analysis_target = BINARY_PATH
            
            # Log unpacking failure
            if logger:
                logger.data['metadata']['packed'] = True
                logger.data['metadata']['packer'] = packer_name
                logger.data['metadata']['unpacked'] = False
    else:
        print("[-] No packer detected")
        analysis_target = BINARY_PATH
        
        if logger:
            logger.data['metadata']['packed'] = False
    
    rootfs_path = get_rootfs(analysis_target)

    if not rootfs_path:
        print("[-] Unknown architecture/Rootfs not found.")
        if logger:
            logger.log_error("Unknown architecture or rootfs not found")
            logger.finalize()
        return

    print(f"[*] Target: {filename}")
    print(f"[*] Rootfs: {rootfs_path}")
    
    # PHASE 0: YARA Static Analysis (FASTEST - < 1 second!)
    print("\n" + "="*60)
    print("[*] PHASE 0: YARA static analysis")
    yara_results = {'detected': [], 'matches': []}
    try:
        yara_scanner = YaraCryptoScanner()
        yara_results = yara_scanner.scan_file(analysis_target)
        
        if yara_results['detected']:
            print(f"[✓] YARA detected: {', '.join(yara_results['detected'])}")
            print(f"    Total matches: {yara_results['total_matches']}")
            print(f"    Scan time: {yara_results['scan_time']:.3f}s")
            
            # Show high-confidence matches
            high_conf = [m for m in yara_results['matches'] if m['confidence'] >= 90]
            if high_conf:
                print(f"    High-confidence rules:")
                for m in high_conf[:5]:
                    print(f"      - {m['rule']} ({m['algorithm']}, {m['confidence']}%)")
        else:
            print("[-] No YARA matches (may be obfuscated or compressed)")
        
        # Log YARA results
        if logger:
            logger.log_yara_results(yara_results)
            
    except Exception as e:
        print(f"[!] YARA scan failed: {e}")
        print("    Continuing with other detection methods...")
    
    # PHASE 1: Static Constant Scanning (FindCrypt-style)
    print("\n" + "="*60)
    print("[*] PHASE 1: Scanning for crypto constants...")
    constant_results = scan_for_constants(analysis_target)
    
    # Log constants
    if logger:
        logger.log_constants(constant_results)
    
    if constant_results:
        print(f"[✓] Found constants for {len(constant_results)} algorithm(s)")
        for algo in constant_results.keys():
            print(f"    - {algo}")
    else:
        print("[-] No crypto constants detected")
    
    # PHASE 2: Check for function symbols
    print("\n" + "="*60)
    print("[*] PHASE 2: Checking for function symbols...")
    crypto_funcs = detect_crypto_functions(analysis_target)
    
    # Log function symbols
    if logger:
        func_names = [name for name, addr in crypto_funcs]
        logger.log_function_symbols(func_names)
    
    if not crypto_funcs:
        print("[-] No crypto function names detected (stripped/obfuscated binary)")
        print("[*] Switching to enhanced behavioral analysis...")
        print("\n" + "="*60)
        print("[*] PHASE 3: Dynamic behavioral analysis...")
        run_stripped_binary_analysis(analysis_target, rootfs_path, filename, constant_results)
        return
    
    print(f"[*] Found {len(crypto_funcs)} crypto candidate(s):")
    for name, addr in crypto_funcs[:10]:
        print(f"    - {name} @ {hex(addr)}")
    
    print("\n" + "="*60)
    print("[*] PHASE 3: Running binary to test crypto functions...")
    run_binary_with_hooks(analysis_target, crypto_funcs, rootfs_path, filename, constant_results)

def run_binary_with_hooks(binary_path, crypto_funcs, rootfs_path, filename, constant_results):
    global stats_total_blocks, stats_crypto_heavy_blocks, basic_blocks, syscall_events, strace_log_path
    
    # Reset stats
    stats_total_blocks = 0
    stats_crypto_heavy_blocks = 0
    basic_blocks = {}
    syscall_events = {
        'getrandom_calls': [],
        'random_reads': [],
        'memory_operations': [],
    }
    
    # ===== STRACE: Native syscall tracing (NEW!) =====
    print("\n" + "="*70)
    print("   NATIVE STRACE ANALYSIS (Optional)")
    print("="*70)
    
    strace_log, strace_success = run_with_strace(binary_path, rootfs_path, timeout=5)
    strace_stats = None
    
    if strace_success and strace_log:
        print(f"[*] Analyzing strace log...")
        strace_stats = analyze_strace_log(strace_log)
        
        if strace_stats:
            print(f"[*] Strace Statistics:")
            print(f"    Total syscalls: {strace_stats['total_syscalls']}")
            
            if strace_stats['getrandom_calls']:
                print(f"    getrandom() calls: {len(strace_stats['getrandom_calls'])}")
                for call in strace_stats['getrandom_calls'][:3]:
                    print(f"      - {call['size']} bytes")
            
            if strace_stats['read_random']:
                print(f"    Random device reads: {len(strace_stats['read_random'])}")
            
            if strace_stats['crypto_relevant']:
                print(f"    Crypto-relevant calls: {len(strace_stats['crypto_relevant'])}")
        
        # Log strace path
        if logger:
            logger.data['metadata']['strace_log'] = strace_log
            logger.data['metadata']['strace_syscalls'] = strace_stats['total_syscalls'] if strace_stats else 0
    else:
        print("[*] Strace skipped or failed - continuing with Qiling emulation")
    
    # Check GLIBC requirements
    glibc_versions = check_glibc_requirements(binary_path)
    if glibc_versions:
        max_version = glibc_versions[-1]
        print(f"[*] Binary requires GLIBC: {', '.join(glibc_versions)} (max: {max_version})")
        
        # Warn if newer than typical rootfs
        max_ver_tuple = tuple(map(int, max_version.split('.')))
        if max_ver_tuple >= (2, 34):
            print(f"[!] WARNING: Binary requires GLIBC {max_version}, but rootfs may have older version")
            print(f"    If execution fails, try compiling with: gcc -static ...")
    
    tmp_path = os.path.join(rootfs_path, "tmp")
    os.makedirs(tmp_path, exist_ok=True)
    temp_dir = tempfile.mkdtemp(dir=tmp_path)
    temp_binary = os.path.join(temp_dir, "test_binary")
    shutil.copy(binary_path, temp_binary)
    
    try:
        ql = Qiling([temp_binary], rootfs_path, verbose=QL_VERBOSE.OFF, console=False)
        base_addr = ql.loader.images[0].base
        
        # CRITICAL: Hook syscalls FIRST
        print("[*] Installing syscall hooks (getrandom, read)...")
        hook_syscalls(ql)
        
        # S-Box Injection logic (preserved)
        try:
            res = subprocess.run(["nm", binary_path], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if " sbox" in line.lower():
                    parts = line.split()
                    sbox_addr = int(parts[0], 16) + base_addr
                    if ql.mem.read(sbox_addr, 1) == b"\x00":
                        print("[*] Injecting AES S-Box...")
                        # Full 256-byte AES S-Box
                        AES_SBOX = (
                            b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"
                            b"\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0"
                            b"\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15"
                            b"\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75"
                            b"\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84"
                            b"\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf"
                            b"\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8"
                            b"\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2"
                            b"\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73"
                            b"\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb"
                            b"\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79"
                            b"\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08"
                            b"\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a"
                            b"\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e"
                            b"\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf"
                            b"\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16"
                        )
                        ql.mem.write(sbox_addr, AES_SBOX)
                        break
        except: pass
        
        call_count = {}
        io_captures = {}
        hook_debug = {}  # Track hook execution
        
        for func_name, func_addr in crypto_funcs:
            func_addr_real = base_addr + func_addr
            hook_debug[func_name] = {'entry_called': 0, 'exit_called': 0, 'captures_attempted': 0}
            
            def make_hook(name):
                def hook_entry(ql):
                    hook_debug[name]['entry_called'] += 1
                    
                    if name not in call_count:
                        call_count[name] = 0
                        io_captures[name] = []
                    call_count[name] += 1
                    
                    try:
                        # 1. CAPTURE REGISTERS (ARGS 0-4, expanded for more coverage)
                        args = []
                        lr = 0
                        if "arm" in filename.lower():
                            args = [ql.arch.regs.r0, ql.arch.regs.r1, ql.arch.regs.r2, ql.arch.regs.r3]
                            lr = ql.arch.regs.lr
                        elif "mips" in filename.lower():
                            args = [ql.arch.regs.a0, ql.arch.regs.a1, ql.arch.regs.a2, ql.arch.regs.a3]
                            lr = ql.arch.regs.ra
                        elif "x86_64" in filename.lower():
                            args = [ql.arch.regs.rdi, ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.rcx]
                            lr = ql.unpack(ql.mem.read(ql.arch.regs.rsp, ql.arch.pointersize))
                        else: return

                        # 2. SNAPSHOT VALID POINTERS (more aggressive scanning)
                        pre_state = {}
                        for i, ptr in enumerate(args):
                            if 0x1000 < ptr < 0x7fffffffffff:  # Valid user-space address
                                try:
                                    # Try to read 16 bytes
                                    data = ql.mem.read(ptr, 16)
                                    # Only store if not all zeros and has some entropy
                                    if data != b'\x00'*16:
                                        pre_state[i] = {'ptr': ptr, 'data': data}
                                except: 
                                    pass
                        
                        if not pre_state: return

                        # 3. RETURN HOOK
                        def hook_exit(ql_inner):
                            hook_debug[name]['exit_called'] += 1
                            found_input = None
                            found_output = None
                            
                            for i, state in pre_state.items():
                                try:
                                    post_data = ql_inner.mem.read(state['ptr'], 16)
                                    
                                    # CHECK 1: Did data change?
                                    if post_data != state['data']:
                                        hook_debug[name]['captures_attempted'] += 1
                                        pre_entropy = get_entropy(state['data'])
                                        post_entropy = get_entropy(post_data)
                                        
                                        # If output has higher entropy than input, likely encrypted
                                        if post_entropy > 3.0 and post_entropy > pre_entropy:
                                            found_input = state['data']
                                            found_output = post_data
                                            break
                                        # Or just any transformation with decent entropy
                                        elif post_entropy > 2.5:
                                            found_input = state['data']
                                            found_output = post_data

                                except: pass
                            
                            if found_input and found_output:
                                io_captures[name].append({'input': found_input, 'output': found_output})

                        if lr: ql.hook_address(hook_exit, lr)

                    except: pass
                return hook_entry
            
            ql.hook_address(make_hook(func_name), func_addr_real)
        
        # Enable Basic Block Profiling (MUCH FASTER than hook_code)
        ql.hook_block(profile_basic_block)
        
        print("[*] Executing binary with basic block profiling...")
        
        execution_failed = False
        glibc_error = False
        
        try:
            ql.run(timeout=50000000) 
        except Exception as e:
            execution_failed = True
            error_msg = str(e)
            
            # Check for GLIBC version mismatch
            if "GLIBC" in error_msg or "version" in error_msg.lower():
                glibc_error = True
                print("\n[!] GLIBC Version Mismatch Detected!")
                print("    The binary requires a newer GLIBC version than available in rootfs.")
                print("\n    Solutions:")
                print("    1. Update rootfs: cd rootfs && git pull")
                print("    2. Use static binary: compile with -static flag")
                print("    3. Copy system libraries: cp /lib/x86_64-linux-gnu/libc.so.6 rootfs/x8664_linux/lib/")
                print(f"\n    Error details: {error_msg}\n")
        
        # Results
        print("\n" + "="*60)
        print("   ENHANCED ANALYSIS RESULTS (v2.0)")
        print("="*60)
        
        if execution_failed:
            print(f"\n[!] Binary execution failed or crashed early")
            if glibc_error:
                print(f"[!] Reason: GLIBC version incompatibility")
            print(f"[*] Falling back to static analysis results only\n")
        else:
            print(f"\n[✓] Binary executed successfully")
        
        # Constant Detection Results
        if constant_results:
            print(f"\n[*] Constant Detection (FindCrypt):")
            total_constants = sum(len(consts) for consts in constant_results.values())
            print(f"    [✓] Detected {len(constant_results)} algorithm(s), {total_constants} constant(s)")
            for algo, constants in constant_results.items():
                const_types = set(c['constant'] for c in constants)
                print(f"      {algo}: {', '.join(list(const_types)[:3])}")
        else:
            print(f"\n[*] Constant Detection:")
            print(f"    [-] No known crypto constants found")
        
        # Avalanche Analysis
        print("\n[*] Avalanche Effect Analysis:")
        
        # Show function call stats
        if call_count:
            print("    [*] Function Call Stats:")
            for func_name, count in sorted(call_count.items(), key=lambda x: x[1], reverse=True):
                print(f"      {func_name}: called {count} time(s)")
        else:
            print("    [-] Note: Functions may be inlined or not called during this execution")
        
        avalanche_detected = False
        total_captures = sum(len(captures) for captures in io_captures.values())
        
        if total_captures == 0:
            print("    [-] Unable to capture I/O through function hooks")
            print("    [-] Note: Binary executed and produced output (check console above)")
            print("    [*] Avalanche testing requires multiple runs with different inputs")
            print("    [*] Alternative: Test manually by running binary multiple times")
        else:
            print(f"    [*] Captured {total_captures} I/O operation(s)")
            
            for func_name, captures in io_captures.items():
                if len(captures) == 0:
                    continue
                    
                print(f"\n    Function: {func_name} ({len(captures)} capture(s))")
                
                # Show first capture details
                if len(captures) >= 1:
                    c = captures[0]
                    inp_hex = c['input'][:16].hex()
                    out_hex = c['output'][:16].hex()
                    inp_entropy = get_entropy(c['input'])
                    out_entropy = get_entropy(c['output'])
                    
                    print(f"      Input:  {inp_hex} (entropy: {inp_entropy:.2f})")
                    print(f"      Output: {out_hex} (entropy: {out_entropy:.2f})")
                
                # Test avalanche between captures
                if len(captures) >= 2:
                    for i in range(len(captures) - 1):
                        c1, c2 = captures[i], captures[i+1]
                        
                        # Skip if inputs are identical
                        if c1['input'] == c2['input']:
                            continue

                        in_diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1['input'], c2['input']))
                        out_diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1['output'], c2['output']))
                        
                        # Show avalanche test result
                        if in_diff > 0:
                            diffusion_ratio = out_diff / 128.0
                            print(f"      Avalanche Test #{i+1}:")
                            print(f"        Input Δ:  {in_diff} bits")
                            print(f"        Output Δ: {out_diff} bits ({diffusion_ratio:.1%} diffusion)")
                            
                            # Check if strong avalanche (30-70% for good crypto, 1-8 bit input change)
                            if 0 < in_diff <= 8 and 0.3 < diffusion_ratio < 0.7:
                                print(f"        ✓ STRONG AVALANCHE DETECTED")
                                avalanche_detected = True
                            elif diffusion_ratio > 0.3:
                                print(f"        ~ Moderate avalanche")
                            else:
                                print(f"        ✗ Weak avalanche")
        
            if not avalanche_detected:
                print("\n    [-] No strong avalanche effect detected")

        # Basic Block Analysis (NEW - replaces instruction analysis)
        total_instructions = sum(b['total_ops'] * b['exec_count'] for b in basic_blocks.values())
        total_crypto_ops = sum(b['crypto_ops'] * b['exec_count'] for b in basic_blocks.values())
        
        # Loop Detection
        crypto_loops = [
            (addr, info) for addr, info in basic_blocks.items()
            if info['is_loop'] and info['total_ops'] > 0 and 
               (info['crypto_ops'] / info['total_ops']) > 0.3
        ]
        
        ratio = 0
        if total_instructions > 0:
            ratio = total_crypto_ops / total_instructions
            print(f"\n[*] Basic Block Analysis:")
            print(f"    Total Basic Blocks: {len(basic_blocks)}")
            print(f"    Crypto Loops: {len(crypto_loops)}")
            print(f"    Total Instructions: {total_instructions}")
            print(f"    Crypto Operations: {total_crypto_ops}")
            print(f"    Crypto-Op Ratio: {ratio:.2%}")
            
        # IMPROVED Confidence Scoring (0-100 scale) with explicit breakdown
        reasons = []

        # Prepare per-factor points so we can print a transparent breakdown
        f1_points = 0  # constants (0-40)
        f2_points = 0  # function name matches (0-30)
        f3_points = 0  # crypto loops (0-20)
        f4_points = 0  # crypto-op ratio (0-15)
        f5_points = 0  # avalanche (0-15)

        # Factor 1: Crypto constants detected (up to 40 points)
        # IMPORTANT: Only count STRONG constants (not RSA exponents)
        strong_constants = {k: v for k, v in constant_results.items() 
                           if k not in ['RSA']}

        if strong_constants:
            num_algos = len(strong_constants)
            if num_algos >= 2:
                f1_points = 40
                reasons.append(f"{num_algos} crypto algorithms detected (constants)")
            elif num_algos == 1:
                f1_points = 30
                reasons.append(f"Crypto constants detected ({list(strong_constants.keys())[0]})")

        # Factor 2: Strong crypto function names (up to 30 points)
        strong_crypto_names = ['aes', 'des', 'rsa', 'sha', 'md5', 'encrypt', 'decrypt', 
                               'cipher', 'keyexpansion', 'subbytes', 'mixcolumns', 'shiftrows']
        strong_matches = sum(1 for name, _ in crypto_funcs 
                            if any(pattern in name.lower() for pattern in strong_crypto_names))

        if strong_matches >= 3:
            f2_points = 30
            reasons.append(f"{strong_matches} strong crypto function names")
        elif strong_matches >= 1:
            f2_points = 20
            reasons.append(f"{strong_matches} crypto function name(s)")

        # Factor 3: Crypto loops (up to 20 points)
        if len(crypto_loops) >= 3:
            f3_points = 20
            reasons.append(f"{len(crypto_loops)} crypto loops (round functions)")
        elif len(crypto_loops) >= 1:
            f3_points = 10
            reasons.append(f"{len(crypto_loops)} crypto loop(s)")

        # Factor 4: Crypto-operation ratio (up to 15 points)
        if ratio > 0.10:
            f4_points = 15
            reasons.append(f"High crypto-op ratio ({ratio:.1%})")
        elif ratio > 0.05:
            f4_points = 10
            reasons.append(f"Medium crypto-op ratio ({ratio:.1%})")
        elif ratio > 0.01:
            f4_points = 5
            reasons.append(f"Low crypto-op ratio ({ratio:.1%})")

        # Factor 5: Avalanche effect (up to 15 points)
        if avalanche_detected:
            f5_points = 15
            reasons.append("Avalanche effect confirmed")

        # Sum up and cap
        confidence_score = min(f1_points + f2_points + f3_points + f4_points + f5_points, 100)

        # Determine confidence level
        if confidence_score >= 70:
            confidence = "HIGH"
        elif confidence_score >= 40:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        # Print transparent breakdown so the user sees why the numeric score was low
        print("\n[*] Confidence scoring breakdown (0-100):")
        print(f"    - Constants evidence : {f1_points} pts (0-40)")
        print(f"    - Function names     : {f2_points} pts (0-30)")
        print(f"    - Crypto loops       : {f3_points} pts (0-20)")
        print(f"    - Crypto-op ratio    : {f4_points} pts (0-15)")
        print(f"    - Avalanche effect   : {f5_points} pts (0-15)")
        print(f"    -> TOTAL: {confidence_score}/100  => {confidence}\n")
        
        # ===== ALGORITHM CLASSIFICATION =====
        classification = analyze_algorithm_evidence(
            constant_results,
            syscall_events,
            basic_blocks,
            io_captures
        )
        
        print_classification_report(classification, syscall_events)
        
        # Report strace log location if available
        if strace_log_path:
            print(f"\n[*] Strace log saved to: {strace_log_path}")
        
    finally:
        try: shutil.rmtree(temp_dir)
        except: pass

if __name__ == "__main__":
    analyze_binary()

