#!/usr/bin/env python3
"""
Crypto Function Detector v3.0 - Multi-Phase Detection
Detects crypto functions via:
0. YARA static analysis (< 1 second, works on stripped binaries)
1. Constant scanning (FindCrypt-style)
2. Basic block profiling (10-100x faster than instruction hooks)
3. Loop detection (identifies round functions)
4. Entropy analysis and avalanche testing
"""

import os
import sys
import subprocess
import shutil
import tempfile
import re
import math
import time
from qiling import Qiling
from qiling.const import QL_VERBOSE

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

def get_rootfs(binary_path):
    """Determine rootfs based on automatically detected architecture."""
    arch = detect_architecture(binary_path)
    
    if not arch:
        print("[-] Could not detect architecture from binary")
        return None
    
    print(f"[+] Detected architecture: {arch}")
    
    # Map architecture to rootfs path
    rootfs_map = {
        'arm64': "/home/prajwal/Documents/dynamic/rootfs/arm64_linux",
        'arm': "/home/prajwal/Documents/dynamic/rootfs/arm_linux",
        'x86_64': "/home/prajwal/Documents/dynamic/rootfs/x8664_linux",
        'x86': "/home/prajwal/Documents/dynamic/rootfs/x86_linux",
        'mips': "/home/prajwal/Documents/dynamic/rootfs/mips32_linux",
        'mips64': "/home/prajwal/Documents/dynamic/rootfs/mips32_linux",  # Fallback
        'riscv64': "/home/prajwal/Documents/dynamic/rootfs/riscv64_linux",
        'riscv32': "/home/prajwal/Documents/dynamic/rootfs/riscv32_linux",
        'powerpc': "/home/prajwal/Documents/dynamic/rootfs/powerpc_linux",
    }
    
    rootfs = rootfs_map.get(arch)
    
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
    global stats_total_blocks, stats_crypto_heavy_blocks, basic_blocks, logger
    
    # Reset stats
    stats_total_blocks = 0
    stats_crypto_heavy_blocks = 0
    basic_blocks = {}
    
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
        
        # Track memory writes with high entropy
        high_entropy_writes = []
        
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
        
        print("[*] Executing binary with basic block profiling...")
        print("    (Using basic block hooks for 10-100x better performance)")
        try:
            ql.run(timeout=50000000)
        except Exception as e:
            if logger:
                logger.log_error(f"Execution error: {str(e)}", e)
        
        # Results
        print("\n" + "="*60)
        print("   ENHANCED ANALYSIS RESULTS (v2.0)")
        print("="*60)
        print(f"\n[✓] Binary executed")
        
        # Constant Detection Results
        if constant_results:
            print(f"\n[*] Constant Detection (FindCrypt):")
            total_constants = sum(len(consts) for consts in constant_results.values())
            print(f"    [✓] Detected {len(constant_results)} algorithm(s), {total_constants} constant(s)")
            for algo, constants in constant_results.items():
                const_types = set(c['constant'] for c in constants)
                print(f"      {algo}: {', '.join(const_types)}")
        else:
            print(f"\n[*] Constant Detection:")
            print(f"    [-] No known crypto constants found")
        
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
        
        # IMPROVED Confidence Scoring
        confidence_score = 0
        reasons = []
        
        # Factor 1: Crypto constants detected (up to 50 points)
        # IMPORTANT: Only count STRONG constants (not RSA exponents which are common)
        strong_constants = {k: v for k, v in constant_results.items() 
                           if k not in ['RSA']}  # RSA exponents have false positives
        
        if strong_constants:
            num_algos = len(strong_constants)
            if num_algos >= 2:
                confidence_score += 50
                reasons.append(f"{num_algos} crypto algorithms detected (constants)")
            elif num_algos == 1:
                confidence_score += 40
                reasons.append(f"Crypto constants detected ({list(strong_constants.keys())[0]})")
        
        # Factor 2: Crypto loops (up to 30 points)
        if len(crypto_loops) >= 3:
            confidence_score += 30
            reasons.append(f"{len(crypto_loops)} crypto loops (round functions)")
        elif len(crypto_loops) >= 1:
            confidence_score += 20
            reasons.append(f"{len(crypto_loops)} crypto loop(s)")
        
        # Factor 3: High-entropy writes (up to 20 points)
        if len(high_entropy_writes) >= 3:
            confidence_score += 20
            reasons.append(f"{len(high_entropy_writes)} high-entropy writes")
        elif len(high_entropy_writes) >= 1:
            confidence_score += 10
            reasons.append(f"{len(high_entropy_writes)} high-entropy write(s)")
        
        # Factor 4: Overall crypto-op ratio (up to 20 points)
        # IMPORTANT: Increased threshold since normal code has arithmetic
        if ratio > 0.30:  # Increased from 0.20 to reduce false positives
            confidence_score += 20
            reasons.append(f"Very high crypto-op ratio ({ratio:.1%})")
        elif ratio > 0.20:
            confidence_score += 15
            reasons.append(f"High crypto-op ratio ({ratio:.1%})")
        elif ratio > 0.15:
            confidence_score += 10
            reasons.append(f"Medium crypto-op ratio ({ratio:.1%})")
        
        # Cap at 100
        confidence_score = min(confidence_score, 100)
        
        # Determine confidence
        if confidence_score >= 70:
            confidence = "HIGH"
        elif confidence_score >= 40:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        # Log verdict
        if logger:
            logger.log_verdict(confidence_score, confidence, reasons)
            # Log crypto loops
            for addr, block_info in basic_blocks.items():
                if block_info['is_loop'] and block_info['exec_count'] >= 10:
                    crypto_ratio = block_info['crypto_ops'] / block_info['total_ops'] if block_info['total_ops'] > 0 else 0
                    if crypto_ratio > 0.3:
                        # addr is already an integer, not a string
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
            print(f"[*] Logs saved to: {log_dir}")
        
        # Verdict
        print("\n" + "="*60)
        if confidence_score >= 40:
            print(f"[*] VERDICT: Crypto behavior detected (Confidence: {confidence})")
        else:
            print(f"[*] VERDICT: No strong crypto indicators (Confidence: {confidence})")
        print(f"    Confidence Score: {confidence_score}/100")
        if reasons:
            print(f"    Reasons:")
            for reason in reasons:
                print(f"      - {reason}")
        print("="*60)
        
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
    
    if not crypto_funcs:
        print("[-] No crypto function names detected (stripped/obfuscated binary)")
        print("[*] Switching to enhanced behavioral analysis...")
        print("\n" + "="*60)
        print("[*] PHASE 3: Dynamic behavioral analysis...")
        run_stripped_binary_analysis(BINARY_PATH, rootfs_path, filename, constant_results)
        return
    
    print(f"[*] Found {len(crypto_funcs)} crypto candidate(s):")
    for name, addr in crypto_funcs[:10]:
        print(f"    - {name} @ {hex(addr)}")
    
    print("\n" + "="*60)
    print("[*] PHASE 3: Running binary to test crypto functions...")
    run_binary_with_hooks(BINARY_PATH, crypto_funcs, rootfs_path, filename, constant_results)

def run_binary_with_hooks(binary_path, crypto_funcs, rootfs_path, filename, constant_results):
    global stats_total_blocks, stats_crypto_heavy_blocks, basic_blocks
    
    # Reset stats
    stats_total_blocks = 0
    stats_crypto_heavy_blocks = 0
    basic_blocks = {}
    
    tmp_path = os.path.join(rootfs_path, "tmp")
    os.makedirs(tmp_path, exist_ok=True)
    temp_dir = tempfile.mkdtemp(dir=tmp_path)
    temp_binary = os.path.join(temp_dir, "test_binary")
    shutil.copy(binary_path, temp_binary)
    
    try:
        ql = Qiling([temp_binary], rootfs_path, verbose=QL_VERBOSE.OFF, console=False)
        base_addr = ql.loader.images[0].base
        
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
        try:
            ql.run(timeout=50000000) 
        except Exception as e:
            pass
        
        # Results
        print("\n" + "="*60)
        print("   ENHANCED ANALYSIS RESULTS (v2.0)")
        print("="*60)
        print(f"\n[✓] Binary executed")
        
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
            
        # IMPROVED Confidence Scoring (0-100 scale)
        confidence_score = 0
        reasons = []
        
        # Factor 1: Crypto constants detected (up to 40 points)
        # IMPORTANT: Only count STRONG constants (not RSA exponents)
        strong_constants = {k: v for k, v in constant_results.items() 
                           if k not in ['RSA']}
        
        if strong_constants:
            num_algos = len(strong_constants)
            if num_algos >= 2:
                confidence_score += 40
                reasons.append(f"{num_algos} crypto algorithms detected (constants)")
            elif num_algos == 1:
                confidence_score += 30
                reasons.append(f"Crypto constants detected ({list(strong_constants.keys())[0]})")
        
        # Factor 2: Strong crypto function names (up to 30 points)
        strong_crypto_names = ['aes', 'des', 'rsa', 'sha', 'md5', 'encrypt', 'decrypt', 
                               'cipher', 'keyexpansion', 'subbytes', 'mixcolumns', 'shiftrows']
        strong_matches = sum(1 for name, _ in crypto_funcs 
                            if any(pattern in name.lower() for pattern in strong_crypto_names))
        
        if strong_matches >= 3:
            confidence_score += 30
            reasons.append(f"{strong_matches} strong crypto function names")
        elif strong_matches >= 1:
            confidence_score += 20
            reasons.append(f"{strong_matches} crypto function name(s)")
        
        # Factor 3: Crypto loops (up to 20 points)
        if len(crypto_loops) >= 3:
            confidence_score += 20
            reasons.append(f"{len(crypto_loops)} crypto loops (round functions)")
        elif len(crypto_loops) >= 1:
            confidence_score += 10
            reasons.append(f"{len(crypto_loops)} crypto loop(s)")
        
        # Factor 4: Crypto-operation ratio (up to 15 points)
        if ratio > 0.10:
            confidence_score += 15
            reasons.append(f"High crypto-op ratio ({ratio:.1%})")
        elif ratio > 0.05:
            confidence_score += 10
            reasons.append(f"Medium crypto-op ratio ({ratio:.1%})")
        elif ratio > 0.01:
            confidence_score += 5
            reasons.append(f"Low crypto-op ratio ({ratio:.1%})")
        
        # Factor 5: Avalanche effect (up to 15 points)
        if avalanche_detected:
            confidence_score += 15
            reasons.append("Avalanche effect confirmed")
        
        # Cap at 100
        confidence_score = min(confidence_score, 100)
        
        # Determine confidence level
        if confidence_score >= 70:
            confidence = "HIGH"
        elif confidence_score >= 40:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
            
        # Verdict
        print("\n" + "="*60)
        print(f"[*] VERDICT: Crypto functions detected (Confidence: {confidence})")
        print(f"    Confidence Score: {confidence_score}/100")
        if reasons:
            print(f"    Reasons:")
            for reason in reasons:
                print(f"      - {reason}")
        print("="*60)
        
    finally:
        try: shutil.rmtree(temp_dir)
        except: pass

if __name__ == "__main__":
    analyze_binary()

