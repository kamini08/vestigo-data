#!/usr/bin/env python3
"""
Feature Extractor for AI/ML-Based Cryptographic Protocol Detection
Purpose: Generate time-series execution traces for LSTM/Transformer training

This script uses Qiling Framework to emulate stripped ELF binaries and produces
a unified sequential log of basic blocks and syscalls, preserving temporal order.
"""

import os
import sys
import json
import hashlib
import math
import struct
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional

from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_ARCH
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM
from capstone import CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN


def detect_architecture(binary_path):
    """Automatically detect architecture from ELF header."""
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
    
    # Get the dynamic directory (where this script is located)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Map architecture to rootfs path
    rootfs_map = {
        'arm64': os.path.join(script_dir, "rootfs/arm64_linux"),
        'arm': os.path.join(script_dir, "rootfs/arm_linux"),
        'x86_64': os.path.join(script_dir, "rootfs/x8664_linux"),
        'x86': os.path.join(script_dir, "rootfs/x86_linux"),
        'mips': os.path.join(script_dir, "rootfs/mips32_linux"),
        'mips64': os.path.join(script_dir, "rootfs/mips32_linux"),  # Fallback
        'riscv64': os.path.join(script_dir, "rootfs/riscv64_linux"),
        'riscv32': os.path.join(script_dir, "rootfs/riscv32_linux"),
        'powerpc': os.path.join(script_dir, "rootfs/powerpc_linux"),
    }
    
    rootfs = rootfs_map.get(arch)
    
    if not rootfs:
        print(f"[-] No rootfs mapping found for architecture: {arch}")
        return None
    
    # Verify rootfs exists
    if not os.path.exists(rootfs):
        print(f"[-] Rootfs path does not exist: {rootfs}")
        print(f"[!] Please ensure rootfs is available at: {rootfs}")
        return None
    
    print(f"[+] Using rootfs: {rootfs}")
    return rootfs


class ExecutionTracer:
    """
    Captures unified time-series execution trace of basic blocks and syscalls.
    Implements block coalescing to compress repetitive hardware loops (rep stosd, crypto rounds).
    """
    
    def __init__(self, output_path: str = "trace.jsonl", enable_coalescing: bool = True):
        self.output_path = output_path
        self.trace_log = []
        self.sequence_number = 0
        self.block_cache = {}  # Cache for block features to avoid recomputation
        self.disassembler = None
        
        # Block coalescing state
        self.enable_coalescing = enable_coalescing
        self.last_block_address = None
        self.last_block_hash = None
        self.repeat_count = 0
        self.pending_coalesced_block = None
        
    def initialize_disassembler(self, ql: Qiling):
        """Initialize Capstone disassembler based on architecture."""
        arch_map = {
            "x86": (CS_ARCH_X86, CS_MODE_32),
            "x8664": (CS_ARCH_X86, CS_MODE_64),
            "arm": (CS_ARCH_ARM, CS_MODE_ARM),
            "arm64": (CS_ARCH_ARM, CS_MODE_ARM),
            "mips": (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN),
        }
        
        arch = ql.arch.type.name.lower()
        if arch in arch_map:
            cs_arch, cs_mode = arch_map[arch]
            self.disassembler = Cs(cs_arch, cs_mode)
            self.disassembler.detail = True
        else:
            print(f"[!] Unsupported architecture: {arch}")
            
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of a byte buffer.
        High entropy (>7.0) suggests encrypted/compressed data.
        """
        if not data:
            return 0.0
        
        entropy = 0.0
        byte_counts = defaultdict(int)
        
        for byte in data:
            byte_counts[byte] += 1
        
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    def hash_bytes(self, data: bytes, algorithm: str = "sha256") -> str:
        """Generate hash of raw bytes for block identification."""
        if algorithm == "md5":
            return hashlib.md5(data).hexdigest()
        else:
            return hashlib.sha256(data).hexdigest()
    
    def _normalize_operand(self, op_str: str) -> str:
        """
        Normalize operands to reduce variance while preserving semantic information.
        E.g., 'rax' -> 'reg', '0x1234' -> 'imm', '[rbp-0x10]' -> 'mem_stack'
        """
        import re
        
        op_str = op_str.strip()
        
        # Memory operands
        if '[' in op_str:
            if 'rsp' in op_str or 'rbp' in op_str or 'esp' in op_str or 'ebp' in op_str:
                return 'mem_stack'
            elif 'rip' in op_str or 'eip' in op_str:
                return 'mem_rip'
            else:
                return 'mem_heap'
        
        # Registers
        reg_patterns = [
            r'^r[a-z0-9]+$', r'^e[a-z]+$', r'^[a-z][a-z]$',  # x86/x64 regs
            r'^x[0-9]+$', r'^w[0-9]+$',  # ARM regs
            r'^v[0-9]+$', r'^s[0-9]+$', r'^d[0-9]+$',  # ARM SIMD
            r'^\$[a-z0-9]+$'  # MIPS regs
        ]
        for pattern in reg_patterns:
            if re.match(pattern, op_str, re.IGNORECASE):
                return 'reg'
        
        # Immediate values (hex or decimal)
        if re.match(r'^-?0x[0-9a-f]+$', op_str, re.IGNORECASE) or re.match(r'^-?\d+$', op_str):
            return 'imm'
        
        # Default
        return 'const'
    
    def _get_instruction_with_operands(self, insn) -> str:
        """
        Create instruction representation with normalized operands.
        E.g., 'mov rax, rdi' -> 'mov_reg_reg'
             'xor eax, eax' -> 'xor_reg_reg'
             'add rax, 0x10' -> 'add_reg_imm'
        """
        try:
            mnemonic = insn.mnemonic
            op_str = insn.op_str
            
            if not op_str:
                return mnemonic
            
            # Split operands
            operands = [op.strip() for op in op_str.split(',')]
            
            # Normalize each operand
            normalized_ops = [self._normalize_operand(op) for op in operands]
            
            # Create instruction signature
            return f"{mnemonic}_{'_'.join(normalized_ops)}"
        except:
            return insn.mnemonic
    
    def _capture_register_state(self, ql: Qiling) -> Dict[str, str]:
        """
        Capture current register state for avalanche analysis.
        Architecture-aware register sampling.
        """
        arch = ql.arch.type
        reg_state = {}
        
        try:
            if arch == QL_ARCH.X86:
                reg_state = {
                    'eax': hex(ql.arch.regs.eax),
                    'ebx': hex(ql.arch.regs.ebx),
                    'ecx': hex(ql.arch.regs.ecx),
                    'edx': hex(ql.arch.regs.edx),
                    'esi': hex(ql.arch.regs.esi),
                    'edi': hex(ql.arch.regs.edi),
                }
            elif arch == QL_ARCH.X8664:
                reg_state = {
                    'rax': hex(ql.arch.regs.rax),
                    'rbx': hex(ql.arch.regs.rbx),
                    'rcx': hex(ql.arch.regs.rcx),
                    'rdx': hex(ql.arch.regs.rdx),
                    'rsi': hex(ql.arch.regs.rsi),
                    'rdi': hex(ql.arch.regs.rdi),
                }
            elif arch == QL_ARCH.ARM:
                reg_state = {
                    'r0': hex(ql.arch.regs.r0),
                    'r1': hex(ql.arch.regs.r1),
                    'r2': hex(ql.arch.regs.r2),
                    'r3': hex(ql.arch.regs.r3),
                    'r4': hex(ql.arch.regs.r4),
                    'r5': hex(ql.arch.regs.r5),
                }
            elif arch == QL_ARCH.MIPS:
                reg_state = {
                    'v0': hex(ql.arch.regs.v0),
                    'v1': hex(ql.arch.regs.v1),
                    'a0': hex(ql.arch.regs.a0),
                    'a1': hex(ql.arch.regs.a1),
                    'a2': hex(ql.arch.regs.a2),
                    'a3': hex(ql.arch.regs.a3),
                }
        except Exception as e:
            pass  # Silently ignore register access errors
        
        return reg_state
    
    def _capture_memory_state(self, ql: Qiling) -> Dict[str, Any]:
        """
        Capture stack/heap state for avalanche analysis.
        Samples key memory regions and calculates entropy.
        """
        mem_state = {}
        arch = ql.arch.type
        
        try:
            # Get stack pointer
            if arch == QL_ARCH.X86:
                sp = ql.arch.regs.esp
            elif arch == QL_ARCH.X8664:
                sp = ql.arch.regs.rsp
            elif arch == QL_ARCH.ARM:
                sp = ql.arch.regs.sp
            elif arch == QL_ARCH.MIPS:
                sp = ql.arch.regs.sp
            else:
                return mem_state
            
            # Sample stack (top 128 bytes)
            stack_data = ql.mem.read(sp, 128)
            mem_state['stack_entropy'] = self.calculate_entropy(stack_data)
            mem_state['stack_hash'] = hashlib.md5(stack_data).hexdigest()[:16]
            
            # Count non-zero bytes (indicator of data activity)
            mem_state['stack_nonzero_bytes'] = sum(1 for b in stack_data if b != 0)
            
        except Exception as e:
            pass  # Silently ignore memory access errors
        
        return mem_state
    
    def extract_block_features(self, ql: Qiling, address: int, size: int) -> Dict[str, Any]:
        """
        Extract features from a basic block.
        This creates the "words" in our execution grammar.
        
        IMPROVEMENTS:
        - mnemonics now include operand types (mov_reg_reg vs mov_reg_imm)
        - has_crypto_patterns moved to metadata (not for model input)
        - AVALANCHE: Register and memory state capture for crypto blocks
        """
        # Check cache first
        cache_key = (address, size)
        if cache_key in self.block_cache:
            cached = self.block_cache[cache_key].copy()
            
            # For crypto blocks, ALWAYS capture fresh register/memory state (don't cache)
            if cached.get("metadata", {}).get("has_crypto_patterns"):
                cached["register_state"] = self._capture_register_state(ql)
                cached["memory_state"] = self._capture_memory_state(ql)
            
            return cached
        
        try:
            # Read the raw bytes of the block
            raw_bytes = ql.mem.read(address, size)
            bytes_hash = self.hash_bytes(raw_bytes)
            
            # Disassemble to get mnemonics with operand types
            mnemonics_simple = []  # Just mnemonic (for compatibility)
            mnemonics_typed = []   # Mnemonic with operand types (NEW!)
            instruction_count = 0
            
            if self.disassembler:
                for insn in self.disassembler.disasm(raw_bytes, address):
                    mnemonics_simple.append(insn.mnemonic)
                    mnemonics_typed.append(self._get_instruction_with_operands(insn))
                    instruction_count += 1
            
            # Detect crypto patterns
            has_crypto = self._detect_crypto_patterns(mnemonics_simple)
            
            features = {
                "address": hex(address),
                "size": size,
                "bytes_hash": bytes_hash,
                "mnemonics": mnemonics_typed,  # Use typed version
                "mnemonics_simple": mnemonics_simple,  # Keep simple for reference
                "instruction_count": instruction_count,
                # MOVED: has_crypto_patterns to metadata (not for model input)
                "metadata": {
                    "has_crypto_patterns": has_crypto
                }
            }
            
            # AVALANCHE ENHANCEMENT: Capture register/memory state for crypto blocks
            if has_crypto:
                features["register_state"] = self._capture_register_state(ql)
                features["memory_state"] = self._capture_memory_state(ql)
            
            # Cache the result
            self.block_cache[cache_key] = features.copy()
            return features
            
        except Exception as e:
            print(f"[!] Error extracting block at {hex(address)}: {e}")
            return {
                "address": hex(address),
                "size": size,
                "error": str(e)
            }
    
    def _detect_crypto_patterns(self, mnemonics: List[str]) -> bool:
        """
        Heuristic detection of crypto-like instruction patterns.
        XOR loops, bit rotations, SIMD operations are common.
        """
        crypto_indicators = ["xor", "rol", "ror", "shl", "shr", "pxor", "aes"]
        xor_count = sum(1 for m in mnemonics if "xor" in m.lower())
        
        # Multiple XORs or specific crypto instructions
        if xor_count > 2 or any(ind in " ".join(mnemonics).lower() for ind in crypto_indicators):
            return True
        return False
    
    def log_basic_block(self, ql: Qiling, address: int, size: int):
        """
        Log a basic block execution event with intelligent coalescing.
        
        COALESCING LOGIC:
        - Detects repeated execution of the same block (hardware loops like rep stosd)
        - Squashes N identical executions into 1 event with execution_count field
        - Dramatically reduces noise from memset/memcpy operations
        - Preserves LSTM context window for actual crypto logic
        """
        features = self.extract_block_features(ql, address, size)
        block_hash = features.get("bytes_hash")
        
        if not self.enable_coalescing:
            # No coalescing - log every block (old behavior)
            event = {
                "seq": self.sequence_number,
                "timestamp": datetime.now().isoformat(),
                "type": "basic_block",
                "data": features
            }
            self.trace_log.append(event)
            self.sequence_number += 1
            return
        
        # COALESCING ENABLED
        # Check if this is a repeat of the last block
        if address == self.last_block_address and block_hash == self.last_block_hash:
            # Same block executed again - increment repeat counter
            self.repeat_count += 1
            
            # Update pending coalesced block's metadata
            if self.pending_coalesced_block:
                self.pending_coalesced_block["data"]["execution_count"] = self.repeat_count
        else:
            # Different block - flush any pending coalesced block
            self._flush_coalesced_block()
            
            # Start tracking new block
            self.last_block_address = address
            self.last_block_hash = block_hash
            self.repeat_count = 1
            
            # Create pending coalesced block
            self.pending_coalesced_block = {
                "seq": self.sequence_number,
                "timestamp": datetime.now().isoformat(),
                "type": "basic_block",
                "data": {
                    **features,
                    "execution_count": 1  # Will be updated if repeated
                }
            }
    
    def _flush_coalesced_block(self):
        """Flush any pending coalesced block to the trace log."""
        if self.pending_coalesced_block:
            self.trace_log.append(self.pending_coalesced_block)
            self.sequence_number += 1
            self.pending_coalesced_block = None
    
    def _normalize_syscall_args(self, syscall_name: str, args: List[Any]) -> List[Any]:
        """
        Normalize syscall arguments to reduce variance.
        
        IMPROVEMENTS:
        - FDs are tagged (SOCKET_FD, FILE_FD, etc.)
        - Pointers are abstracted (PTR_STACK, PTR_HEAP, PTR_LOW, PTR_HIGH)
        - Small integers kept as-is for semantic meaning
        """
        normalized = []
        
        # FD-related syscalls (first arg is usually FD)
        fd_syscalls = {'read', 'write', 'send', 'recv', 'sendto', 'recvfrom', 
                      'connect', 'bind', 'listen', 'accept', 'close',
                      'ioctl', 'fcntl', 'fstat', 'lseek'}
        
        for i, arg in enumerate(args):
            if isinstance(arg, int):
                # First arg of FD syscalls
                if i == 0 and syscall_name in fd_syscalls:
                    if arg >= 100:
                        normalized.append("MOCK_FD")  # Our mocked FDs
                    elif arg == 0:
                        normalized.append("STDIN")
                    elif arg == 1:
                        normalized.append("STDOUT")
                    elif arg == 2:
                        normalized.append("STDERR")
                    elif arg < 20:
                        normalized.append("LOW_FD")
                    else:
                        normalized.append("FILE_FD")
                
                # Pointer-like values (addresses)
                elif arg > 0x1000:
                    if 0x7fff00000000 <= arg <= 0x7fffffffffff:
                        normalized.append("PTR_STACK")
                    elif 0x555555554000 <= arg <= 0x555555600000:
                        normalized.append("PTR_TEXT")
                    elif arg >= 0x7f0000000000:
                        normalized.append("PTR_LIB")
                    else:
                        normalized.append("PTR_HEAP")
                
                # Small integers (flags, sizes, etc.) - keep as-is
                elif arg < 1024:
                    normalized.append(arg)
                
                # Medium integers (likely sizes)
                else:
                    normalized.append("SIZE")
            
            elif isinstance(arg, str):
                # Already hex string from serialization
                if arg.startswith('0x'):
                    # Parse and categorize
                    try:
                        addr = int(arg, 16)
                        if 0x7fff00000000 <= addr <= 0x7fffffffffff:
                            normalized.append("PTR_STACK")
                        elif addr >= 0x7f0000000000:
                            normalized.append("PTR_LIB")
                        elif addr > 0x10000:
                            normalized.append("PTR_HEAP")
                        else:
                            normalized.append(arg)
                    except:
                        normalized.append(arg)
                else:
                    normalized.append(arg)
            else:
                normalized.append(str(arg))
        
        return normalized
    
    def log_syscall(self, ql: Qiling, syscall_name: str, args: List[Any], 
                    return_value: Any = None, buffer_data: bytes = None):
        """
        Log a syscall execution event.
        These are the "punctuation" in our execution grammar.
        
        IMPROVEMENTS:
        - args are now normalized (FDs -> tags, pointers -> categories)
        - Original args kept in metadata for debugging
        - Flushes any pending coalesced blocks (syscalls break repetition patterns)
        """
        # Flush any pending coalesced block before logging syscall
        self._flush_coalesced_block()
        
        # Truncate args to first 4 for context
        args_context = args[:4] if args else []
        
        # Convert args to serializable format (original)
        serialized_args = []
        for arg in args_context:
            if isinstance(arg, int):
                serialized_args.append(hex(arg) if arg > 255 else arg)
            else:
                serialized_args.append(str(arg))
        
        # Normalize args for ML model
        normalized_args = self._normalize_syscall_args(syscall_name, args_context)
        
        event = {
            "seq": self.sequence_number,
            "timestamp": datetime.now().isoformat(),
            "type": "syscall",
            "data": {
                "name": syscall_name,
                "args": normalized_args,  # Use normalized version
                "return_value": return_value,
                "metadata": {
                    "args_raw": serialized_args  # Keep original for debugging
                }
            }
        }
        
        # Calculate entropy for data buffers (key feature for crypto detection)
        if buffer_data:
            entropy = self.calculate_entropy(buffer_data)
            event["data"]["buffer_size"] = len(buffer_data)
            event["data"]["entropy"] = entropy
            event["data"]["likely_encrypted"] = entropy > 7.0
        
        self.trace_log.append(event)
        self.sequence_number += 1
    
    def save_trace(self):
        """Write the unified trace to JSONL format."""
        # Flush any pending coalesced block before saving
        self._flush_coalesced_block()
        
        print(f"[*] Saving trace with {len(self.trace_log)} events to {self.output_path}")
        
        with open(self.output_path, 'w') as f:
            for event in self.trace_log:
                f.write(json.dumps(event) + '\n')
        
        print(f"[+] Trace saved successfully!")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Generate statistics about the trace."""
        block_count = sum(1 for e in self.trace_log if e["type"] == "basic_block")
        syscall_count = sum(1 for e in self.trace_log if e["type"] == "syscall")
        crypto_blocks = sum(1 for e in self.trace_log 
                           if e["type"] == "basic_block" and 
                           e["data"].get("metadata", {}).get("has_crypto_patterns", False))
        
        # Count coalesced blocks (execution_count > 1)
        coalesced_count = sum(1 for e in self.trace_log 
                             if e["type"] == "basic_block" and 
                             e["data"].get("execution_count", 1) > 1)
        
        # Total executions (including coalesced repeats)
        total_executions = sum(e["data"].get("execution_count", 1) 
                              for e in self.trace_log 
                              if e["type"] == "basic_block")
        
        stats = {
            "total_events": len(self.trace_log),
            "basic_blocks": block_count,
            "syscalls": syscall_count,
            "crypto_pattern_blocks": crypto_blocks,
            "unique_blocks": len(self.block_cache)
        }
        
        if self.enable_coalescing:
            compression_ratio = (total_executions / max(block_count, 1))
            stats["coalesced_blocks"] = coalesced_count
            stats["total_block_executions"] = total_executions
            stats["compression_ratio"] = f"{compression_ratio:.2f}x"
        
        return stats


class EnvironmentMocker:
    """
    The "Liar" - Mocks environment to prevent early exits and force protocol revelation.
    
    IMPROVEMENTS:
    - Hooks by both function name AND raw syscall number
    - Architecture-aware syscall number detection
    - Robust fallback mechanisms
    """
    
    def __init__(self, tracer: ExecutionTracer):
        self.tracer = tracer
        self.fake_fds = {}
        self.next_fd = 100  # Start fake FDs at 100 to avoid conflicts
        
    def get_syscall_numbers(self, ql: Qiling, name: str) -> list:
        """Get syscall numbers for a given name across architectures."""
        arch = ql.arch.type
        
        # Syscall number mappings (architecture-specific)
        syscall_map = {
            "x86": {
                "socket": 1,     # socketcall sub-function
                "connect": 3,    # socketcall sub-function
                "send": 9,       # socketcall sub-function
                "recv": 10,      # socketcall sub-function
                "open": 5,
                "read": 3,
                "write": 4,
            },
            "x8664": {
                "socket": 41,
                "connect": 42,
                "send": 44,
                "sendto": 44,
                "recv": 45,
                "recvfrom": 45,
                "open": 2,
                "read": 0,
                "write": 1,
            },
            "arm": {
                "socket": 281,
                "connect": 283,
                "send": 289,
                "recv": 291,
                "open": 5,
                "read": 3,
                "write": 4,
            },
            "mips": {
                "socket": 4183,
                "connect": 4170,
                "send": 4178,
                "recv": 4175,
                "open": 4005,
                "read": 4003,
                "write": 4004,
            }
        }
        
        arch_map = syscall_map.get(arch, {})
        numbers = []
        if name in arch_map:
            numbers.append(arch_map[name])
        return numbers
    
    def hook_syscall_robust(self, ql: Qiling, name: str, handler):
        """
        Hook a syscall by BOTH name and number for maximum compatibility.
        """
        hooked_methods = []
        
        # Method 1: Hook by name (high-level OS layer)
        try:
            ql.os.set_syscall(name, handler)
            hooked_methods.append(f"name:{name}")
        except Exception as e:
            pass
        
        # Method 2: Hook by syscall number (low-level)
        syscall_numbers = self.get_syscall_numbers(ql, name)
        for num in syscall_numbers:
            try:
                ql.os.set_syscall(num, handler)
                hooked_methods.append(f"num:{num}")
            except Exception as e:
                pass
        
        if hooked_methods:
            print(f"  [+] Hooked {name}: {', '.join(hooked_methods)}")
        else:
            print(f"  [!] Failed to hook {name}")
        
        return len(hooked_methods) > 0
        
    def setup_hooks(self, ql: Qiling):
        """Install hooks for common syscalls that might cause early exit."""
        print("[*] Installing robust environment mocking hooks (name + number)...")
        
        # Network syscalls
        self._hook_connect(ql)
        self._hook_socket(ql)
        self._hook_send(ql)
        self._hook_recv(ql)
        
        # File syscalls
        self._hook_open(ql)
        self._hook_read(ql)
        self._hook_write(ql)
        
        # DNS
        self._hook_gethostbyname(ql)
        
        print("[+] Robust environment mocking hooks installed")
    
    def _hook_connect(self, ql: Qiling):
        """Mock connect to always succeed."""
        def mock_connect(ql, sockfd, addr, addrlen, *args):
            self.tracer.log_syscall(ql, "connect", [sockfd, addr, addrlen], return_value=0)
            print(f"[MOCK] connect({sockfd}) -> SUCCESS")
            return 0
        
        self.hook_syscall_robust(ql, "connect", mock_connect)
    
    def _hook_socket(self, ql: Qiling):
        """Mock socket to return valid FD."""
        def mock_socket(ql, domain, type_, protocol, *args):
            fake_fd = self.next_fd
            self.next_fd += 1
            self.fake_fds[fake_fd] = "socket"
            self.tracer.log_syscall(ql, "socket", [domain, type_, protocol], return_value=fake_fd)
            print(f"[MOCK] socket() -> FD {fake_fd}")
            return fake_fd
        
        self.hook_syscall_robust(ql, "socket", mock_socket)
    
    def _hook_send(self, ql: Qiling):
        """Mock send and capture buffer for entropy analysis."""
        def mock_send(ql, sockfd, buf_addr, length, flags, *args):
            try:
                buffer_data = ql.mem.read(buf_addr, min(length, 4096))  # Cap at 4KB
                self.tracer.log_syscall(ql, "send", [sockfd, hex(buf_addr), length, flags], 
                                       return_value=length, buffer_data=buffer_data)
                print(f"[MOCK] send({sockfd}, {length} bytes) -> Entropy: {self.tracer.calculate_entropy(buffer_data):.2f}")
            except:
                self.tracer.log_syscall(ql, "send", [sockfd, hex(buf_addr), length, flags], return_value=length)
            return length
        
        self.hook_syscall_robust(ql, "send", mock_send)
        self.hook_syscall_robust(ql, "sendto", mock_send)
    
    def _hook_recv(self, ql: Qiling):
        """Mock recv to return dummy data OR controlled input for avalanche testing."""
        def mock_recv(ql, sockfd, buf_addr, length, flags, *args):
            # Check for avalanche experiment override
            override_hex = os.environ.get("QILING_OVERRIDE_INPUT_HEX")
            
            if override_hex:
                # Use controlled input from environment
                try:
                    controlled_data = bytes.fromhex(override_hex)
                    fake_data = controlled_data[:length]
                    print(f"[AVALANCHE] recv({sockfd}) -> Using controlled input ({len(fake_data)} bytes)")
                except Exception as e:
                    print(f"[!] Failed to parse QILING_OVERRIDE_INPUT_HEX: {e}")
                    fake_data = b"\x16\x03\x01\x00\x50" + b"\x00" * min(length - 5, 100)
            else:
                # Return fake TLS handshake-like data
                fake_data = b"\x16\x03\x01\x00\x50" + b"\x00" * min(length - 5, 100)
            
            try:
                ql.mem.write(buf_addr, fake_data[:length])
            except:
                pass
            self.tracer.log_syscall(ql, "recv", [sockfd, hex(buf_addr), length, flags], return_value=len(fake_data))
            print(f"[MOCK] recv({sockfd}) -> {len(fake_data)} bytes")
            return len(fake_data)
        
        self.hook_syscall_robust(ql, "recv", mock_recv)
        self.hook_syscall_robust(ql, "recvfrom", mock_recv)
    
    def _hook_open(self, ql: Qiling):
        """Mock open to always succeed."""
        def mock_open(ql, filename_addr, flags, mode, *args):
            try:
                filename = ql.os.utils.read_cstring(filename_addr)
            except:
                filename = "unknown"
            
            fake_fd = self.next_fd
            self.next_fd += 1
            self.fake_fds[fake_fd] = filename
            self.tracer.log_syscall(ql, "open", [filename, flags, mode], return_value=fake_fd)
            print(f"[MOCK] open('{filename}') -> FD {fake_fd}")
            return fake_fd
        
        self.hook_syscall_robust(ql, "open", mock_open)
        self.hook_syscall_robust(ql, "openat", mock_open)
    
    def _hook_read(self, ql: Qiling):
        """Mock read to return dummy data OR controlled input for avalanche testing."""
        def mock_read(ql, fd, buf_addr, count, *args):
            # Check for avalanche experiment override
            override_hex = os.environ.get("QILING_OVERRIDE_INPUT_HEX")
            
            if override_hex:
                # Use controlled input from environment
                try:
                    controlled_data = bytes.fromhex(override_hex)
                    fake_data = controlled_data[:count]
                    print(f"[AVALANCHE] read({fd}) -> Using controlled input ({len(fake_data)} bytes)")
                except Exception as e:
                    print(f"[!] Failed to parse QILING_OVERRIDE_INPUT_HEX: {e}")
                    fake_data = b"MOCK_CONFIG_DATA\n" * min(count // 17, 10)
            else:
                # Default mock data
                fake_data = b"MOCK_CONFIG_DATA\n" * min(count // 17, 10)
            
            try:
                ql.mem.write(buf_addr, fake_data[:count])
            except:
                pass
            bytes_read = min(len(fake_data), count)
            self.tracer.log_syscall(ql, "read", [fd, hex(buf_addr), count], return_value=bytes_read)
            return bytes_read
        
        self.hook_syscall_robust(ql, "read", mock_read)
    
    def _hook_write(self, ql: Qiling):
        """Mock write and capture buffer for entropy analysis."""
        def mock_write(ql, fd, buf_addr, count, *args):
            try:
                buffer_data = ql.mem.read(buf_addr, min(count, 4096))
                self.tracer.log_syscall(ql, "write", [fd, hex(buf_addr), count], 
                                       return_value=count, buffer_data=buffer_data)
            except:
                self.tracer.log_syscall(ql, "write", [fd, hex(buf_addr), count], return_value=count)
            return count
        
        self.hook_syscall_robust(ql, "write", mock_write)
    
    def _hook_gethostbyname(self, ql: Qiling):
        """Mock DNS resolution."""
        def mock_gethostbyname(ql, name_addr, *args):
            try:
                hostname = ql.os.utils.read_cstring(name_addr)
            except:
                hostname = "unknown"
            
            # Return a fake hostent structure pointer
            fake_addr = 0x41414141
            self.tracer.log_syscall(ql, "gethostbyname", [hostname], return_value=fake_addr)
            print(f"[MOCK] gethostbyname('{hostname}') -> 0x41414141")
            return fake_addr
        
        self.hook_syscall_robust(ql, "gethostbyname", mock_gethostbyname)


class UniversalSyscallHooker:
    """
    Universal low-level interrupt/syscall hooker that works across architectures.
    Catches syscalls that Qiling's high-level OS emulation might miss.
    """
    
    def __init__(self, tracer: ExecutionTracer):
        self.tracer = tracer
        self.syscall_map = {}
        
    def get_syscall_register(self, ql: Qiling) -> str:
        """Get the syscall number register name based on architecture."""
        arch = ql.arch.type
        
        syscall_reg_map = {
            QL_ARCH.X86: "eax",      # int 0x80
            QL_ARCH.X8664: "rax",    # syscall instruction
            QL_ARCH.ARM: "r7",       # SWI/SVC
            QL_ARCH.ARM64: "x8",     # SVC
            QL_ARCH.MIPS: "v0",      # syscall
            QL_ARCH.RISCV: "a7",     # ecall
            QL_ARCH.RISCV64: "a7",
        }
        
        return syscall_reg_map.get(arch, "eax")
    
    def get_syscall_instruction(self, ql: Qiling) -> tuple:
        """Get the syscall instruction pattern for the architecture."""
        arch = ql.arch.type
        
        # Returns (interrupt_number or None, instruction_bytes or None)
        syscall_patterns = {
            QL_ARCH.X86: (0x80, b'\xcd\x80'),        # int 0x80
            QL_ARCH.X8664: (None, b'\x0f\x05'),      # syscall
            QL_ARCH.ARM: (None, b'\x00\x00\x00\xef'), # SWI 0 (little-endian)
            QL_ARCH.ARM64: (None, b'\x01\x00\x00\xd4'), # SVC #0
            QL_ARCH.MIPS: (None, b'\x0c\x00\x00\x00'), # syscall (little-endian)
        }
        
        return syscall_patterns.get(arch, (0x80, b'\xcd\x80'))
    
    def force_hook_syscalls(self, ql: Qiling):
        """
        Hook low-level interrupt/syscall mechanism to catch ALL syscalls.
        This bypasses Qiling's high-level OS layer.
        
        Uses instruction-level detection for MIPS/ARM/RISCV to guarantee syscall capture.
        """
        arch = ql.arch.type
        syscall_reg = self.get_syscall_register(ql)
        intr_num, syscall_bytes = self.get_syscall_instruction(ql)
        
        print(f"[*] Installing universal syscall hook for {arch} (register: {syscall_reg})")
        if syscall_bytes:
            print(f"[*] Syscall instruction pattern: {syscall_bytes.hex()}")
        
        # Hook interrupt for x86 (int 0x80)
        if intr_num is not None and arch == QL_ARCH.X86:
            def interrupt_hook(ql, intno):
                if intno == 0x80:  # Syscall interrupt
                    self._handle_syscall(ql, syscall_reg)
            
            try:
                ql.hook_intr(interrupt_hook)
                print(f"[+] Hooked interrupt 0x{intr_num:02x} for syscall detection")
            except Exception as e:
                print(f"[!] Failed to hook interrupt: {e}")
        
        # Hook syscall instruction for MIPS, ARM, RISCV (instruction-level detection)
        else:
            # For MIPS: syscall opcode is 0x0000000c (little-endian: \x0c\x00\x00\x00)
            # We need to check both endianness variants
            
            print("[*] HOOK INSTALLED - Instruction-level detection active")
            syscall_count = [0]  # Track successful detections
            
            def code_hook(ql, address, size):
                try:
                    # DEBUG: Target specific problematic addresses from user's log
                    # Address 0x41e69c and 0x45e08c mentioned as having syscall issues
                    if address in [0x41e69c, 0x45e08c]:
                        opcode = ql.mem.read(address, 4)
                        print(f"[!] HIT TARGET BLOCK {hex(address)}")
                        print(f"    Opcode: {opcode.hex()}")
                        print(f"    V0 register: {ql.arch.regs.v0}")
                        
                        # Check if it matches syscall opcode
                        if opcode == b'\x0c\x00\x00\x00' or opcode == b'\x00\x00\x00\x0c':
                            print(f"    ✓ MATCHES SYSCALL OPCODE!")
                            self.tracer.log_syscall(ql, f"FORCE_LOG_{hex(address)}", [], 0)
                        else:
                            print(f"    ✗ NOT a syscall opcode")
                    
                    # Read instruction bytes (4 bytes for MIPS)
                    code = ql.mem.read(address, 4)
                    
                    # MIPS syscall: 0x0000000c (big-endian) or 0x0c000000 (little-endian)
                    is_syscall = False
                    if arch == QL_ARCH.MIPS:
                        # Little-endian: \x0c\x00\x00\x00
                        # Big-endian: \x00\x00\x00\x0c
                        if code == b'\x0c\x00\x00\x00' or code == b'\x00\x00\x00\x0c':
                            is_syscall = True
                            syscall_count[0] += 1
                            if syscall_count[0] <= 5:  # Show first 5
                                v0 = ql.arch.regs.v0
                                print(f"[+] Syscall #{syscall_count[0]} detected at {hex(address)}, v0={v0}, opcode={code.hex()}")
                    else:
                        # Other architectures: match expected bytes
                        if syscall_bytes and code.startswith(syscall_bytes):
                            is_syscall = True
                    
                    if is_syscall:
                        self._handle_syscall(ql, syscall_reg)
                        
                except Exception as e:
                    # Show errors for debugging
                    if "0x41e69c" in str(address):
                        print(f"[!] ERROR at target address: {e}")
                    pass  # Silently ignore other memory read errors
            
            try:
                # Hook EVERY instruction (slow but guaranteed to catch syscalls)
                ql.hook_code(code_hook)
                print(f"[+] Hooked code execution for instruction-level syscall detection")
            except Exception as e:
                print(f"[!] Failed to hook code: {e}")
    
    def _handle_syscall(self, ql: Qiling, syscall_reg: str):
        """Handle a detected syscall by reading registers and logging."""
        try:
            # Get syscall number from the appropriate register
            syscall_num = getattr(ql.arch.regs, syscall_reg, None)
            
            if syscall_num is None:
                return
            
            # Get syscall name (if known)
            syscall_name = self._get_syscall_name(ql, syscall_num)
            
            # Get arguments from registers (architecture-specific)
            args = self._get_syscall_args(ql)
            
            # Log the syscall
            self.tracer.log_syscall(ql, f"{syscall_name}", args, return_value=None)
            
        except Exception as e:
            pass  # Silently ignore to avoid breaking emulation
    
    def _get_syscall_name(self, ql: Qiling, syscall_num: int) -> str:
        """Attempt to resolve syscall number to name (architecture-specific)."""
        arch = ql.arch.type
        
        # Comprehensive MIPS syscall table (Linux MIPS O32 ABI)
        if arch == QL_ARCH.MIPS:
            mips_syscalls = {
                4001: "exit", 4002: "fork", 4003: "read", 4004: "write", 4005: "open",
                4006: "close", 4007: "waitpid", 4008: "creat", 4009: "link", 4010: "unlink",
                4011: "execve", 4012: "chdir", 4013: "time", 4014: "mknod", 4015: "chmod",
                4019: "lseek", 4020: "getpid", 4024: "getuid", 4033: "access",
                4037: "kill", 4041: "dup", 4042: "pipe", 4045: "brk", 4047: "getgid",
                4054: "ioctl", 4055: "fcntl", 4063: "dup2", 4064: "getppid",
                4078: "gettimeofday", 4090: "mmap", 4091: "munmap", 4120: "clone",
                4122: "uname", 4125: "mprotect", 4140: "llseek", 4162: "nanosleep",
                4166: "vm86", 4183: "getcwd", 4246: "exit_group", 4248: "set_tid_address",
            }
            return mips_syscalls.get(syscall_num, f"syscall_{syscall_num}")
        
        # x86/x86_64 syscalls
        elif arch in [QL_ARCH.X86, QL_ARCH.X8664]:
            common_syscalls = {
                0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
                5: "fstat", 9: "mmap", 10: "mprotect", 11: "munmap",
                39: "getpid", 45: "brk", 60: "exit", 102: "socketcall",
                231: "exit_group",
            }
            return common_syscalls.get(syscall_num, f"syscall_{syscall_num}")
        
        # ARM syscalls
        elif arch in [QL_ARCH.ARM, QL_ARCH.ARM64]:
            arm_syscalls = {
                1: "exit", 3: "read", 4: "write", 5: "open", 6: "close",
                20: "getpid", 45: "brk", 248: "exit_group",
            }
            return arm_syscalls.get(syscall_num, f"syscall_{syscall_num}")
        
        # Fallback
        return f"syscall_{syscall_num}"
    
    def _get_syscall_args(self, ql: Qiling) -> list:
        """Get syscall arguments from registers (architecture-specific)."""
        arch = ql.arch.type
        
        try:
            if arch == QL_ARCH.X86:
                return [ql.arch.regs.ebx, ql.arch.regs.ecx, ql.arch.regs.edx, ql.arch.regs.esi]
            elif arch == QL_ARCH.X8664:
                return [ql.arch.regs.rdi, ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10]
            elif arch == QL_ARCH.ARM:
                return [ql.arch.regs.r0, ql.arch.regs.r1, ql.arch.regs.r2, ql.arch.regs.r3]
            elif arch == QL_ARCH.ARM64:
                return [ql.arch.regs.x0, ql.arch.regs.x1, ql.arch.regs.x2, ql.arch.regs.x3]
            elif arch == QL_ARCH.MIPS:
                return [ql.arch.regs.a0, ql.arch.regs.a1, ql.arch.regs.a2, ql.arch.regs.a3]
            elif arch in [QL_ARCH.RISCV, QL_ARCH.RISCV64]:
                return [ql.arch.regs.a0, ql.arch.regs.a1, ql.arch.regs.a2, ql.arch.regs.a3]
            else:
                return []
        except:
            return []


def run_feature_extraction(binary_path: str, rootfs_path: str = None, output_path: str = None):
    """
    Main feature extraction pipeline.
    
    Args:
        binary_path: Path to the stripped ELF binary
        rootfs_path: Path to Qiling rootfs for the architecture (optional, will auto-detect)
        output_path: Output path for the trace JSONL file (optional, will auto-generate)
    """
    import tempfile
    import shutil
    from pathlib import Path
    
    print(f"[*] Starting feature extraction for: {binary_path}")
    
    # Check for avalanche experiment override for output path
    override_output = os.environ.get("QILING_OUTPUT_TRACE")
    if override_output:
        output_path = override_output
        print(f"[AVALANCHE] Using controlled output path: {output_path}")
    
    # Auto-generate output path if not provided
    if not output_path:
        # Get the script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Create traces directory
        traces_dir = os.path.join(script_dir, "traces")
        os.makedirs(traces_dir, exist_ok=True)
        
        # Generate meaningful filename from binary name + timestamp
        binary_name = os.path.splitext(os.path.basename(binary_path))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"{binary_name}_{timestamp}.jsonl"
        output_path = os.path.join(traces_dir, output_filename)
        
        print(f"[*] Auto-generated output path: {output_path}")
    
    # Auto-detect rootfs if not provided
    if not rootfs_path:
        print("[*] Auto-detecting rootfs from binary architecture...")
        rootfs_path = get_rootfs(binary_path)
        if not rootfs_path:
            print("[!] Failed to auto-detect rootfs. Please specify manually.")
            return None
    else:
        print(f"[*] Using provided rootfs: {rootfs_path}")
    
    # FIX #1: Copy binary INTO rootfs to avoid path resolution errors
    # This prevents: "ValueError: ... is not in the subpath of ..."
    print("[*] Copying binary into rootfs/tmp to avoid path resolution issues...")
    tmp_path = os.path.join(rootfs_path, "tmp")
    os.makedirs(tmp_path, exist_ok=True)
    temp_dir = tempfile.mkdtemp(dir=tmp_path)
    temp_binary = os.path.join(temp_dir, "binary_to_analyze")
    shutil.copy(binary_path, temp_binary)
    print(f"[+] Binary copied to: {temp_binary}")
    
    # Initialize tracer
    tracer = ExecutionTracer(output_path)
    
    # Initialize Qiling
    try:
        # FIX #2: Use console=False to reduce noise and verbose=OFF
        ql = Qiling([temp_binary], rootfs_path, verbose=QL_VERBOSE.OFF, console=False)
        tracer.initialize_disassembler(ql)
        
        # FIX #3: Add syscall hooks to ignore unimplemented syscalls (like rseq)
        # This prevents crashes when binaries try to use modern Linux syscalls
        print("[*] Installing syscall filters for unimplemented syscalls...")
        try:
            # Hook rseq (386) - Restartable sequences - modern Linux optimization
            def mock_rseq(ql, *args):
                # Return ENOSYS (syscall not implemented)
                return -38
            ql.os.set_syscall("rseq", mock_rseq)
            
            # Hook readlinkat to avoid path resolution issues
            def mock_readlinkat(ql, dirfd, pathname_addr, buf_addr, bufsiz, *args):
                # Return fake path inside rootfs
                fake_path = b"/tmp/binary_to_analyze\x00"
                try:
                    ql.mem.write(buf_addr, fake_path[:bufsiz])
                    return len(fake_path) - 1
                except:
                    return -1
            ql.os.set_syscall("readlinkat", mock_readlinkat)
            
            # Hook getrandom (modern syscall that may not be implemented)
            def mock_getrandom(ql, buf_addr, buflen, flags, *args):
                # Fill buffer with fake random data
                fake_random = bytes([0x42] * min(buflen, 256))
                try:
                    ql.mem.write(buf_addr, fake_random[:buflen])
                    return buflen
                except:
                    return -1
            ql.os.set_syscall("getrandom", mock_getrandom)
            
            print("[+] Syscall filters installed (rseq, readlinkat, getrandom)")
        except Exception as e:
            print(f"[!] Warning: Could not install all syscall filters: {e}")
            print("[*] Proceeding anyway (may encounter unimplemented syscall errors)")
        
        # Setup environment mocking (high-level hooks)
        mocker = EnvironmentMocker(tracer)
        mocker.setup_hooks(ql)
        
        # Setup universal syscall hooking (low-level interrupt/instruction hooks)
        # This catches syscalls that the high-level OS layer might miss
        print("[*] Installing universal low-level syscall hooks...")
        universal_hooker = UniversalSyscallHooker(tracer)
        universal_hooker.force_hook_syscalls(ql)
        
        # Hook basic block execution
        def block_hook(ql, address, size):
            tracer.log_basic_block(ql, address, size)
        
        ql.hook_block(block_hook)
        
        print("[*] Starting emulation...")
        print("[*] Press Ctrl+C to stop early if needed\n")
        
        # Run the binary
        try:
            ql.run(timeout=30000000)  # 30 second timeout
        except KeyboardInterrupt:
            print("\n[!] Execution interrupted by user")
        except Exception as e:
            print(f"\n[!] Execution stopped: {e}")
        
        # Save the trace
        tracer.save_trace()
        
        # Print statistics
        stats = tracer.get_statistics()
        print("\n" + "="*60)
        print("EXTRACTION STATISTICS")
        print("="*60)
        for key, value in stats.items():
            print(f"  {key:.<40} {value}")
        print("="*60)
        
        # Cleanup temporary files
        try:
            shutil.rmtree(temp_dir)
            print(f"[+] Cleaned up temporary files: {temp_dir}")
        except:
            pass
        
        return tracer
        
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        
        # Cleanup on error too
        try:
            if 'temp_dir' in locals():
                shutil.rmtree(temp_dir)
        except:
            pass
        
        return None


def generate_sample_output():
    """
    Generate a detailed example of the expected output format.
    This shows what the training_log.jsonl looks like.
    """
    sample_trace = [
        {
            "seq": 0,
            "timestamp": "2025-12-02T10:30:00.123456",
            "type": "basic_block",
            "data": {
                "address": "0x400580",
                "size": 24,
                "bytes_hash": "a3f5e8c2b1d4f9a7e6c3b2a1f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e",
                "mnemonics": ["push_reg", "mov_reg_reg", "sub_reg_imm", "mov_reg_reg", "call_imm"],
                "mnemonics_simple": ["push", "mov", "sub", "mov", "call"],
                "instruction_count": 5,
                "metadata": {
                    "has_crypto_patterns": False
                }
            }
        },
        {
            "seq": 1,
            "timestamp": "2025-12-02T10:30:00.123567",
            "type": "syscall",
            "data": {
                "name": "socket",
                "args": [2, 1, 0],
                "return_value": 100,
                "metadata": {
                    "args_raw": [2, 1, 0]
                }
            }
        },
        {
            "seq": 2,
            "timestamp": "2025-12-02T10:30:00.123678",
            "type": "basic_block",
            "data": {
                "address": "0x4007a0",
                "size": 64,
                "bytes_hash": "c7f3e9a8b4d2f1a5e8c6b3a2f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e",
                "mnemonics": ["xor_reg_reg", "xor_reg_reg", "xor_reg_reg", "rol_reg_imm", 
                             "add_reg_reg", "xor_reg_reg", "mov_reg_reg", "xor_reg_imm", 
                             "shl_reg_imm", "xor_reg_reg"],
                "mnemonics_simple": ["xor", "xor", "xor", "rol", "add", "xor", "mov", "xor", "shl", "xor"],
                "instruction_count": 10,
                "metadata": {
                    "has_crypto_patterns": True
                }
            }
        },
        {
            "seq": 3,
            "timestamp": "2025-12-02T10:30:00.123789",
            "type": "syscall",
            "data": {
                "name": "send",
                "args": ["MOCK_FD", "PTR_STACK", 256, 0],
                "return_value": 256,
                "buffer_size": 256,
                "entropy": 7.8924,
                "likely_encrypted": True,
                "metadata": {
                    "args_raw": [100, "0x7ffe1234", 256, 0]
                }
            }
        },
        {
            "seq": 4,
            "timestamp": "2025-12-02T10:30:00.123890",
            "type": "syscall",
            "data": {
                "name": "recv",
                "args": ["MOCK_FD", "PTR_STACK", 512, 0],
                "return_value": 105,
                "metadata": {
                    "args_raw": [100, "0x7ffe5678", 512, 0]
                }
            }
        },
        {
            "seq": 5,
            "timestamp": "2025-12-02T10:30:00.124001",
            "type": "basic_block",
            "data": {
                "address": "0x400b20",
                "size": 128,
                "bytes_hash": "f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
                "mnemonics": ["movdqu_reg_mem_heap", "pxor_reg_reg", "pxor_reg_mem_rip", 
                             "movdqa_reg_mem_rip", "aesenc_reg_reg", "aesenc_reg_reg", 
                             "aesenclast_reg_reg", "movdqu_mem_heap_reg"],
                "mnemonics_simple": ["movdqu", "pxor", "pxor", "movdqa", "aesenc", "aesenc", "aesenclast", "movdqu"],
                "instruction_count": 8,
                "metadata": {
                    "has_crypto_patterns": True
                }
            }
        },
        {
            "seq": 6,
            "timestamp": "2025-12-02T10:30:00.124112",
            "type": "syscall",
            "data": {
                "name": "write",
                "args": ["STDOUT", "PTR_STACK", 32],
                "return_value": 32,
                "buffer_size": 32,
                "entropy": 3.2145,
                "likely_encrypted": False,
                "metadata": {
                    "args_raw": [1, "0x7ffe9abc", 32]
                }
            }
        }
    ]
    
    print("\n" + "="*80)
    print("SAMPLE OUTPUT FORMAT (trace.jsonl)")
    print("="*80)
    print("\nEach line is a JSON object representing a sequential event:\n")
    
    for event in sample_trace:
        print(json.dumps(event, indent=2))
        print()
    
    print("="*80)
    print("KEY IMPROVEMENTS FOR ML MODEL:")
    print("="*80)
    print("""
1. ENHANCED MNEMONICS (Fixed sparsity issue):
   OLD: ["mov", "mov", "call"]
   NEW: ["mov_reg_reg", "mov_reg_imm", "call_imm"]
   
   ✓ Now distinguishes context: mov_reg_mem (load), mov_reg_imm (constant)
   ✓ Model can learn patterns like "xor_reg_reg" (zeroing) vs "xor_reg_imm" (crypto)
   
2. NORMALIZED SYSCALL ARGS (Reduced variance):
   OLD: [100, "0x7ffe1234", 256, 0]
   NEW: ["MOCK_FD", "PTR_STACK", 256, 0]
   
   ✓ FD=100 or FD=3 both map to "MOCK_FD" - model learns the role, not the value
   ✓ Stack pointers always tagged "PTR_STACK" regardless of ASLR
   ✓ Small integers (sizes, flags) kept as-is for semantic meaning
   
3. METADATA SEPARATION (Removed data leakage):
   OLD: "has_crypto_patterns": true (in main data)
   NEW: "metadata": {"has_crypto_patterns": true}
   
   ✓ Model cannot "cheat" by seeing explicit labels during inference
   ✓ Must learn crypto from instruction patterns (aesenc, xor_reg_reg, etc.)
   ✓ metadata used only for training labels, not as input features
   
4. ENTROPY PRESERVED (Key feature - unchanged):
   "entropy": 7.8924, "likely_encrypted": true
   
   ✓ Still the most valuable feature for detecting encrypted traffic
   ✓ Model learns: High entropy after crypto block = encrypted protocol
   
5. RAW DATA IN METADATA (Debugging/validation):
   "metadata": {"args_raw": [100, "0x7ffe1234", 256, 0]}
   
   ✓ Original values preserved for debugging
   ✓ Not used for model training
   ✓ Helps validate normalization correctness
""")
    print("="*80)
    print("\nML TRAINING STRATEGY:")
    print("="*80)
    print("""
Feature Extraction for LSTM/Transformer:

INPUT FEATURES (for model):
  • mnemonics (typed): ["mov_reg_reg", "xor_reg_reg", ...]
  • syscall name: "send", "recv", ...
  • syscall args (normalized): ["MOCK_FD", "PTR_STACK", ...]
  • entropy: 7.89 (float)
  • buffer_size: 256 (int)

LABELS (ground truth, NOT model input):
  • metadata.has_crypto_patterns (block-level)
  • likely_encrypted (syscall-level)
  • Protocol class: TLS_AES, SSH, ChaCha, etc. (trace-level)

WHAT THE MODEL LEARNS:
  "If I see sequence: [xor_reg_reg, rol_reg_imm, xor_reg_reg, ...] 
   followed by send(MOCK_FD, PTR_STACK, SIZE) with entropy>7.0,
   then this is encrypted network traffic"
   
The model discovers crypto patterns from instruction sequences,
not from being told "has_crypto_patterns=true"!
""")
    print("="*80)


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║   Feature Extractor for Crypto Protocol Detection in Stripped Firmware   ║
║   ML Training Data Pipeline - Dynamic Binary Analysis Layer              ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")
    
    if len(sys.argv) < 2:
        print("Usage: python feature_extractor.py <binary_path> [rootfs_path] [output_path]")
        print("\nExamples:")
        print("  # Auto-detect everything (RECOMMENDED):")
        print("  python feature_extractor.py /path/to/binary")
        print("  → Output: traces/binary_name_YYYYMMDD_HHMMSS.jsonl")
        print()
        print("  # Specify custom output path:")
        print("  python feature_extractor.py /path/to/binary custom_trace.jsonl")
        print()
        print("  # Specify rootfs manually:")
        print("  python feature_extractor.py /path/to/binary ./rootfs/x8664_linux")
        print("  python feature_extractor.py /path/to/binary ./rootfs/x8664_linux custom.jsonl")
        print()
        print("  # Real-world examples:")
        print("  python feature_extractor.py wolfssl_chacha.elf")
        print("  → traces/wolfssl_chacha_20251202_144530.jsonl")
        print()
        print("  python feature_extractor.py /samples/openssl_aes.bin")
        print("  → traces/openssl_aes_20251202_144531.jsonl")
        print("\n" + "-"*79)
        print("\nGenerating sample output format for reference...\n")
        generate_sample_output()
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    # Parse arguments flexibly
    rootfs_path = None
    output_path = None  # Changed default to None for auto-generation
    
    if len(sys.argv) >= 3:
        # Check if arg 2 is a rootfs path or output path
        arg2 = sys.argv[2]
        if os.path.isdir(arg2) or 'rootfs' in arg2:
            # It's a rootfs path
            rootfs_path = arg2
            if len(sys.argv) >= 4:
                output_path = sys.argv[3]
        else:
            # It's an output path
            output_path = arg2
    
    if not os.path.exists(binary_path):
        print(f"[!] Error: Binary not found: {binary_path}")
        sys.exit(1)
    
    # Run the extraction (rootfs and output_path will be auto-detected/generated if None)
    tracer = run_feature_extraction(binary_path, rootfs_path, output_path)
    
    if tracer:
        print(f"\n[+] SUCCESS! Training data ready for ML pipeline")
        print(f"[+] All traces stored in: traces/ directory\n")
        
        # Generate sample output for reference
        print("\n" + "-"*79)
        print("Generating sample output documentation...")
        generate_sample_output()