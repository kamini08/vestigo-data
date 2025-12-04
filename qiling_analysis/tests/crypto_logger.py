#!/usr/bin/env python3
"""
Comprehensive Crypto Detection Logger
Silently logs all analysis data to logs/ directory without affecting terminal output.
"""

import os
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path

class CryptoLogger:
    def __init__(self, binary_path, log_dir="../logs"):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path)
        self.start_time = time.time()
        
        # Calculate binary hash
        try:
            with open(binary_path, 'rb') as f:
                self.binary_hash = hashlib.sha256(f.read()).hexdigest()
        except:
            self.binary_hash = "unknown"
        
        # Create logs directory
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_base = os.path.join(script_dir, log_dir)
        os.makedirs(self.log_base, exist_ok=True)
        
        # Create session directory
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in self.binary_name)
        self.session_dir = os.path.join(self.log_base, f"{safe_name}_{self.timestamp}")
        os.makedirs(self.session_dir, exist_ok=True)
        
        # Initialize data structures
        self.data = {
            "metadata": {
                "binary_name": self.binary_name,
                "binary_path": self.binary_path,
                "sha256": self.binary_hash,
                "timestamp": self.timestamp,
                "start_time": datetime.now().isoformat(),
            },
            "architecture": None,
            "constants": {},
            "function_symbols": [],
            "basic_blocks": {},
            "crypto_loops": [],
            "memory_writes": [],
            "memory_reads": [],
            "register_states": [],
            "instruction_log": [],
            "syscalls": [],
            "execution_trace": [],
            "io_data": {
                "inputs": [],
                "outputs": []
            },
            "statistics": {
                "crypto_ops": {},
                "instruction_categories": {},
                "entropy_timeline": []
            },
            "timing": {},
            "errors": [],
            "verdict": {}
        }
        
        # Performance counters
        self.counters = {
            "total_instructions": 0,
            "total_blocks": 0,
            "crypto_operations": 0,
            "memory_accesses": 0
        }
        
        # Create log files
        self.detailed_log = open(os.path.join(self.session_dir, "detailed.log"), "w")
        self.execution_log = open(os.path.join(self.session_dir, "execution_trace.log"), "w")
        self.memory_log = open(os.path.join(self.session_dir, "memory_access.log"), "w")
        
    def _get_elapsed(self):
        return time.time() - self.start_time
    
    def _write_log(self, message, file_handle=None):
        """Write to log file with timestamp."""
        timestamp = self._get_elapsed()
        line = f"[{timestamp:10.6f}s] {message}\n"
        if file_handle:
            file_handle.write(line)
            file_handle.flush()
        else:
            self.detailed_log.write(line)
            self.detailed_log.flush()
    
    def log_architecture(self, arch):
        """Log detected architecture."""
        self.data["metadata"]["architecture"] = arch
        self.data["architecture"] = arch
        self._write_log(f"ARCHITECTURE: {arch}")
    
    def log_constants(self, constant_results):
        """Log detected crypto constants."""
        self.data["constants"] = constant_results
        for algo, constants in constant_results.items():
            self._write_log(f"CONSTANTS: {algo} - {len(constants)} constant(s)")
            for const in constants:
                self._write_log(f"  - {const.get('constant', 'unknown')} @ {hex(const.get('address', 0))}")
    
    def log_yara_results(self, yara_results):
        """Log YARA scan results."""
        self.data["yara_scan"] = {
            "detected_algorithms": yara_results.get('detected', []),
            "total_matches": yara_results.get('total_matches', 0),
            "scan_time": yara_results.get('scan_time', 0),
            "matches": []
        }
        
        if yara_results.get('detected'):
            self._write_log(f"YARA: Detected {len(yara_results['detected'])} algorithm(s)")
            for algo in yara_results['detected']:
                self._write_log(f"  - {algo}")
            
            # Log detailed matches
            for match in yara_results.get('matches', []):
                self.data["yara_scan"]["matches"].append({
                    "rule": match['rule'],
                    "algorithm": match['algorithm'],
                    "confidence": match['confidence'],
                    "description": match['description'],
                    "match_count": match['match_count'],
                    "offsets": [f"0x{off:x}" for off in match['offsets'][:10]]  # First 10
                })
                self._write_log(f"  Match: {match['rule']} ({match['algorithm']}, {match['confidence']}%)")
        else:
            self._write_log("YARA: No crypto constants detected")
    
    def log_function_symbols(self, symbols):
        """Log detected function symbols."""
        self.data["function_symbols"] = symbols
        self._write_log(f"FUNCTION_SYMBOLS: {len(symbols)} detected")
        for sym in symbols[:20]:  # Log first 20
            self._write_log(f"  - {sym}")
    
    def log_basic_block(self, address, size, exec_count, crypto_ops, total_ops, is_loop):
        """Log basic block execution."""
        addr_hex = hex(address)
        
        if addr_hex not in self.data["basic_blocks"]:
            self.data["basic_blocks"][addr_hex] = {
                "address": addr_hex,
                "size": size,
                "exec_count": 0,
                "crypto_ops": 0,
                "total_ops": 0,
                "is_loop": False,
                "first_seen": self._get_elapsed()
            }
        
        bb = self.data["basic_blocks"][addr_hex]
        bb["exec_count"] = exec_count
        bb["crypto_ops"] = crypto_ops
        bb["total_ops"] = total_ops
        bb["is_loop"] = is_loop
        bb["last_seen"] = self._get_elapsed()
        bb["crypto_ratio"] = crypto_ops / total_ops if total_ops > 0 else 0
        
        self.counters["total_blocks"] += 1
        self.counters["total_instructions"] += total_ops
        self.counters["crypto_operations"] += crypto_ops
        
        # Log to execution trace
        self._write_log(f"BB: {addr_hex} exec={exec_count} crypto={crypto_ops}/{total_ops}", self.execution_log)
    
    def log_crypto_loop(self, address, iterations, crypto_ops, total_ops, crypto_ratio):
        """Log detected crypto loop."""
        loop_info = {
            "address": hex(address),
            "iterations": iterations,
            "crypto_ops": crypto_ops,
            "total_ops": total_ops,
            "crypto_ratio": crypto_ratio,
            "timestamp": self._get_elapsed()
        }
        self.data["crypto_loops"].append(loop_info)
        self._write_log(f"CRYPTO_LOOP: {hex(address)} - {iterations} iterations, {crypto_ratio:.1%} crypto-ops")
    
    def log_memory_write(self, address, size, data, entropy=None):
        """Log memory write operation."""
        write_info = {
            "type": "write",
            "address": hex(address),
            "size": size,
            "timestamp": self._get_elapsed(),
            "data_sample": data[:32].hex() if len(data) >= 32 else data.hex(),
            "entropy": entropy
        }
        self.data["memory_writes"].append(write_info)
        self.counters["memory_accesses"] += 1
        
        entropy_str = f" entropy={entropy:.2f}" if entropy else ""
        self._write_log(f"MEM_WRITE: {hex(address)} size={size}{entropy_str}", self.memory_log)
    
    def log_memory_read(self, address, size, data=None):
        """Log memory read operation."""
        read_info = {
            "type": "read",
            "address": hex(address),
            "size": size,
            "timestamp": self._get_elapsed()
        }
        if data:
            read_info["data_sample"] = data[:32].hex() if len(data) >= 32 else data.hex()
        
        self.data["memory_reads"].append(read_info)
        self.counters["memory_accesses"] += 1
        
        self._write_log(f"MEM_READ: {hex(address)} size={size}", self.memory_log)
    
    def log_register_state(self, pc, registers):
        """Log register states at specific PC."""
        state = {
            "pc": hex(pc),
            "timestamp": self._get_elapsed(),
            "registers": {k: hex(v) if isinstance(v, int) else str(v) for k, v in registers.items()}
        }
        self.data["register_states"].append(state)
    
    def log_instruction(self, address, mnemonic, operands, is_crypto_op):
        """Log individual instruction."""
        instr = {
            "address": hex(address),
            "mnemonic": mnemonic,
            "operands": operands,
            "is_crypto": is_crypto_op,
            "timestamp": self._get_elapsed()
        }
        self.data["instruction_log"].append(instr)
        
        # Update instruction categories
        if mnemonic not in self.data["statistics"]["instruction_categories"]:
            self.data["statistics"]["instruction_categories"][mnemonic] = 0
        self.data["statistics"]["instruction_categories"][mnemonic] += 1
        
        # Update crypto ops statistics
        if is_crypto_op:
            if mnemonic not in self.data["statistics"]["crypto_ops"]:
                self.data["statistics"]["crypto_ops"][mnemonic] = 0
            self.data["statistics"]["crypto_ops"][mnemonic] += 1
    
    def log_syscall(self, syscall_name, syscall_num, args=None, return_value=None):
        """Log system call."""
        syscall_info = {
            "name": syscall_name,
            "number": syscall_num,
            "timestamp": self._get_elapsed(),
            "args": args,
            "return_value": return_value
        }
        self.data["syscalls"].append(syscall_info)
        self._write_log(f"SYSCALL: {syscall_name}({syscall_num}) args={args} ret={return_value}")
    
    def log_io_input(self, data, source="stdin"):
        """Log input data."""
        io_info = {
            "source": source,
            "timestamp": self._get_elapsed(),
            "size": len(data),
            "data": data.hex() if isinstance(data, bytes) else str(data)
        }
        self.data["io_data"]["inputs"].append(io_info)
        self._write_log(f"INPUT: {source} size={len(data)}")
    
    def log_io_output(self, data, destination="stdout"):
        """Log output data."""
        io_info = {
            "destination": destination,
            "timestamp": self._get_elapsed(),
            "size": len(data),
            "data": data.hex() if isinstance(data, bytes) else str(data)
        }
        self.data["io_data"]["outputs"].append(io_info)
        self._write_log(f"OUTPUT: {destination} size={len(data)}")
    
    def log_entropy_sample(self, location, entropy, data_size):
        """Log entropy measurement."""
        sample = {
            "location": location,
            "entropy": entropy,
            "size": data_size,
            "timestamp": self._get_elapsed()
        }
        self.data["statistics"]["entropy_timeline"].append(sample)
    
    def log_timing(self, phase, duration):
        """Log phase timing."""
        self.data["timing"][phase] = {
            "duration": duration,
            "timestamp": self._get_elapsed()
        }
        self._write_log(f"TIMING: {phase} = {duration:.3f}s")
    
    def log_error(self, error_msg, exception=None):
        """Log error."""
        error_info = {
            "message": error_msg,
            "timestamp": self._get_elapsed(),
            "exception": str(exception) if exception else None
        }
        self.data["errors"].append(error_info)
        self._write_log(f"ERROR: {error_msg}")
        if exception:
            self._write_log(f"  Exception: {exception}")
    
    def log_verdict(self, confidence_score, confidence_level, reasons):
        """Log final verdict."""
        self.data["verdict"] = {
            "confidence_score": confidence_score,
            "confidence_level": confidence_level,
            "reasons": reasons,
            "result": "CRYPTO_DETECTED" if confidence_score >= 40 else "NO_CRYPTO",
            "timestamp": self._get_elapsed()
        }
        self._write_log(f"VERDICT: {confidence_level} ({confidence_score}/100)")
        for reason in reasons:
            self._write_log(f"  - {reason}")
    
    def finalize(self):
        """Save all logs and close files."""
        # Add final statistics
        elapsed = self._get_elapsed()
        self.data["metadata"]["end_time"] = datetime.now().isoformat()
        self.data["metadata"]["elapsed_time"] = elapsed
        
        self.data["statistics"]["counters"] = {
            "total_instructions": self.counters["total_instructions"],
            "total_blocks": self.counters["total_blocks"],
            "crypto_operations": self.counters["crypto_operations"],
            "memory_accesses": self.counters["memory_accesses"],
            "instructions_per_second": self.counters["total_instructions"] / elapsed if elapsed > 0 else 0,
            "blocks_per_second": self.counters["total_blocks"] / elapsed if elapsed > 0 else 0
        }
        
        # Save JSON files
        with open(os.path.join(self.session_dir, "summary.json"), "w") as f:
            json.dump(self.data, f, indent=2)
        
        with open(os.path.join(self.session_dir, "basic_blocks.json"), "w") as f:
            json.dump(self.data["basic_blocks"], f, indent=2)
        
        with open(os.path.join(self.session_dir, "constants.json"), "w") as f:
            json.dump(self.data["constants"], f, indent=2)
        
        with open(os.path.join(self.session_dir, "crypto_loops.json"), "w") as f:
            json.dump(self.data["crypto_loops"], f, indent=2)
        
        with open(os.path.join(self.session_dir, "memory_operations.json"), "w") as f:
            json.dump({
                "writes": self.data["memory_writes"],
                "reads": self.data["memory_reads"]
            }, f, indent=2)
        
        with open(os.path.join(self.session_dir, "instructions.json"), "w") as f:
            json.dump(self.data["instruction_log"], f, indent=2)
        
        with open(os.path.join(self.session_dir, "statistics.json"), "w") as f:
            json.dump(self.data["statistics"], f, indent=2)
        
        # Create human-readable summary
        self._create_text_summary()
        
        # Close log files
        self.detailed_log.close()
        self.execution_log.close()
        self.memory_log.close()
        
        return self.session_dir
    
    def _create_text_summary(self):
        """Create human-readable summary."""
        summary_path = os.path.join(self.session_dir, "SUMMARY.txt")
        
        with open(summary_path, "w") as f:
            f.write("="*80 + "\n")
            f.write("CRYPTO DETECTION ANALYSIS - COMPREHENSIVE SUMMARY\n")
            f.write("="*80 + "\n\n")
            
            # Binary info
            meta = self.data["metadata"]
            f.write("BINARY INFORMATION\n")
            f.write("-"*80 + "\n")
            f.write(f"Name:           {meta['binary_name']}\n")
            f.write(f"Path:           {meta['binary_path']}\n")
            f.write(f"SHA256:         {meta['sha256']}\n")
            f.write(f"Architecture:   {meta.get('architecture', 'Unknown')}\n")
            f.write(f"Analysis Time:  {meta['start_time']}\n")
            f.write(f"Duration:       {meta.get('elapsed_time', 0):.2f}s\n\n")
            
            # Constants
            f.write("CRYPTO CONSTANTS DETECTED\n")
            f.write("-"*80 + "\n")
            if self.data["constants"]:
                total_constants = sum(len(v) for v in self.data["constants"].values())
                f.write(f"Total algorithms: {len(self.data['constants'])}\n")
                f.write(f"Total constants:  {total_constants}\n\n")
                for algo, constants in self.data["constants"].items():
                    f.write(f"{algo}: {len(constants)} constant(s)\n")
                    for const in constants[:10]:
                        f.write(f"  @ {hex(const.get('address', 0))}: {const.get('constant', 'unknown')}\n")
            else:
                f.write("None detected\n")
            f.write("\n")
            
            # Crypto loops
            f.write("CRYPTO LOOPS (TOP 20)\n")
            f.write("-"*80 + "\n")
            loops = sorted(self.data["crypto_loops"], key=lambda x: x["iterations"], reverse=True)
            if loops:
                f.write(f"Total crypto loops: {len(loops)}\n\n")
                for loop in loops[:20]:
                    f.write(f"{loop['address']}: {loop['iterations']} iterations, "
                           f"{loop['crypto_ratio']:.1%} crypto-ops ({loop['crypto_ops']}/{loop['total_ops']})\n")
            else:
                f.write("None detected\n")
            f.write("\n")
            
            # Basic blocks
            f.write("BASIC BLOCK STATISTICS\n")
            f.write("-"*80 + "\n")
            f.write(f"Total unique blocks:  {len(self.data['basic_blocks'])}\n")
            crypto_blocks = sum(1 for bb in self.data['basic_blocks'].values() if bb.get('crypto_ratio', 0) > 0.3)
            f.write(f"Crypto-heavy blocks:  {crypto_blocks}\n")
            loops_count = sum(1 for bb in self.data['basic_blocks'].values() if bb.get('is_loop', False))
            f.write(f"Loop blocks:          {loops_count}\n\n")
            
            # Memory operations
            f.write("MEMORY OPERATIONS\n")
            f.write("-"*80 + "\n")
            f.write(f"Total writes:         {len(self.data['memory_writes'])}\n")
            f.write(f"Total reads:          {len(self.data['memory_reads'])}\n")
            high_entropy = sum(1 for w in self.data['memory_writes'] if w.get('entropy', 0) > 3.5)
            f.write(f"High-entropy writes:  {high_entropy}\n\n")
            
            # Instructions
            f.write("INSTRUCTION STATISTICS\n")
            f.write("-"*80 + "\n")
            stats = self.data["statistics"]
            f.write(f"Total instructions:   {stats['counters']['total_instructions']:,}\n")
            f.write(f"Crypto operations:    {stats['counters']['crypto_operations']:,}\n")
            crypto_ratio = (stats['counters']['crypto_operations'] / stats['counters']['total_instructions'] * 100) if stats['counters']['total_instructions'] > 0 else 0
            f.write(f"Crypto-op ratio:      {crypto_ratio:.2f}%\n\n")
            
            if stats.get('crypto_ops'):
                f.write("Top crypto operations:\n")
                top_ops = sorted(stats['crypto_ops'].items(), key=lambda x: x[1], reverse=True)[:10]
                for op, count in top_ops:
                    f.write(f"  {op}: {count:,}\n")
            f.write("\n")
            
            # Performance
            f.write("PERFORMANCE METRICS\n")
            f.write("-"*80 + "\n")
            counters = stats["counters"]
            f.write(f"Execution time:       {meta.get('elapsed_time', 0):.2f}s\n")
            f.write(f"Instructions/sec:     {counters.get('instructions_per_second', 0):,.0f}\n")
            f.write(f"Blocks/sec:           {counters.get('blocks_per_second', 0):,.0f}\n")
            f.write(f"Memory accesses:      {counters.get('memory_accesses', 0):,}\n\n")
            
            # Syscalls
            if self.data["syscalls"]:
                f.write("SYSTEM CALLS\n")
                f.write("-"*80 + "\n")
                f.write(f"Total syscalls:       {len(self.data['syscalls'])}\n")
                syscall_counts = {}
                for sc in self.data["syscalls"]:
                    name = sc.get("name", "unknown")
                    syscall_counts[name] = syscall_counts.get(name, 0) + 1
                f.write("\nTop syscalls:\n")
                for name, count in sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"  {name}: {count}\n")
                f.write("\n")
            
            # Verdict
            f.write("FINAL VERDICT\n")
            f.write("-"*80 + "\n")
            verdict = self.data["verdict"]
            f.write(f"Confidence Score:     {verdict.get('confidence_score', 0)}/100\n")
            f.write(f"Confidence Level:     {verdict.get('confidence_level', 'UNKNOWN')}\n")
            f.write(f"Result:               {verdict.get('result', 'UNKNOWN')}\n\n")
            
            if verdict.get('reasons'):
                f.write("Detection Reasons:\n")
                for reason in verdict['reasons']:
                    f.write(f"  - {reason}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write(f"Logs saved to: {self.session_dir}\n")
            f.write("="*80 + "\n")
