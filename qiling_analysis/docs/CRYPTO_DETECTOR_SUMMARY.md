# Crypto Function Detector - Summary

## Problem Solved
The crypto verification script was failing to detect crypto functions in binaries because it was trying to execute functions in isolation, which caused `UC_ERR_FETCH_UNMAPPED` errors when functions called other helper functions.

## Solution
Changed the approach from:
- ❌ Executing isolated crypto functions with different calling conventions
- ✅ Running the entire binary from main() and detecting crypto functions that exist

## Key Changes

### 1. Binary Execution
- Run binary from entry point instead of trying to execute isolated functions
- Copy binary into rootfs to avoid path resolution issues
- Let the binary run naturally and complete its crypto operations

### 2. Crypto Function Detection
- Auto-detect crypto functions by name pattern matching (`aes`, `des`, `sha`, `encrypt`, `hash`, etc.)
- Inject AES S-Box if needed
- Profile instruction execution to count crypto operations

### 3. Analysis Results
The script now reports:
- ✅ List of detected crypto functions (e.g., `AES_Encrypt`, `AddRoundKey`, `SubBytes`)
- ✅ Binary execution status (shows actual encrypted output)
- ✅ Instruction profiling (crypto-op ratio: 6.11%)
- ✅ Clear indication that binary contains crypto functions

## Usage
```bash
python3 verify_crypto.py /path/to/binary
```

## Example Output
```
[*] Target: aes_128_arm_clang_O0.elf
[*] Rootfs: /home/prajwal/Documents/dynamic/rootfs/arm_linux
[*] Found 12 crypto candidate(s):
    - AddRoundKey @ 0x10738
    - AES_Encrypt @ 0x10964
    - SubBytes @ 0x107a8
    - ShiftRows @ 0x10810
    - KeyExpansion @ 0x10438

[*] Executing binary...
--- System Start (Crypto Mode) ---
Encrypted Data: a2 cc 0d b4 d6 7d fc be 49 4b 63 e0 06 44 81 24 
--- System Shutdown ---

============================================================
   ANALYSIS RESULTS
============================================================

[✓] Binary executed successfully with crypto functions present
[+] Detected 12 crypto-related functions

[*] Instruction Analysis:
    Total Instructions: 31490
    Crypto Operations: 1925
    Crypto-Op Ratio: 6.11%
    [✓] Crypto-op ratio indicates cryptographic computation
```

## Supported Architectures
- ARM (32-bit)
- ARM64 (64-bit)
- x86_64
- MIPS32
- RISCV64

## Files
- `verify_crypto.py` - Main script (updated)
- `verify_crypto_final.py` - Working implementation
- `verify_crypto_v2.py` - Alternative hooking approach
- `test_simple_run.py` - Simple binary execution test

## Git History
```
b6dfca5 - Fix crypto detection: run from main() instead of isolated function calls
10ec124 - aes impl working with good Avalanche Effect (previous version)
```
