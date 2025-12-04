#!/bin/bash
# Test YARA Crypto Detection

echo "=================================="
echo "YARA Crypto Detection Tests"
echo "=================================="
echo ""

# Activate virtual environment
source qiling_env/bin/activate

# Test 1: Standalone YARA scanner
echo "[Test 1] Standalone YARA Scanner"
echo "Testing on: wolfssl_chacha_obf_basic.elf"
python3 tests/yara_scanner.py /home/prajwal/Documents/vestigo-data/wolfssl_chacha_obf_basic.elf
echo ""

# Test 2: Integrated detection (if binary works)
echo "[Test 2] Full Integrated Detection with YARA Phase 0"
echo "This will run: YARA → Constants → Symbols → Dynamic Analysis"
echo ""
python3 tests/verify_crypto.py /home/prajwal/Documents/vestigo-data/wolfssl_chacha_obf_basic.elf 2>&1 | head -100

echo ""
echo "=================================="
echo "Test Complete!"
echo "Check logs/ directory for detailed results"
echo "=================================="
