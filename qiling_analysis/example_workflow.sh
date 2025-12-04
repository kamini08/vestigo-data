#!/bin/bash
# Example workflow: Extract features from a binary and analyze

# Example binary paths (replace with your actual binaries)
BINARY="./tests/your_binary"
ROOTFS="./rootfs/x8664_linux"
OUTPUT="./traces/my_trace.jsonl"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Crypto Protocol Detection - Feature Extraction Workflow      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "[!] Binary not found: $BINARY"
    echo ""
    echo "Please replace BINARY path in this script with your actual binary."
    echo ""
    echo "Example binaries to test:"
    echo "  - OpenSSL TLS client"
    echo "  - SSH client binary"
    echo "  - Custom IoT firmware"
    echo ""
    exit 1
fi

# Step 2: Check if rootfs exists
if [ ! -d "$ROOTFS" ]; then
    echo "[!] Rootfs not found: $ROOTFS"
    echo ""
    echo "Available rootfs directories:"
    ls -1 rootfs/ 2>/dev/null | head -10
    echo ""
    exit 1
fi

# Step 3: Create output directory
mkdir -p traces

# Step 4: Run feature extraction
echo "[Step 1/3] Extracting features from binary..."
echo "  Binary: $BINARY"
echo "  Rootfs: $ROOTFS"
echo "  Output: $OUTPUT"
echo ""

python3 feature_extractor.py "$BINARY" "$ROOTFS" "$OUTPUT"

if [ $? -ne 0 ]; then
    echo ""
    echo "[!] Feature extraction failed!"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 5: Analyze the trace
echo "[Step 2/3] Analyzing trace quality..."
echo ""

python3 trace_analyzer.py "$OUTPUT"

if [ $? -ne 0 ]; then
    echo ""
    echo "[!] Trace analysis failed!"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 6: Show some example events
echo "[Step 3/3] Sample events from trace:"
echo ""
echo "First 5 events:"
head -5 "$OUTPUT" | jq -c '{seq: .seq, type: .type, key: (if .type == "basic_block" then .data.address else .data.name end)}'
echo ""

echo "Crypto blocks:"
grep '"has_crypto_patterns": true' "$OUTPUT" | head -3 | jq -c '{seq: .seq, addr: .data.address, mnemonics: .data.mnemonics[0:5]}'
echo ""

echo "High-entropy I/O:"
grep '"likely_encrypted": true' "$OUTPUT" | jq -c '{seq: .seq, syscall: .data.name, entropy: .data.entropy, size: .data.buffer_size}'
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✓ Workflow complete!"
echo ""
echo "Next steps:"
echo "  1. Review the quality score from trace_analyzer.py"
echo "  2. If score ≥ 3/5, trace is ready for ML training"
echo "  3. Collect more traces from different binaries"
echo "  4. Use ml_preprocessor.py to prepare training data"
echo ""
echo "Files generated:"
echo "  - $OUTPUT (trace data)"
echo ""
