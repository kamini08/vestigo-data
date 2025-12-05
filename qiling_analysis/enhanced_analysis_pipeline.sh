#!/bin/bash
# Enhanced Crypto Detection Pipeline
# Demonstrates the improved detection system with structural patterns and runtime profiling

set -e

BINARY_PATH="${1:-}"
BINARY_NAME=$(basename "$BINARY_PATH" 2>/dev/null || echo "unknown")
OUTPUT_DIR="./enhanced_analysis_${BINARY_NAME}_$(date +%Y%m%d_%H%M%S)"

if [ -z "$BINARY_PATH" ]; then
    echo "Usage: $0 <path_to_binary>"
    echo ""
    echo "Example:"
    echo "  $0 ./binaries/AES128_x86_64_O2"
    exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found: $BINARY_PATH"
    exit 1
fi

echo "========================================="
echo "Enhanced Crypto Detection Pipeline"
echo "========================================="
echo "Binary: $BINARY_PATH"
echo "Output: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Step 1: Extract execution trace with runtime profiling
echo "[1/5] Extracting execution trace with runtime profiling..."
python3 feature_extractor.py \
    --binary "$BINARY_PATH" \
    --output "$OUTPUT_DIR/trace.jsonl" \
    --enable-coalescing

if [ ! -f "$OUTPUT_DIR/trace.jsonl" ]; then
    echo "Error: Trace extraction failed"
    exit 1
fi

echo "  ✓ Trace extracted: $OUTPUT_DIR/trace.jsonl"
echo ""

# Step 2: Advanced pattern detection on raw trace
echo "[2/5] Running advanced pattern detection..."
python3 advanced_pattern_detector.py \
    "$OUTPUT_DIR/trace.jsonl" \
    "$OUTPUT_DIR/pattern_analysis.json"

if [ -f "$OUTPUT_DIR/pattern_analysis.json" ]; then
    echo "  ✓ Pattern analysis: $OUTPUT_DIR/pattern_analysis.json"
    echo ""
    echo "  Pattern Detection Summary:"
    python3 -c "
import json
with open('$OUTPUT_DIR/pattern_analysis.json', 'r') as f:
    data = json.load(f)
    print(f\"    - SPN Score:        {data.get('spn_score', 0.0):.2f}\")
    print(f\"    - NTT Score:        {data.get('ntt_score', 0.0):.2f}\")
    print(f\"    - MODEXP Score:     {data.get('modexp_score', 0.0):.2f}\")
    print(f\"    - BigInt Density:   {data.get('bigint_density', 0.0):.2f}\")
    print(f\"    - Feistel Score:    {data.get('feistel_score', 0.0):.2f}\")
    print(f\"    - Evidence Found:   {len(data.get('structural_evidence', []))}\")
"
fi
echo ""

# Step 3: Extract windowed features (includes advanced patterns)
echo "[3/5] Extracting windowed features..."
python3 window_feature_extractor.py \
    --trace "$OUTPUT_DIR/trace.jsonl" \
    --output "$OUTPUT_DIR/windowed_features.json" \
    --window-size 50 \
    --stride 25

if [ ! -f "$OUTPUT_DIR/windowed_features.json" ]; then
    echo "Error: Window feature extraction failed"
    exit 1
fi

echo "  ✓ Windowed features: $OUTPUT_DIR/windowed_features.json"
echo ""

# Step 4: Generate enhanced JSONL training data
echo "[4/5] Generating enhanced training dataset..."

# Try to infer algorithm from filename
ALGORITHM=$(echo "$BINARY_NAME" | cut -d'_' -f1)

python3 enhanced_dataset_generator.py \
    --trace "$OUTPUT_DIR/trace.jsonl" \
    --windowed-features "$OUTPUT_DIR/windowed_features.json" \
    --output "$OUTPUT_DIR/training_data.jsonl" \
    --label "$ALGORITHM"

if [ ! -f "$OUTPUT_DIR/training_data.jsonl" ]; then
    echo "Error: Enhanced dataset generation failed"
    exit 1
fi

echo "  ✓ Training data: $OUTPUT_DIR/training_data.jsonl"
echo ""

# Step 5: Show summary of enhanced features
echo "[5/5] Enhanced Feature Summary"
echo "========================================"

python3 << 'EOF'
import json
import sys

# Load training data
with open(f'$OUTPUT_DIR/training_data.jsonl', 'r') as f:
    samples = [json.loads(line) for line in f]

print(f"Total samples: {len(samples)}")
print("")

# Aggregate statistics
spn_scores = [s['structural_pattern']['spn_score'] for s in samples]
ntt_scores = [s['structural_pattern']['ntt_score'] for s in samples]
modexp_scores = [s['structural_pattern']['modexp_score'] for s in samples]

print("Structural Pattern Detection:")
print(f"  SPN detected in:     {sum(1 for s in spn_scores if s > 0.5)} / {len(samples)} windows")
print(f"  NTT detected in:     {sum(1 for s in ntt_scores if s > 0.5)} / {len(samples)} windows")
print(f"  MODEXP detected in:  {sum(1 for s in modexp_scores if s > 0.5)} / {len(samples)} windows")
print("")

# Dominant patterns
from collections import Counter
patterns = [s['dominant_pattern'] for s in samples]
pattern_counts = Counter(patterns)
print("Dominant Patterns:")
for pattern, count in pattern_counts.most_common():
    print(f"  {pattern}: {count} windows ({count/len(samples)*100:.1f}%)")
print("")

# Runtime characteristics
total_mem_accesses = sum(s['runtime_metrics']['memory_accesses'] for s in samples)
avg_mem_accesses = total_mem_accesses / len(samples) if samples else 0
max_footprint = max((s['runtime_metrics']['memory_footprint_bytes'] for s in samples), default=0)

print("Runtime Characteristics:")
print(f"  Avg memory accesses/window: {avg_mem_accesses:.0f}")
print(f"  Max memory footprint: {max_footprint} bytes")
print("")

# Algorithm hints
algo_hints = {
    'AES-like': sum(s['algorithm_hints']['is_aes_like'] for s in samples),
    'RSA-like': sum(s['algorithm_hints']['is_rsa_like'] for s in samples),
    'KYBER-like': sum(s['algorithm_hints']['is_kyber_like'] for s in samples),
    'Custom Block Cipher': sum(s['algorithm_hints']['is_custom_block_cipher'] for s in samples),
    'Custom Asymmetric': sum(s['algorithm_hints']['is_custom_asymmetric'] for s in samples),
}

print("Algorithm Classification Hints:")
for hint, count in algo_hints.items():
    if count > 0:
        print(f"  {hint}: {int(count)} windows")
print("")

# Round detection
rounds_detected = sum(s['round_detected'] for s in samples)
max_reps = max((s['max_repetitions'] for s in samples), default=0)

print("Round Detection:")
print(f"  Rounds detected: {rounds_detected} / {len(samples)} windows")
print(f"  Max repetitions: {max_reps}")

EOF

echo ""
echo "========================================="
echo "✓ Enhanced analysis complete!"
echo "========================================="
echo ""
echo "Output files:"
echo "  - Trace:              $OUTPUT_DIR/trace.jsonl"
echo "  - Pattern Analysis:   $OUTPUT_DIR/pattern_analysis.json"
echo "  - Windowed Features:  $OUTPUT_DIR/windowed_features.json"
echo "  - Training Data:      $OUTPUT_DIR/training_data.jsonl"
echo ""
echo "Next steps:"
echo "  1. Review pattern_analysis.json for structural detections"
echo "  2. Use training_data.jsonl for LSTM training"
echo "  3. Compare advanced scores vs basic heuristics"
