# 🚀 Batch Processing Status - Full Dataset

## Current Status: **IN PROGRESS** ✅

**Started**: December 5, 2025, 00:47
**Dataset**: 1100 crypto binaries (11 algorithms × 100 samples each)
**Progress**: 251 / 1100 (23%)
**Parallel Processes**: 4
**Pipeline**: Full (Extraction → Windowing → Inference)

---

## Dataset Composition

| Algorithm | Count | Description |
|-----------|-------|-------------|
| AES128 | 100 | AES 128-bit |
| AES192 | 100 | AES 192-bit |
| AES256 | 100 | AES 256-bit |
| ECC | 100 | Elliptic Curve Crypto |
| PRNG | 100 | Pseudo-random generators |
| RSA1024 | 100 | RSA 1024-bit |
| RSA4096 | 100 | RSA 4096-bit |
| SHA1 | 100 | SHA-1 hash |
| SHA224 | 100 | SHA-224 hash |
| SHA256 | 100 | SHA-256 hash |
| XOR | 100 | XOR cipher |
| **TOTAL** | **1100** | |

---

## Output Structure

```
batch_results_full/
├── traces/                      # Raw execution traces (JSONL)
│   ├── AES128_arm_O0_v0_*.jsonl
│   ├── AES128_arm_O0_v1_*.jsonl
│   └── ... (1100 files)
│
├── windowed_features/           # ML-ready windowed features
│   ├── AES128_arm_O0_v0_windowed.jsonl
│   ├── AES128_arm_O0_v1_windowed.jsonl
│   └── ... (1100 files)
│
├── analysis_results/            # Crypto inference results
│   ├── AES128_arm_O0_v0_analysis.jsonl
│   ├── AES128_arm_O0_v1_analysis.jsonl
│   └── ... (1100 files)
│
├── loop_analysis/               # Crypto loop analysis (legacy)
│   └── ... (1100 files)
│
├── batch_results.json           # Detailed results per binary
└── training_dataset.json        # ML training dataset with labels
```

---

## Generated Data Per Binary

### 1. Raw Trace (`traces/*.jsonl`)
- **Format**: JSONL (1 event per line)
- **Size**: ~500KB - 2MB per file
- **Content**: 
  - Basic block sequences
  - Syscall sequences
  - Register states
  - Memory states
  - Temporal ordering

**Example**:
```json
{"seq": 42, "type": "basic_block", "data": {"address": "0x400580", "mnemonics": ["xor_reg_reg", "rol_reg_imm"], ...}}
```

### 2. Windowed Features (`windowed_features/*_windowed.jsonl`)
- **Format**: JSONL (1 window per line)
- **Size**: ~10-50KB per file
- **Features**: 60+ per window
  - `xor_density`, `shift_density`, `loop_repetition_score`
  - `stack_entropy_slope`, `register_volatility`
  - `crypto_heuristic_score`, `mnemonic_entropy`
  - And 50+ more...

**Example**:
```json
{"window_id": 42, "features": {"xor_density": 0.23, "shift_density": 0.18, ...}}
```

### 3. Analysis Results (`analysis_results/*_analysis.jsonl`)
- **Format**: JSONL (1 analysis per window)
- **Size**: ~50-200KB per file
- **Content**:
  - `crypto_detection` (probability, algorithm, evidence)
  - `protocol_stage` (HANDSHAKE, ENCRYPTION, etc.)
  - `anomaly_detection` (anomalies found)
  - `explainability` (feature importance, top factors)

**Example**:
```json
{
  "window_id": 42,
  "analysis": {
    "crypto_detection": {
      "is_crypto": true,
      "crypto_probability": 0.87,
      "encryption_algorithm_family": {
        "algorithm": "AES",
        "confidence": 0.82
      }
    }
  }
}
```

---

## Monitoring Commands

```bash
# Check progress
./monitor_progress.sh

# Watch live log
tail -f batch_processing.log

# Count completed binaries
grep -c "✅ \[" batch_processing.log

# Check for errors
grep -i "error\|failed" batch_processing.log

# See current activity
ps aux | grep batch_extract_features
```

---

## Expected Completion

- **Binaries**: 1100
- **Parallel processes**: 4
- **Avg time per binary**: ~0.8 seconds (extraction + windowing + inference)
- **Expected total time**: ~220 seconds ÷ 4 = **~55 minutes**
- **ETA**: ~00:50 (December 5, 2025)

---

## Next Steps After Completion

### 1. Verify Results
```bash
# Check final summary
tail -50 batch_processing.log

# Count generated files
ls batch_results_full/traces/ | wc -l           # Should be 1100
ls batch_results_full/windowed_features/ | wc -l  # Should be 1100
ls batch_results_full/analysis_results/ | wc -l   # Should be 1100
```

### 2. Explore Training Dataset
```bash
# View training dataset summary
cat batch_results_full/training_dataset.json | jq '.summary'

# Check crypto detection rates per algorithm
cat batch_results_full/training_dataset.json | jq '.by_algorithm'
```

### 3. Analyze Results
```python
import json
import pandas as pd

# Load windowed features for ML training
features_list = []
for file in glob('batch_results_full/windowed_features/*.jsonl'):
    with open(file) as f:
        for line in f:
            window = json.loads(line)
            features_list.append(window['features'])

df = pd.DataFrame(features_list)
print(df.describe())  # Statistical summary
```

### 4. Train ML Model
```python
# Load features and labels
X = df[feature_columns]  # 60+ features
y = df['ground_truth_algorithm']  # From filename

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train LSTM
model = build_lstm_model(input_dim=60, num_classes=11)
model.fit(X_train, y_train, epochs=50)

# Evaluate
accuracy = model.evaluate(X_test, y_test)
```

### 5. Replace Heuristic Inference
```python
# Update crypto_inference_engine.py
engine = CryptoProtocolInferenceEngine(
    model_path='models/trained_lstm.h5',
    mode='ml'  # ← Use trained model!
)
```

---

## Known Limitations (Heuristic Mode)

1. **Low crypto detection rate** (~1-2% windows detected)
   - Most execution is setup/cleanup, not crypto
   - Heuristic thresholds conservative
   - **Solution**: Train ML model for better detection

2. **Algorithm misclassification**
   - AES often detected as "ChaCha/Stream (obfuscated)"
   - Heuristics can't distinguish similar patterns
   - **Solution**: Train multi-class classifier

3. **Obfuscation challenges**
   - Low XOR/shift density in obfuscated code
   - **Solution**: ML model learns obfuscation patterns

---

## Success Metrics (Current Heuristics)

- ✅ **100% extraction success rate** (no failures)
- ✅ **Average 0.8s per binary** (fast!)
- ✅ **Full pipeline working** (extraction → windowing → inference)
- ✅ **60+ features extracted** per window
- ⚠️ **1-2% crypto detection** (needs ML model)
- ⚠️ **Algorithm classification** (needs training)

---

## Files Generated

**Total estimated size**: ~2-3 GB for full dataset

| File Type | Count | Size (each) | Total Size |
|-----------|-------|-------------|------------|
| Raw traces | 1100 | ~1 MB | ~1.1 GB |
| Windowed features | 1100 | ~20 KB | ~22 MB |
| Analysis results | 1100 | ~100 KB | ~110 MB |
| Loop analysis | 1100 | ~5 KB | ~5.5 MB |
| **TOTAL** | **4400** | - | **~1.24 GB** |

---

## Contact / Troubleshooting

**If processing fails**:
```bash
# Check log for errors
grep -i "error\|exception\|failed" batch_processing.log

# Re-run failed binaries only
python3 batch_extract_features.py \
    --dataset-dir /home/prajwal/Documents/LSTM-dataset/dataset \
    --output-dir ./batch_results_full \
    --full-pipeline \
    --parallel 4 \
    --timeout 180
```

**If need to restart**:
```bash
# Kill current process
pkill -f batch_extract_features.py

# Delete partial results
rm -rf batch_results_full/

# Start fresh
nohup python3 batch_extract_features.py ... > batch_processing.log 2>&1 &
```

---

**Last Updated**: December 5, 2025, 00:50
**Status**: ✅ Processing (251/1100 complete)
