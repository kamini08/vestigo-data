# Feature Extraction Pipeline for ML-Based Crypto Protocol Detection

> **Building the data ingestion layer for detecting cryptographic protocols (TLS, SSH, AES, ChaCha) in stripped firmware using LSTM/Transformer models.**

## 🎯 Project Goal

Train an ML model to classify cryptographic protocols in **stripped ELF binaries** (no symbols, MIPS/ARM/x86) by analyzing execution traces. The model learns to recognize protocol "grammar" from:
- **Basic block instruction sequences** (the "words")
- **Syscall patterns** (the "punctuation")
- **I/O entropy** (encrypted vs. plaintext data)

---

## 📦 What's Included

### Core Tools

| File | Purpose | Lines |
|------|---------|-------|
| **`feature_extractor.py`** | Extract execution traces from binaries | ~650 |
| **`trace_analyzer.py`** | Validate trace quality for ML | ~400 |
| **`ml_preprocessor.py`** | Convert traces to ML-ready format | ~350 |
| **`example_workflow.sh`** | End-to-end example script | ~80 |

### Documentation

| File | Purpose |
|------|---------|
| **`QUICKSTART_GUIDE.md`** | Get started in 3 steps |
| **`FEATURE_EXTRACTOR_README.md`** | Comprehensive documentation |
| **`PROJECT_SUMMARY.md`** | Technical implementation details |
| **`sample_trace.jsonl`** | Example output format |

---

## 🚀 Quick Start

### 1. Extract Features from Binary

```bash
python3 feature_extractor.py <binary> <rootfs> trace.jsonl
```

**Example:**
```bash
python3 feature_extractor.py \
    ./tests/ssl_client \
    ./rootfs/x8664_linux \
    trace.jsonl
```

### 2. Analyze Trace Quality

```bash
python3 trace_analyzer.py trace.jsonl
```

**Output shows:**
- Event statistics
- Crypto patterns detected
- Entropy distribution
- **Quality score (0-5)** ← Look for ≥3/5

### 3. Prepare for ML Training

```python
from ml_preprocessor import TracePreprocessor, load_traces

# Load traces
traces = load_traces(['trace1.jsonl', 'trace2.jsonl'])

# Build vocabularies
preprocessor = TracePreprocessor()
preprocessor.build_vocabularies(traces)

# Create training data
X, labels = preprocessor.create_training_data(traces)
# X shape: (num_sequences, 100 timesteps, 27 features)
```

### 4. Use in Your ML Pipeline

See `QUICKSTART_GUIDE.md` for LSTM/Transformer examples.

---

## 📊 What the Output Looks Like

### Trace Format (trace.jsonl)

Each line is a JSON event in sequential order:

```json
{"seq": 0, "type": "basic_block", "data": {
  "address": "0x400580",
  "mnemonics": ["push", "mov", "call"],
  "has_crypto_patterns": false
}}

{"seq": 1, "type": "syscall", "data": {
  "name": "socket",
  "args": [2, 1, 0],
  "return_value": 100
}}

{"seq": 2, "type": "basic_block", "data": {
  "address": "0x4007a0",
  "mnemonics": ["xor", "xor", "rol", "add", "xor"],
  "has_crypto_patterns": true
}}

{"seq": 3, "type": "syscall", "data": {
  "name": "send",
  "buffer_size": 256,
  "entropy": 7.8924,
  "likely_encrypted": true
}}
```

**Key Pattern:** Crypto block → High-entropy I/O = Encrypted protocol

---

## 🔑 Key Features for ML

### 1. **Temporal Sequences** (for LSTM/Transformer)
```
Block → Syscall → Block → Syscall → ...
```
Preserves execution order to learn protocol state machines.

### 2. **Instruction Mnemonics** (for embedding)
```
["xor", "rol", "xor"] ← ChaCha20 pattern
["aesenc", "aesenc"] ← AES pattern
```
Treated as "words" for NLP-style learning.

### 3. **Shannon Entropy** (crypto detection)
```
entropy=3.2 → Plaintext (e.g., TLS handshake)
entropy=7.9 → Ciphertext (e.g., encrypted data)
```
Distinguishes encrypted from plaintext I/O.

### 4. **Block Hashing** (code reuse detection)
```
bytes_hash=a3f5e8... → Unique identifier for code blocks
```
Robust to ASLR/PIE, detects library reuse.

---

## 🏗️ Architecture

```
┌─────────────────────────┐
│   Stripped ELF Binary   │  (MIPS/ARM/x86, no symbols)
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│  Qiling Emulation       │  (Full system emulation)
│  + Capstone Disasm      │  (Instruction decoding)
│  + Environment Mocking  │  (Force protocol execution)
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│  Unified Trace (JSONL)  │
│  • Basic blocks         │  ← "Words"
│  • Syscalls             │  ← "Punctuation"
│  • Entropy annotations  │  ← Crypto signal
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│  ML Preprocessing       │
│  • Vocabularies         │
│  • Feature vectors      │
│  • Sliding windows      │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│  LSTM/Transformer       │
│  Model Training         │
└─────────────────────────┘
```

---

## 📚 Documentation Guide

**Start here:**
1. **`QUICKSTART_GUIDE.md`** - Fast introduction (10 min read)
2. **`example_workflow.sh`** - Automated example
3. **`sample_trace.jsonl`** - See actual output

**Deep dive:**
4. **`FEATURE_EXTRACTOR_README.md`** - Full technical docs
5. **`PROJECT_SUMMARY.md`** - Implementation details

---

## 🔧 Installation

### Prerequisites

```bash
# Python 3.8+
pip install qiling capstone

# Optional (for ML preprocessing)
pip install numpy tensorflow  # or pytorch
```

### Verify Installation

```bash
# Run on sample trace
python3 trace_analyzer.py sample_trace.jsonl

# Should output statistics and quality score
```

---

## 🎓 Use Cases

### 1. IoT Firmware Analysis
```bash
# Extract from ARM router firmware
python3 feature_extractor.py router.elf ./rootfs/arm_linux trace.jsonl
```

### 2. Malware Protocol Detection
```bash
# Analyze C2 communication in malware
python3 feature_extractor.py trojan.elf ./rootfs/x8664_linux malware_trace.jsonl
```

### 3. Embedded Device Security
```bash
# Detect crypto in MIPS IoT device
python3 feature_extractor.py iot_device.elf ./rootfs/mips32_linux iot_trace.jsonl
```

---

## 📊 Expected Results

### High-Quality Trace (Ready for ML)
```
Total Events:              5,432
Unique Blocks:             1,234
Crypto Pattern Blocks:     156
High-Entropy I/O:          23
Quality Score:             5/5 ✓ EXCELLENT
```

### Low-Quality Trace (Need longer run)
```
Total Events:              87
Unique Blocks:             34
Crypto Pattern Blocks:     0
High-Entropy I/O:          0
Quality Score:             1/5 ✗ POOR
```

---

## 🐛 Troubleshooting

### Binary exits immediately?
- Environment mocking should prevent this
- Check which syscall causes exit with `strace`
- Add missing syscall hook in `EnvironmentMocker`

### No crypto patterns detected?
- Binary may not use crypto
- Or crypto is in library calls (not inline)
- Check mnemonics manually: `jq '.data.mnemonics' trace.jsonl`

### Low entropy on encrypted data?
- Entropy requires buffers >32 bytes
- Small packets may appear low-entropy

**See `QUICKSTART_GUIDE.md` for more troubleshooting.**

---

## 🎯 Next Steps

### Phase 1: Data Collection
- Collect 500+ binaries per protocol class
- Run feature extraction on all
- Aim for quality scores ≥4/5

### Phase 2: ML Training
```python
# Prepare data
from ml_preprocessor import TracePreprocessor

traces = load_traces(glob('traces/*.jsonl'))
preprocessor = TracePreprocessor()
X, y = preprocessor.prepare_dataset(traces)

# Train LSTM
model = build_lstm_model(input_shape=(100, 27))
model.fit(X, y, epochs=50, validation_split=0.2)
```

### Phase 3: Evaluation
- Test on unseen binaries
- Measure precision/recall per protocol
- Confusion matrix analysis

---

## 📈 Expected ML Performance

### Target Metrics (After Training)
- **TLS vs. SSH:** >95% accuracy
- **AES vs. ChaCha:** >90% accuracy
- **Encrypted vs. Plaintext:** >98% accuracy

### Training Data Requirements
- **Minimum:** 100 binaries per class
- **Recommended:** 500+ binaries per class
- **Diversity:** Multiple implementations (OpenSSL, WolfSSL, mbedTLS)

---

## 🤝 Contributing

Improvements welcome:
- Additional architecture support (RISC-V, PowerPC)
- More syscall hooks
- Better crypto pattern heuristics
- Real-time streaming mode

---

## 📝 Citation

```bibtex
@misc{crypto_protocol_detection_2025,
  title={Feature Extraction for ML-Based Cryptographic Protocol Detection},
  author={Dynamic Binary Analysis Framework},
  year={2025},
  howpublished={GitHub}
}
```

---

## 🔗 Resources

- **Qiling Framework:** https://github.com/qilingframework/qiling
- **Capstone Engine:** https://www.capstone-engine.org/
- **LSTM Tutorial:** https://colah.github.io/posts/2015-08-Understanding-LSTMs/
- **Transformer Paper:** https://arxiv.org/abs/1706.03762

---

## ✅ Validation

Run the test workflow:

```bash
./example_workflow.sh
```

Or manually:

```bash
# 1. Analyze sample trace
python3 trace_analyzer.py sample_trace.jsonl

# 2. Should show:
#    - 31 total events
#    - 8 crypto blocks
#    - 85.7% encryption likelihood
#    - Quality Score: 3/5 (GOOD)
```

---

## 💡 Pro Tips

1. **GPU Training:** Execution traces are long sequences (500-5000 events)
2. **Data Augmentation:** Run same binary with different network conditions
3. **Cross-Architecture:** Train on x86, test on ARM/MIPS
4. **Ensemble:** Combine LSTM + Random Forest on entropy features

---

## 🎉 Ready to Build!

You have everything needed to:
1. ✅ Extract high-fidelity execution traces
2. ✅ Validate data quality
3. ✅ Prepare ML training data
4. ✅ Train LSTM/Transformer models
5. ✅ Detect crypto protocols in stripped firmware

**Start with `QUICKSTART_GUIDE.md` and happy hunting! 🔍🔐**

---

**Questions?** Check the documentation files or open an issue.

**Status:** 🟢 Production Ready
