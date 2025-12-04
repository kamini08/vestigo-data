# Quick Start Guide - Crypto Protocol Detection Data Pipeline

## 📦 What You Have

1. **`feature_extractor.py`** - Main data extraction script using Qiling + Capstone
2. **`trace_analyzer.py`** - Data quality analysis and validation tool
3. **`sample_trace.jsonl`** - Example output showing format
4. **`FEATURE_EXTRACTOR_README.md`** - Comprehensive documentation

## 🚀 Quick Start (3 Steps)

### Step 1: Extract Features from Binary

```bash
python3 feature_extractor.py <binary> <rootfs> <output.jsonl>
```

**Example:**
```bash
# For x86-64 binary
python3 feature_extractor.py \
    ./tests/your_binary \
    ./rootfs/x8664_linux \
    ./traces/binary_trace.jsonl
```

**What it does:**
- Emulates the binary in Qiling
- Hooks every basic block execution
- Captures all syscalls
- Calculates entropy for I/O buffers
- Outputs unified time-series trace

### Step 2: Analyze the Trace

```bash
python3 trace_analyzer.py ./traces/binary_trace.jsonl
```

**What it shows:**
- Event statistics (blocks, syscalls, crypto patterns)
- Entropy distribution
- Instruction patterns
- Protocol signatures
- **ML training data quality score**

### Step 3: Use for ML Training

```python
import json

# Load trace
with open('trace.jsonl', 'r') as f:
    events = [json.loads(line) for line in f]

# Extract features for ML
for event in events:
    seq_num = event['seq']
    event_type = event['type']
    
    if event_type == 'basic_block':
        mnemonics = event['data']['mnemonics']
        has_crypto = event['data']['has_crypto_patterns']
        # Feed to LSTM/Transformer
    
    elif event_type == 'syscall':
        syscall_name = event['data']['name']
        entropy = event['data'].get('entropy', 0)
        # Feed to model
```

## 📊 Understanding the Output

### Sample Event Sequence (What the Model Learns)

```
seq=0:  Block    → Normal execution (mov, push, call)
seq=1:  Syscall  → socket() - Network setup
seq=2:  Block    → Test and jump
seq=3:  Syscall  → connect() - Connection established
seq=4:  Block    → Crypto operations (xor, rol, xor, xor)
seq=5:  Syscall  → send(entropy=7.89, encrypted!) - Encrypted data sent
```

**The Model Learns:**
> "When I see repeated XOR operations followed by a high-entropy send(), that's encrypted network traffic."

### Key Features for Classification

| Feature | Purpose | Example |
|---------|---------|---------|
| `mnemonics` | Instruction sequence | `["xor", "rol", "add"]` |
| `bytes_hash` | Block fingerprint | SHA256 hash |
| `has_crypto_patterns` | Quick flag | `true`/`false` |
| `entropy` | Data randomness | 7.89 (encrypted) |
| `syscall name` | Behavioral context | "send", "recv" |
| `seq` | Temporal order | 0, 1, 2, ... |

## 🎯 Real-World Usage

### Collecting Training Data for TLS Detection

```bash
# 1. Run TLS client binary
python3 feature_extractor.py \
    ./samples/openssl_client \
    ./rootfs/x8664_linux \
    ./data/tls_trace.jsonl

# 2. Analyze quality
python3 trace_analyzer.py ./data/tls_trace.jsonl

# Output will show:
# ✓ TLS/SSL-like encrypted communication
# ✓ Heavy cryptographic operations (AES likely)
# Quality Score: 5/5 - EXCELLENT
```

### Comparing Protocols

```bash
# Extract from multiple binaries
for binary in samples/*.elf; do
    name=$(basename "$binary" .elf)
    python3 feature_extractor.py \
        "$binary" \
        ./rootfs/x8664_linux \
        "./data/${name}_trace.jsonl"
done

# Analyze all
for trace in data/*_trace.jsonl; do
    echo "=== $trace ==="
    python3 trace_analyzer.py "$trace" | grep "Quality Score"
done
```

## 🔧 Troubleshooting

### Issue: Binary exits immediately

**Symptom:**
```
Total Events: 15
Status: POOR - Binary may need different inputs/environment
```

**Solution:** The environment mocker might need more hooks. Check what syscall causes exit:
```bash
# Run with strace to see syscalls
strace -e trace=all ./your_binary 2>&1 | head -50
```

Then add hooks in `EnvironmentMocker._hook_<syscall>()`.

### Issue: No crypto patterns detected

**Symptom:**
```
Crypto Pattern Blocks: 0
✗ No crypto patterns detected
```

**Possible reasons:**
1. Binary doesn't use crypto (plaintext protocol)
2. Crypto is in a library call (not inline)
3. Pattern detection is too strict

**Solution:** Check the mnemonics manually:
```bash
jq 'select(.type=="basic_block") | .data.mnemonics' trace.jsonl | head -20
```

If you see XOR/ROL/AES instructions, adjust `_detect_crypto_patterns()` threshold.

### Issue: Low entropy on known encrypted data

**Symptom:**
```
send() entropy: 2.5 (likely_encrypted: false)
```

**Cause:** Small buffers or repeated patterns.

**Solution:** Check buffer size:
```bash
jq 'select(.data.entropy?) | {name: .data.name, entropy: .data.entropy, size: .data.buffer_size}' trace.jsonl
```

Entropy is only reliable for buffers >32 bytes.

## 📈 Quality Metrics Guide

| Metric | Good | Excellent |
|--------|------|-----------|
| Total Events | >500 | >5,000 |
| Unique Blocks | >100 | >500 |
| Crypto Blocks | >5 | >50 |
| High-Entropy I/O | >1 | >10 |
| Syscall Variety | >5 | >10 |

## 🎓 ML Model Tips

### 1. Sequence Length for LSTM

**Recommended:** 100-200 events per sequence
- Too short (<50): Loses context
- Too long (>500): Vanishing gradients

```python
SEQUENCE_LENGTH = 150
sequences = create_sequences(events, SEQUENCE_LENGTH)
```

### 2. Embedding Dimensions

**Block Hash:** Vocabulary size = unique blocks (typically 1000-10000)
```python
block_embedding = Embedding(vocab_size=10000, output_dim=128)
```

**Mnemonics:** Vocabulary size = ~50-100 instructions
```python
mnemonic_embedding = Embedding(vocab_size=100, output_dim=64)
```

### 3. Features to Feed the Model

**Continuous features:**
- Entropy (normalized 0-1)
- Block size (log-scaled)
- Instruction count

**Categorical features:**
- Block hash (embedded)
- Mnemonics (embedded)
- Syscall name (one-hot or embedded)

**Binary features:**
- has_crypto_patterns (0/1)
- likely_encrypted (0/1)

### 4. Labels for Supervised Learning

```python
labels = {
    'TLS_handshake': 0,
    'TLS_encrypted': 1,
    'SSH_auth': 2,
    'SSH_encrypted': 3,
    'ChaCha20': 4,
    'AES_CBC': 5,
    'plaintext': 6
}
```

## 📚 Next Steps

1. **Collect Diverse Dataset:**
   - TLS 1.2, TLS 1.3 implementations
   - SSH clients/servers
   - Custom IoT protocols
   - Malware C2 channels

2. **Label Your Data:**
   - Ground truth from Wireshark captures
   - Known protocol implementations

3. **Train Model:**
   - Start with LSTM baseline
   - Try Transformer for long sequences
   - Consider attention mechanisms

4. **Evaluate:**
   - Precision/Recall per protocol
   - Confusion matrix
   - Test on unseen binaries

## 🔗 Resources

- **Qiling Framework:** https://github.com/qilingframework/qiling
- **Capstone Engine:** https://www.capstone-engine.org/
- **LSTM for Sequences:** https://colah.github.io/posts/2015-08-Understanding-LSTMs/
- **Transformers:** https://arxiv.org/abs/1706.03762

## 💡 Pro Tips

1. **Use GPU for ML Training:** These traces are long sequences
2. **Data Augmentation:** Run same binary with different inputs
3. **Cross-Architecture:** Train on x86, test on ARM/MIPS
4. **Ensemble Models:** Combine LSTM + Random Forest on crypto features

---

**🎉 You're ready to build an ML-based crypto protocol detector!**

Questions? Check `FEATURE_EXTRACTOR_README.md` for detailed docs.
