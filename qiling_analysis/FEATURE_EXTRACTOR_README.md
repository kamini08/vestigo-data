# Feature Extractor for AI/ML Cryptographic Protocol Detection

## 🎯 Purpose

This script generates high-fidelity time-series execution traces from stripped ELF binaries for training LSTM/Transformer models to detect cryptographic protocols and primitives.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Stripped ELF Binary                      │
│            (MIPS/ARM/x86 - No Symbols, Stripped)            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Qiling Framework Emulation                     │
│  • Full system emulation with rootfs                        │
│  • Hook-based instrumentation                               │
│  • Architecture-agnostic (supports MIPS/ARM/x86)            │
└─────────────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
    ┌──────────────────┐    ┌──────────────────┐
    │  Basic Blocks    │    │    Syscalls      │
    │  (The "Words")   │    │(The"Punctuation")│
    └──────────────────┘    └──────────────────┘
                │                       │
                └───────────┬───────────┘
                            ▼
            ┌──────────────────────────────┐
            │   Capstone Disassembly       │
            │   • Mnemonic extraction      │
            │   • Pattern recognition      │
            └──────────────────────────────┘
                            │
                            ▼
            ┌──────────────────────────────┐
            │   Environment Mocking        │
            │   (The "Liar")               │
            │   • Force protocol execution │
            │   • Prevent early exits      │
            │   • Capture I/O buffers      │
            └──────────────────────────────┘
                            │
                            ▼
            ┌──────────────────────────────┐
            │   Unified Time-Series Log    │
            │   trace.jsonl                │
            │   • Sequential events        │
            │   • Interleaved blocks/calls │
            │   • Entropy-annotated I/O    │
            └──────────────────────────────┘
                            │
                            ▼
            ┌──────────────────────────────┐
            │   ML Pipeline Ingestion      │
            │   LSTM/Transformer Training  │
            └──────────────────────────────┘
```

## 🔑 Key Features

### 1. **Unified Time-Series Format**
- All events (basic blocks + syscalls) have a `seq` number
- Preserves exact temporal order of execution
- Critical for learning protocol state machines

### 2. **Basic Block Features (The "Words")**
Each executed basic block captures:
- `address`: Virtual address (hex)
- `size`: Block size in bytes
- `bytes_hash`: SHA256 of raw opcodes (identifies blocks across ASLR/PIE)
- `mnemonics`: Array of instruction names (e.g., `["mov", "xor", "add"]`)
- `instruction_count`: Number of instructions
- `has_crypto_patterns`: Boolean flag for crypto-like operations

### 3. **Syscall Features (The "Punctuation")**
For `open`, `read`, `write`, `connect`, `send`, `recv`:
- `name`: Syscall name
- `args`: First 4 arguments (context)
- `return_value`: Return value
- `entropy`: Shannon entropy (0.0-8.0) of buffer data
- `likely_encrypted`: Boolean flag (entropy > 7.0)

### 4. **Environment Mocking (The "Liar")**
Prevents early exits and forces protocol execution:
- `connect()` → Always returns success (0)
- `socket()` → Returns valid fake FDs
- `send()/recv()` → Captures buffers, calculates entropy
- `open()` → Always succeeds with fake FDs
- `gethostbyname()` → Returns dummy addresses

## 📊 Output Format (trace.jsonl)

Each line is a JSON event in sequential order:

```json
{
  "seq": 0,
  "timestamp": "2025-12-02T10:30:00.123456",
  "type": "basic_block",
  "data": {
    "address": "0x400580",
    "size": 24,
    "bytes_hash": "a3f5e8c2b1d4f9a7e6c3b2a1f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e",
    "mnemonics": ["push", "mov", "sub", "mov", "call"],
    "instruction_count": 5,
    "has_crypto_patterns": false
  }
}
```

```json
{
  "seq": 1,
  "timestamp": "2025-12-02T10:30:00.123567",
  "type": "syscall",
  "data": {
    "name": "socket",
    "args": [2, 1, 0],
    "return_value": 100
  }
}
```

```json
{
  "seq": 2,
  "timestamp": "2025-12-02T10:30:00.123678",
  "type": "basic_block",
  "data": {
    "address": "0x4007a0",
    "size": 64,
    "bytes_hash": "c7f3e9a8b4d2f1a5e8c6b3a2f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e",
    "mnemonics": ["xor", "xor", "xor", "rol", "add", "xor", "mov", "xor", "shl", "xor"],
    "instruction_count": 10,
    "has_crypto_patterns": true
  }
}
```

```json
{
  "seq": 3,
  "timestamp": "2025-12-02T10:30:00.123789",
  "type": "syscall",
  "data": {
    "name": "send",
    "args": [100, "0x7ffe1234", 256, 0],
    "return_value": 256,
    "buffer_size": 256,
    "entropy": 7.8924,
    "likely_encrypted": true
  }
}
```

```json
{
  "seq": 4,
  "timestamp": "2025-12-02T10:30:00.123890",
  "type": "syscall",
  "data": {
    "name": "recv",
    "args": [100, "0x7ffe5678", 512, 0],
    "return_value": 105
  }
}
```

## 🚀 Usage

### Basic Usage

```bash
python feature_extractor.py <binary_path> <rootfs_path> [output_path]
```

### Examples

**x86-64 Linux Binary:**
```bash
python feature_extractor.py ./tests/stripped_binary ./rootfs/x8664_linux trace.jsonl
```

**ARM Binary:**
```bash
python feature_extractor.py ./firmware/arm_router.elf ./rootfs/arm_linux arm_trace.jsonl
```

**MIPS Binary:**
```bash
python feature_extractor.py ./firmware/mips_iot.elf ./rootfs/mips32_linux mips_trace.jsonl
```

### View Sample Output Format

```bash
python feature_extractor.py
```
(Running without arguments shows detailed sample output)

## 📦 Dependencies

```bash
pip install qiling capstone
```

Required system packages for Qiling (Ubuntu/Debian):
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip git cmake pkg-config
```

## 🧪 Example Workflow

### Step 1: Extract Features from Binary
```bash
python feature_extractor.py \
    ./malware_samples/trojan.elf \
    ./rootfs/x8664_linux \
    ./training_data/trojan_trace.jsonl
```

### Step 2: Inspect the Output
```bash
head -n 10 ./training_data/trojan_trace.jsonl | jq .
```

### Step 3: Analyze Statistics
```bash
# Count basic blocks
grep '"type": "basic_block"' trojan_trace.jsonl | wc -l

# Count crypto patterns
grep '"has_crypto_patterns": true' trojan_trace.jsonl | wc -l

# Find high-entropy I/O
jq 'select(.data.entropy > 7.0)' trojan_trace.jsonl
```

## 🎓 ML Pipeline Integration

### Data Preprocessing for LSTM/Transformer

```python
import json
import numpy as np

def load_trace(jsonl_path):
    """Load trace into sequential format for ML."""
    events = []
    with open(jsonl_path, 'r') as f:
        for line in f:
            events.append(json.loads(line))
    return events

def create_sequences(events, sequence_length=100):
    """Create fixed-length sequences for LSTM."""
    sequences = []
    labels = []
    
    for i in range(0, len(events) - sequence_length, sequence_length // 2):
        seq = events[i:i+sequence_length]
        sequences.append(seq)
        
        # Label based on crypto patterns and entropy
        has_crypto = any(e['data'].get('has_crypto_patterns') for e in seq)
        has_high_entropy = any(e['data'].get('entropy', 0) > 7.0 for e in seq)
        
        if has_crypto and has_high_entropy:
            labels.append('encrypted_protocol')
        elif has_crypto:
            labels.append('crypto_operation')
        else:
            labels.append('normal')
    
    return sequences, labels

# Usage
trace = load_trace('trace.jsonl')
sequences, labels = create_sequences(trace)
```

### Feature Embedding Strategy

1. **Block Hash Embedding**: Use `bytes_hash` as vocabulary ID
2. **Mnemonic Embedding**: Treat mnemonics as words (Word2Vec/BERT-style)
3. **Entropy Feature**: Direct numerical input (normalized 0-1)
4. **Positional Encoding**: Use `seq` number for temporal position

## 🔍 Crypto Detection Patterns

The script detects crypto-like patterns using heuristics:

### XOR-Heavy Loops
```
["xor", "xor", "xor", "rol", "add", "xor", ...]
```
→ Likely stream cipher (ChaCha, Salsa20)

### AES-NI Instructions
```
["pxor", "aesenc", "aesenc", "aesenclast", "movdqu"]
```
→ Hardware-accelerated AES

### High-Entropy Output
```
Syscall: send(fd, buf, 256)
Entropy: 7.89 (likely_encrypted: true)
```
→ Encrypted network traffic

### Pattern Combinations
```
Block (has_crypto_patterns: true)
  ↓
Syscall: send (entropy: 7.9, likely_encrypted: true)
```
→ Crypto computation followed by encrypted I/O = **Protocol Detection**

## 📈 Expected Output Statistics

Typical trace for a TLS client:

```
EXTRACTION STATISTICS
======================================
total_events......................... 12,543
basic_blocks......................... 11,890
syscalls............................. 653
crypto_pattern_blocks................ 234
unique_blocks........................ 1,456
```

## 🛠️ Troubleshooting

### Issue: "Unsupported architecture"
**Solution**: Ensure rootfs matches binary architecture:
- x86-64: `rootfs/x8664_linux`
- ARM: `rootfs/arm_linux`
- MIPS: `rootfs/mips32_linux`

### Issue: Binary exits immediately
**Solution**: Environment mocking should prevent this, but if it persists:
- Add more syscall hooks in `EnvironmentMocker`
- Use `strace` on native system to identify missing syscalls

### Issue: Low crypto pattern detection
**Solution**: The heuristic is conservative. Tune `_detect_crypto_patterns()`:
- Lower XOR threshold
- Add more crypto instruction patterns

## 📚 Key Insights for ML Model

### Why This Format Works for Protocol Detection

1. **Sequential Grammar**: Blocks are "words", syscalls are "punctuation"
   - LSTM learns: "After crypto block, expect high-entropy send()"
   
2. **Entropy is Critical**: Distinguishes plaintext vs. ciphertext
   - TLS Handshake: Low entropy (plaintext certificates)
   - TLS Application Data: High entropy (AES-GCM encrypted)
   
3. **Mnemonic Sequences**: Enable NLP techniques
   - Word2Vec on instruction mnemonics
   - Attention mechanisms on instruction patterns
   
4. **Block Hashing**: Robust feature across binaries
   - Same crypto implementation = same hash
   - Works with ASLR, PIE, code reuse

## 🎯 Next Steps for Your Project

1. **Data Collection**: Run on 1000+ binaries (TLS, SSH, custom protocols)
2. **Labeling**: Label traces with ground truth (TLS v1.2, ChaCha20, etc.)
3. **Model Training**:
   - LSTM: For sequential protocol detection
   - Transformer: For long-range dependencies
4. **Evaluation**: Precision/Recall on test set of stripped IoT firmware

## 📝 Citation

If you use this in academic work:

```
@misc{feature_extractor_2025,
  title={Dynamic Binary Analysis for ML-Based Cryptographic Protocol Detection},
  author={Your Name},
  year={2025},
  howpublished={GitHub: Dynamic Binary Analysis Framework}
}
```

## 🤝 Contributing

Improvements welcome:
- Additional architecture support (RISC-V, PowerPC)
- More sophisticated crypto pattern detection
- Real-time streaming for live firmware analysis

---

**Happy Hunting! 🔍🔐**
