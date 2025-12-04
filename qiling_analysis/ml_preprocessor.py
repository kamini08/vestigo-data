#!/usr/bin/env python3
"""
ML Data Preprocessor - Convert trace.jsonl to ML-ready format

This script demonstrates how to preprocess the execution traces
for LSTM/Transformer training.
"""

import json
from typing import List, Dict, Tuple
from collections import Counter

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("[!] Warning: numpy not installed. Install with: pip install numpy")
    print("[!] Running in demo mode without actual array processing.\n")


class TracePreprocessor:
    """Convert raw traces to ML-ready sequences."""
    
    def __init__(self):
        self.block_vocab = {}  # bytes_hash -> ID
        self.mnemonic_vocab = {}  # mnemonic -> ID
        self.syscall_vocab = {}  # syscall name -> ID
        
        self.next_block_id = 0
        self.next_mnemonic_id = 0
        self.next_syscall_id = 0
    
    def build_vocabularies(self, traces: List[List[Dict]]):
        """Build vocabularies from all traces."""
        print("[*] Building vocabularies...")
        
        all_blocks = set()
        all_mnemonics = set()
        all_syscalls = set()
        
        for trace in traces:
            for event in trace:
                if event['type'] == 'basic_block':
                    block_hash = event['data'].get('bytes_hash', 'unknown')
                    all_blocks.add(block_hash)
                    
                    for mnemonic in event['data'].get('mnemonics', []):
                        all_mnemonics.add(mnemonic)
                
                elif event['type'] == 'syscall':
                    all_syscalls.add(event['data']['name'])
        
        # Create mappings (reserve 0 for padding)
        self.block_vocab = {block: i+1 for i, block in enumerate(sorted(all_blocks))}
        self.mnemonic_vocab = {m: i+1 for i, m in enumerate(sorted(all_mnemonics))}
        self.syscall_vocab = {s: i+1 for i, s in enumerate(sorted(all_syscalls))}
        
        print(f"  Block vocabulary: {len(self.block_vocab)} unique blocks")
        print(f"  Mnemonic vocabulary: {len(self.mnemonic_vocab)} unique instructions")
        print(f"  Syscall vocabulary: {len(self.syscall_vocab)} unique syscalls")
    
    def event_to_features(self, event: Dict) -> Dict[str, any]:
        """Convert a single event to ML features."""
        features = {
            'event_type': 0 if event['type'] == 'basic_block' else 1,
            'block_id': 0,
            'syscall_id': 0,
            'mnemonic_ids': [],
            'has_crypto': 0,
            'entropy': 0.0,
            'size': 0,
            'instruction_count': 0
        }
        
        if event['type'] == 'basic_block':
            data = event['data']
            block_hash = data.get('bytes_hash', 'unknown')
            features['block_id'] = self.block_vocab.get(block_hash, 0)
            features['has_crypto'] = 1 if data.get('has_crypto_patterns') else 0
            features['size'] = data.get('size', 0)
            features['instruction_count'] = data.get('instruction_count', 0)
            
            # Encode mnemonics (up to 20 instructions per block)
            mnemonics = data.get('mnemonics', [])[:20]
            features['mnemonic_ids'] = [
                self.mnemonic_vocab.get(m, 0) for m in mnemonics
            ]
            # Pad to fixed length
            while len(features['mnemonic_ids']) < 20:
                features['mnemonic_ids'].append(0)
        
        elif event['type'] == 'syscall':
            data = event['data']
            features['syscall_id'] = self.syscall_vocab.get(data['name'], 0)
            features['entropy'] = data.get('entropy', 0.0) / 8.0  # Normalize to 0-1
        
        return features
    
    def trace_to_sequence(self, trace: List[Dict], max_length: int = 200):
        """Convert a trace to a fixed-length feature sequence."""
        if not HAS_NUMPY:
            return []
        
        features_list = []
        
        for event in trace[:max_length]:
            features = self.event_to_features(event)
            
            # Flatten to vector
            vector = [
                features['event_type'],
                features['block_id'],
                features['syscall_id'],
                features['has_crypto'],
                features['entropy'],
                np.log1p(features['size']),  # Log scale
                features['instruction_count']
            ] + features['mnemonic_ids']
            
            features_list.append(vector)
        
        # Pad if needed
        while len(features_list) < max_length:
            features_list.append([0] * 27)  # 7 + 20 mnemonics
        
        return np.array(features_list, dtype=np.float32)
    
    def create_sliding_windows(self, trace: List[Dict], 
                               window_size: int = 100, 
                               stride: int = 50):
        """Create sliding windows from a trace."""
        if not HAS_NUMPY:
            return []
        
        windows = []
        
        for i in range(0, len(trace) - window_size + 1, stride):
            window = trace[i:i + window_size]
            seq = self.trace_to_sequence(window, max_length=window_size)
            windows.append(seq)
        
        return windows


def load_traces(file_paths: List[str]) -> List[List[Dict]]:
    """Load multiple trace files."""
    traces = []
    
    for path in file_paths:
        print(f"[*] Loading {path}...")
        with open(path, 'r') as f:
            trace = [json.loads(line) for line in f]
            traces.append(trace)
    
    return traces


def extract_labels_from_trace(trace: List[Dict]) -> str:
    """
    Heuristic to label a trace based on patterns.
    In real usage, you'd have ground truth labels.
    """
    crypto_blocks = sum(1 for e in trace if e['type'] == 'basic_block' and e['data'].get('has_crypto_patterns'))
    high_entropy_io = sum(1 for e in trace if e['type'] == 'syscall' and e['data'].get('likely_encrypted'))
    
    aes_instructions = sum(1 for e in trace if e['type'] == 'basic_block' 
                          for m in e['data'].get('mnemonics', []) if 'aes' in m.lower())
    
    if crypto_blocks > 5 and high_entropy_io > 2:
        if aes_instructions > 10:
            return 'TLS_AES'
        else:
            return 'TLS_ChaCha'
    elif crypto_blocks > 2:
        return 'crypto_operation'
    else:
        return 'plaintext'


def demo_preprocessing():
    """Demonstrate the preprocessing pipeline."""
    print("""
╔════════════════════════════════════════════════════════════════════╗
║        ML Data Preprocessor for Crypto Protocol Detection         ║
║                    Trace → Training Data                           ║
╚════════════════════════════════════════════════════════════════════╝
""")
    
    if not HAS_NUMPY:
        print("[!] This demo requires numpy. Install with: pip install numpy")
        print("\nBut here's what the preprocessing pipeline does:\n")
        print("1. Load trace files (JSONL format)")
        print("2. Build vocabularies (blocks, mnemonics, syscalls)")
        print("3. Convert events to feature vectors")
        print("4. Create sliding windows for LSTM input")
        print("5. Output shape: (num_sequences, timesteps, features)")
        return None, None, None
    
    # Load sample trace
    print("\n[STEP 1] Loading traces...")
    traces = load_traces(['sample_trace.jsonl'])
    print(f"  Loaded {len(traces)} traces")
    print(f"  Total events: {sum(len(t) for t in traces)}")
    
    # Build vocabularies
    print("\n[STEP 2] Building vocabularies...")
    preprocessor = TracePreprocessor()
    preprocessor.build_vocabularies(traces)
    
    # Convert to sequences
    print("\n[STEP 3] Converting to ML sequences...")
    all_sequences = []
    all_labels = []
    
    for trace in traces:
        # Option A: Sliding windows (for long traces)
        windows = preprocessor.create_sliding_windows(trace, window_size=100, stride=50)
        print(f"  Created {len(windows)} windows from trace")
        
        for window in windows:
            all_sequences.append(window)
            label = extract_labels_from_trace(trace)
            all_labels.append(label)
    
    # Convert to numpy arrays
    X = np.array(all_sequences)
    print(f"\n[STEP 4] Final dataset shape:")
    print(f"  X shape: {X.shape}")
    print(f"    - {X.shape[0]} sequences")
    print(f"    - {X.shape[1]} timesteps per sequence")
    print(f"    - {X.shape[2]} features per timestep")
    
    print(f"\n  Labels: {Counter(all_labels)}")
    
    # Show feature breakdown
    print(f"\n[STEP 5] Feature vector breakdown (per timestep):")
    print(f"  [0]     event_type (0=block, 1=syscall)")
    print(f"  [1]     block_id (vocabulary ID)")
    print(f"  [2]     syscall_id (vocabulary ID)")
    print(f"  [3]     has_crypto (0/1)")
    print(f"  [4]     entropy (0.0-1.0 normalized)")
    print(f"  [5]     log(size)")
    print(f"  [6]     instruction_count")
    print(f"  [7-26]  mnemonic_ids (20 instructions)")
    
    # Show sample
    print(f"\n[STEP 6] Sample feature vector (first timestep):")
    print(f"  {X[0, 0, :]}")
    
    # Ready for ML
    print(f"\n{'='*70}")
    print(f"✓ Data is ready for ML training!")
    print(f"{'='*70}")
    print(f"\nNext steps:")
    print(f"1. Split into train/validation/test sets")
    print(f"2. Define LSTM/Transformer model")
    print(f"3. Train with categorical crossentropy loss")
    print(f"4. Evaluate on held-out test binaries")
    
    print(f"\nExample TensorFlow/Keras model:")
    print(f"""
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

model = Sequential([
    LSTM(128, return_sequences=True, input_shape=(100, 27)),
    Dropout(0.3),
    LSTM(64),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dense(num_classes, activation='softmax')
])

model.compile(
    optimizer='adam',
    loss='categorical_crossentropy',
    metrics=['accuracy']
)

model.fit(X_train, y_train, validation_data=(X_val, y_val), epochs=50)
""")
    
    return X, all_labels, preprocessor


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Load user-provided traces
        traces = load_traces(sys.argv[1:])
        preprocessor = TracePreprocessor()
        preprocessor.build_vocabularies(traces)
        
        # Process each trace
        for i, trace in enumerate(traces):
            windows = preprocessor.create_sliding_windows(trace)
            label = extract_labels_from_trace(trace)
            print(f"Trace {i}: {len(windows)} windows, label={label}")
    else:
        # Demo mode
        demo_preprocessing()
