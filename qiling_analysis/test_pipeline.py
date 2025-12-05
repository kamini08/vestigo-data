#!/usr/bin/env python3
"""
Quick Test: Demonstrate Complete Pipeline
Tests all 3 layers: extraction → windowing → inference
"""

import sys
import json
from pathlib import Path

# Import pipeline components
try:
    from window_feature_extractor import WindowFeatureExtractor
    from crypto_inference_engine import CryptoProtocolInferenceEngine
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're in the correct directory!")
    sys.exit(1)


def test_pipeline_on_trace(trace_path: str):
    """Test complete pipeline on existing trace file"""
    
    trace_path = Path(trace_path)
    if not trace_path.exists():
        print(f"❌ Trace file not found: {trace_path}")
        return False
    
    print("="*70)
    print("🧪 TESTING COMPLETE PIPELINE")
    print("="*70)
    print(f"Input trace: {trace_path}\n")
    
    # === LAYER 2: Window Feature Extraction ===
    print("[1/3] Creating windowed features...")
    
    extractor = WindowFeatureExtractor(window_size=50, stride=25)
    
    # Load trace
    events = extractor.load_trace(str(trace_path))
    print(f"  ✅ Loaded {len(events)} events")
    
    if len(events) < 50:
        print(f"  ⚠️  Warning: Trace too short ({len(events)} events), using smaller window")
        extractor = WindowFeatureExtractor(window_size=min(20, len(events)), stride=10)
        events = extractor.load_trace(str(trace_path))
    
    # Create windows
    windows = extractor.create_windows(events)
    print(f"  ✅ Created {len(windows)} windows")
    
    if not windows:
        print("  ❌ No windows created! Trace too short.")
        return False
    
    # Show first window features
    print(f"\n  📊 Sample window features (window 0):")
    sample_features = windows[0]['features']
    for key, value in list(sample_features.items())[:10]:
        if isinstance(value, float):
            print(f"     {key}: {value:.4f}")
        else:
            print(f"     {key}: {value}")
    print(f"     ... ({len(sample_features)} features total)")
    
    # === LAYER 3: ML Inference ===
    print(f"\n[2/3] Running inference (heuristic mode)...")
    
    engine = CryptoProtocolInferenceEngine(mode='heuristic')
    
    # Analyze first window
    result = engine.analyze_window(windows[0])
    
    print(f"  ✅ Analysis complete")
    
    # === RESULTS ===
    print(f"\n[3/3] Results:")
    print("\n" + "="*70)
    print("📊 CRYPTO DETECTION RESULTS")
    print("="*70)
    
    crypto_analysis = result['analysis']['crypto_detection']
    print(f"\n🔐 Crypto Detection:")
    print(f"   Is Crypto: {crypto_analysis['is_crypto']}")
    print(f"   Probability: {crypto_analysis['crypto_probability']:.2f}")
    
    algo_family = crypto_analysis['encryption_algorithm_family']
    print(f"\n🔐 Algorithm Family:")
    print(f"   Type: {algo_family['type']}")
    print(f"   Algorithm: {algo_family['algorithm']}")
    print(f"   Confidence: {algo_family['confidence']:.2f}")
    print(f"   Evidence:")
    for evidence in algo_family['evidence']:
        print(f"     - {evidence}")
    
    stage = result['analysis']['protocol_stage']
    print(f"\n📶 Protocol Stage:")
    print(f"   Current Stage: {stage['stage']}")
    print(f"   Stage Probabilities:")
    for stage_name, prob in sorted(stage['stage_probabilities'].items(), key=lambda x: x[1], reverse=True):
        print(f"     {stage_name}: {prob:.2f}")
    
    anomalies = result['analysis']['anomaly_detection']
    print(f"\n⚠️  Anomalies Detected: {len(anomalies)}")
    for anom in anomalies:
        print(f"   - {anom['type']} (severity: {anom['severity']}, score: {anom['score']:.2f})")
    
    explainability = result['explainability']
    print(f"\n💡 Explainability:")
    print(f"   Top Factors:")
    for factor in explainability['top_factors'][:5]:
        print(f"     - {factor}")
    
    print(f"\n   Feature Importance (top 5):")
    for feature, importance in sorted(explainability['feature_importance'].items(), 
                                     key=lambda x: x[1], reverse=True)[:5]:
        print(f"     {feature}: {importance:.2f}")
    
    # === FULL JSON OUTPUT ===
    print("\n" + "="*70)
    print("📄 FULL JSON OUTPUT (First Window)")
    print("="*70)
    
    # Convert numpy types to native Python types
    def convert_numpy(obj):
        import numpy as np
        if isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, dict):
            return {k: convert_numpy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_numpy(v) for v in obj]
        return obj
    
    result_serializable = convert_numpy(result)
    print(json.dumps(result_serializable, indent=2))
    
    print("\n" + "="*70)
    print("✅ PIPELINE TEST COMPLETE")
    print("="*70)
    
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 test_pipeline.py <trace.jsonl>")
        print("\nExample:")
        print("  python3 test_pipeline.py traces/wolfssl_chacha_obf_basic_20251204_200027.jsonl")
        
        # Look for existing traces
        traces_dir = Path(__file__).parent / "traces"
        if traces_dir.exists():
            traces = list(traces_dir.glob("*.jsonl"))
            if traces:
                print(f"\n📁 Found {len(traces)} trace file(s) in traces/:")
                for trace in traces[:5]:
                    print(f"   - {trace.name}")
                if len(traces) > 5:
                    print(f"   ... and {len(traces) - 5} more")
                
                print(f"\n💡 Try: python3 test_pipeline.py {traces[0]}")
        
        sys.exit(1)
    
    trace_path = sys.argv[1]
    success = test_pipeline_on_trace(trace_path)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
