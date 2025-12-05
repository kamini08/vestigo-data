#!/usr/bin/env python3
"""
Test Multiple Windows: Find where crypto actually happens
"""

import sys
import json
from pathlib import Path
from window_feature_extractor import WindowFeatureExtractor
from crypto_inference_engine import CryptoProtocolInferenceEngine


def analyze_all_windows(trace_path: str):
    """Analyze ALL windows to find crypto hotspots"""
    
    print("="*70)
    print("🔍 ANALYZING ALL WINDOWS - Finding Crypto Hotspots")
    print("="*70)
    print(f"Trace: {Path(trace_path).name}\n")
    
    # Load and window
    extractor = WindowFeatureExtractor(window_size=50, stride=25)
    events = extractor.load_trace(trace_path)
    windows = extractor.create_windows(events)
    
    print(f"Total windows: {len(windows)}\n")
    
    # Analyze each window
    engine = CryptoProtocolInferenceEngine(mode='heuristic')
    
    crypto_windows = []
    
    for i, window in enumerate(windows):
        result = engine.analyze_window(window)
        
        features = window['features']
        crypto_prob = result['analysis']['crypto_detection']['crypto_probability']
        
        # Track high crypto probability windows
        if crypto_prob > 0.5:
            crypto_windows.append({
                'window_id': i,
                'crypto_prob': crypto_prob,
                'xor_density': features['xor_density'],
                'shift_density': features['shift_density'],
                'algorithm': result['analysis']['crypto_detection']['encryption_algorithm_family']['algorithm']
            })
    
    # Show results
    print(f"🔐 Crypto Windows Found: {len(crypto_windows)}/{len(windows)}")
    print(f"   Detection Rate: {len(crypto_windows)/len(windows)*100:.1f}%\n")
    
    if crypto_windows:
        print("📊 Top 10 Crypto Windows:")
        print(f"{'Window':<10} {'Crypto Prob':<15} {'XOR Density':<15} {'Shift Density':<15} {'Algorithm':<20}")
        print("-" * 80)
        
        for cw in sorted(crypto_windows, key=lambda x: x['crypto_prob'], reverse=True)[:10]:
            print(f"{cw['window_id']:<10} {cw['crypto_prob']:<15.2f} {cw['xor_density']:<15.4f} {cw['shift_density']:<15.4f} {cw['algorithm']:<20}")
        
        # Show best window in detail
        best = max(crypto_windows, key=lambda x: x['crypto_prob'])
        print(f"\n{'='*70}")
        print(f"🎯 BEST CRYPTO WINDOW: Window {best['window_id']}")
        print(f"{'='*70}")
        
        best_result = engine.analyze_window(windows[best['window_id']])
        
        print(f"\n🔐 Crypto Detection:")
        print(f"   Probability: {best_result['analysis']['crypto_detection']['crypto_probability']:.2f}")
        
        algo = best_result['analysis']['crypto_detection']['encryption_algorithm_family']
        print(f"\n🔐 Algorithm:")
        print(f"   {algo['algorithm']} ({algo['type']})")
        print(f"   Confidence: {algo['confidence']:.2f}")
        print(f"   Evidence:")
        for evidence in algo['evidence']:
            print(f"     - {evidence}")
        
        print(f"\n💡 Top Factors:")
        for factor in best_result['explainability']['top_factors'][:5]:
            print(f"   - {factor}")
        
        # Show feature comparison
        print(f"\n{'='*70}")
        print("📊 FEATURE COMPARISON: Window 0 vs Best Window")
        print(f"{'='*70}")
        
        w0_features = windows[0]['features']
        best_features = windows[best['window_id']]['features']
        
        print(f"{'Feature':<30} {'Window 0':<15} {'Best Window':<15} {'Difference'}")
        print("-" * 70)
        
        key_features = ['xor_density', 'shift_density', 'loop_repetition_score', 
                       'mnemonic_entropy', 'crypto_heuristic_score']
        
        for feat in key_features:
            w0_val = w0_features.get(feat, 0)
            best_val = best_features.get(feat, 0)
            diff = best_val - w0_val
            sign = "+" if diff > 0 else ""
            print(f"{feat:<30} {w0_val:<15.4f} {best_val:<15.4f} {sign}{diff:.4f}")
    
    else:
        print("❌ NO CRYPTO WINDOWS DETECTED!")
        print("\nPossible reasons:")
        print("  1. Binary didn't execute crypto code (early exit)")
        print("  2. Crypto patterns too subtle for heuristics")
        print("  3. Need trained ML model for detection")
        
        # Show some sample features
        print("\n📊 Sample Features (Window 10):")
        if len(windows) > 10:
            sample = windows[10]['features']
            for key in ['xor_density', 'shift_density', 'loop_repetition_score', 
                       'mnemonic_entropy', 'crypto_heuristic_score']:
                print(f"   {key}: {sample.get(key, 0):.4f}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 test_all_windows.py <trace.jsonl>")
        sys.exit(1)
    
    analyze_all_windows(sys.argv[1])
