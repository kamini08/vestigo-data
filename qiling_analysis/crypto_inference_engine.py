#!/usr/bin/env python3
"""
Crypto Protocol Inference Engine
Generates comprehensive analysis JSON with probabilities, stages, and explainability

This is the final layer that takes windowed features and produces the desired output:
- crypto_detection with probabilities
- encryption_algorithm_family classification
- protocol_stage detection
- anomaly_detection
- explainability with feature importance

NOTE: This is a TEMPLATE implementation that uses heuristics.
Replace with trained LSTM/Transformer model for production use.
"""

import json
import numpy as np
from typing import Dict, List, Any, Optional
from pathlib import Path
from collections import Counter


class CryptoProtocolInferenceEngine:
    """
    Generates comprehensive crypto analysis JSON from windowed features.
    
    Current implementation uses HEURISTICS for demonstration.
    TODO: Replace with trained ML model (LSTM/Transformer) for production.
    """
    
    def __init__(self, model_path: Optional[str] = None, mode: str = 'heuristic'):
        """
        Args:
            model_path: Path to trained model (optional, for ML mode)
            mode: 'heuristic' (rule-based) or 'ml' (trained model)
        """
        self.mode = mode
        self.model = None
        
        if mode == 'ml' and model_path:
            # TODO: Load your trained LSTM/Transformer model
            # self.model = tf.keras.models.load_model(model_path)
            # OR: self.model = torch.load(model_path)
            print(f"[!] ML mode not implemented yet. Using heuristic fallback.")
            print(f"[!] Train a model first, then load it here.")
            self.mode = 'heuristic'
        
        # Stage labels (from protocol analysis)
        self.stage_labels = ['HANDSHAKE', 'KEY_EXCHANGE', 'ENCRYPTION', 'DATA_TRANSFER', 'CLEANUP']
        
        # Algorithm labels
        self.algo_labels = ['AES', 'ChaCha', 'RSA', 'ECC', 'DES', '3DES', 'Blowfish', 'Unknown']
        
        # Protocol stage history for sequence tracking
        self.stage_history: List[Dict] = []
    
    def analyze_window(self, window: Dict, window_context: Optional[List[Dict]] = None) -> Dict:
        """
        Generate comprehensive analysis JSON for a single window.
        
        Args:
            window: Window dict with 'features' key
            window_context: Previous windows for temporal context (optional)
        
        Returns:
            Analysis dict matching your desired JSON structure
        """
        features = window['features']
        window_id = window.get('window_id', 0)
        
        if self.mode == 'ml':
            # TODO: Use trained model
            return self._analyze_with_model(window, window_context)
        else:
            # Use heuristic rules
            return self._analyze_with_heuristics(window, window_context)
    
    def _analyze_with_heuristics(self, window: Dict, window_context: Optional[List[Dict]]) -> Dict:
        """
        Heuristic-based analysis (for demonstration/testing).
        Replace with ML model for production.
        """
        features = window['features']
        window_id = window.get('window_id', 0)
        
        # === CRYPTO DETECTION ===
        crypto_score = self._calculate_crypto_score(features)
        is_crypto = crypto_score > 0.5
        
        # === ALGORITHM CLASSIFICATION ===
        algo_result = self._classify_algorithm(features)
        
        # === PROTOCOL STAGE DETECTION ===
        stage_result = self._detect_protocol_stage(features, window_context)
        
        # === BEHAVIOR CLASSIFICATION ===
        behavior = self._classify_behavior(features, crypto_score)
        
        # === ANOMALY DETECTION ===
        anomalies = self._detect_anomalies(features)
        
        # === TRACE RECONSTRUCTION ===
        trace_reconstruction = self._reconstruct_trace(window_id, stage_result, window_context)
        
        # === EXPLAINABILITY ===
        explainability = self._explain_prediction(features, crypto_score, stage_result, algo_result)
        
        # Build final JSON structure
        result = {
            "window_id": window_id,
            "analysis": {
                "crypto_detection": {
                    "is_crypto": is_crypto,
                    "crypto_probability": round(crypto_score, 2),
                    "encryption_algorithm_family": {
                        "type": algo_result['type'],
                        "algorithm": algo_result['algorithm'],
                        "confidence": round(algo_result['confidence'], 2),
                        "evidence": algo_result['evidence']
                    }
                },
                "protocol_stage": {
                    "stage": stage_result['stage'],
                    "stage_probabilities": stage_result['probabilities']
                },
                "behavior_classification": {
                    "class": behavior['class'],
                    "confidence": round(behavior['confidence'], 2)
                },
                "anomaly_detection": anomalies
            },
            "trace_reconstruction": trace_reconstruction,
            "explainability": explainability
        }
        
        # Update stage history
        self.stage_history.append({
            "window": window_id,
            "stage": stage_result['stage'],
            "confidence": stage_result['probabilities'][stage_result['stage']]
        })
        
        return result
    
    def _calculate_crypto_score(self, features: Dict) -> float:
        """
        Calculate crypto probability using heuristics.
        
        Strong indicators:
        - High XOR density (>0.08 for obfuscated, >0.15 for clear)
        - High shift/rotate density (>0.05 for obfuscated, >0.10 for clear)
        - Tight loops (execution_count > 10)
        - High buffer entropy (>7.0)
        - AES instructions present
        """
        score = 0.0
        
        # XOR operations (0-0.25 points) - lowered threshold
        xor_density = features.get('xor_density', 0)
        score += min(xor_density * 2.0, 0.25)  # Was 1.5, now 2.0 for more sensitive
        
        # Shift/rotate operations (0-0.20 points) - lowered threshold
        shift_density = features.get('shift_density', 0)
        score += min(shift_density * 3.0, 0.20)  # Was 2.0, now 3.0 for more sensitive
        
        # Loop patterns (0-0.20 points) - lowered threshold
        loop_score = features.get('loop_repetition_score', 0)
        score += min(loop_score * 1.2, 0.20)  # Was 1.0, now 1.2 for more sensitive
        
        # High entropy I/O (0-0.20 points)
        buffer_entropy = features.get('avg_buffer_entropy', 0)
        if buffer_entropy > 7.0:
            score += 0.20
        elif buffer_entropy > 6.0:
            score += 0.10
        
        # Mnemonic entropy (0-0.10 points)
        mnemonic_entropy = features.get('mnemonic_entropy', 0)
        score += min(mnemonic_entropy / 50.0, 0.10)
        
        # AES hardware instructions (0-0.15 points)
        if features.get('has_aes_instructions', 0) > 0:
            score += 0.15
        
        # Register volatility (0-0.10 points)
        register_vol = features.get('register_volatility', 0)
        score += min(register_vol / 500.0, 0.10)
        
        return min(score, 1.0)
    
    def _classify_algorithm(self, features: Dict) -> Dict:
        """
        Classify encryption algorithm based on features.
        
        Heuristics:
        - AES instructions → AES
        - High XOR + shift + tight loops → ChaCha/stream cipher
        - Low instruction diversity → Block cipher (DES/3DES)
        - High computation → RSA/ECC
        """
        evidence = []
        confidence = 0.5
        algorithm = "Unknown"
        crypto_type = "UNKNOWN"
        
        # Check for AES hardware instructions
        if features.get('has_aes_instructions', 0) > 0:
            algorithm = "AES"
            crypto_type = "SYMMETRIC"
            confidence = 0.90
            evidence.append("AES hardware instructions detected")
            evidence.append("aesenc/aesdec opcodes found")
        
        # Check for SHA instructions
        elif features.get('sha_instruction_count', 0) > 0:
            algorithm = "SHA"
            crypto_type = "HASH"
            confidence = 0.85
            evidence.append("SHA hardware instructions detected")
        
        # High XOR + shift + loops → Stream cipher (ChaCha/Salsa)
        # LOWERED thresholds and made more flexible (2 out of 3 conditions)
        has_xor = features.get('xor_density', 0) > 0.08
        has_shift = features.get('shift_density', 0) > 0.05
        has_loops = features.get('loop_repetition_score', 0) > 0.15
        
        # Need at least 2 out of 3 indicators (flexible for obfuscation)
        crypto_indicators = sum([has_xor, has_shift, has_loops])
        
        if crypto_indicators >= 2:
            algorithm = "ChaCha/Stream"
            crypto_type = "SYMMETRIC"
            confidence = 0.60 + (crypto_indicators * 0.05)  # 0.60-0.75 based on indicators
            
            if has_xor:
                evidence.append("XOR operations detected")
            if has_shift:
                evidence.append("rotate/shift operations")
            if has_loops:
                evidence.append("repeated loop structure")
            
            if features.get('mnemonic_entropy', 0) > 3.5:
                evidence.append("high mnemonic entropy")
                confidence += 0.05
            
            # Detect obfuscation
            if features.get('xor_density', 0) < 0.12:
                evidence.append("(possibly obfuscated)")
                algorithm = "ChaCha/Stream (obfuscated)"
        
        # High computation + low loops → Asymmetric (RSA/ECC)
        elif (features.get('total_executions', 0) > 1000 and
              features.get('loop_repetition_score', 0) < 0.2 and
              features.get('register_volatility', 0) > 100):
            algorithm = "RSA/ECC"
            crypto_type = "ASYMMETRIC"
            confidence = 0.65
            evidence.append("high computational complexity")
            evidence.append("low loop repetition")
            evidence.append("high register churn")
        
        # Low entropy + moderate loops → DES/3DES
        elif (features.get('mnemonic_entropy', 0) < 2.0 and
              features.get('loop_repetition_score', 0) > 0.4 and
              features.get('unique_mnemonic_ratio', 0) < 0.3):
            algorithm = "DES/3DES"
            crypto_type = "SYMMETRIC"
            confidence = 0.60
            evidence.append("low instruction diversity")
            evidence.append("repetitive pattern (Feistel network)")
        
        # Fallback: Generic symmetric cipher
        elif features.get('crypto_heuristic_score', 0) > 0.5:
            algorithm = "Generic Symmetric"
            crypto_type = "SYMMETRIC"
            confidence = 0.55
            if features.get('xor_density', 0) > 0.1:
                evidence.append("XOR operations present")
            if features.get('shift_density', 0) > 0.05:
                evidence.append("shift/rotate operations")
            if features.get('loop_repetition_score', 0) > 0.2:
                evidence.append("loop structure detected")
        
        return {
            'algorithm': algorithm,
            'type': crypto_type,
            'confidence': min(confidence, 0.99),
            'evidence': evidence
        }
    
    def _detect_protocol_stage(self, features: Dict, window_context: Optional[List[Dict]]) -> Dict:
        """
        Detect protocol stage based on patterns.
        
        Stages:
        - HANDSHAKE: Low entropy, network syscalls, small buffers
        - KEY_EXCHANGE: Moderate computation, network I/O, growing stack
        - ENCRYPTION: High crypto activity, high entropy buffers
        - DATA_TRANSFER: High network activity, encrypted buffers
        - CLEANUP: Decreasing activity, memory cleanup
        """
        probabilities = {label: 0.0 for label in self.stage_labels}
        
        # === HANDSHAKE indicators ===
        if (features.get('network_syscall_ratio', 0) > 0.3 and
            features.get('avg_buffer_entropy', 0) < 5.0 and
            features.get('crypto_heuristic_score', 0) < 0.3):
            probabilities['HANDSHAKE'] = 0.70
        
        # === KEY_EXCHANGE indicators ===
        if (features.get('network_syscall_ratio', 0) > 0.2 and
            features.get('stack_entropy_slope', 0) > 0.5 and
            features.get('crypto_heuristic_score', 0) > 0.4 and
            features.get('crypto_heuristic_score', 0) < 0.7):
            probabilities['KEY_EXCHANGE'] = 0.75
        
        # === ENCRYPTION indicators (strongest for crypto) ===
        if (features.get('crypto_heuristic_score', 0) > 0.6 and
            features.get('avg_buffer_entropy', 0) > 6.5):
            probabilities['ENCRYPTION'] = 0.85
        
        # Add bonus if previous stage was KEY_EXCHANGE
        if self.stage_history and self.stage_history[-1]['stage'] == 'KEY_EXCHANGE':
            probabilities['ENCRYPTION'] += 0.10
        
        # === DATA_TRANSFER indicators ===
        if (features.get('network_syscall_ratio', 0) > 0.4 and
            features.get('avg_buffer_entropy', 0) > 7.0 and
            features.get('crypto_heuristic_score', 0) < 0.5):
            probabilities['DATA_TRANSFER'] = 0.70
        
        # === CLEANUP indicators ===
        if (features.get('syscall_ratio', 0) > 0.5 and
            features.get('block_count', 0) < 20 and
            features.get('heap_growth', 0) < 0):
            probabilities['CLEANUP'] = 0.60
        
        # Normalize probabilities
        total = sum(probabilities.values())
        if total > 0:
            probabilities = {k: round(v / total, 2) for k, v in probabilities.items()}
        else:
            # Default to ENCRYPTION if no clear indicators
            probabilities['ENCRYPTION'] = 0.50
            probabilities['HANDSHAKE'] = 0.20
            probabilities['KEY_EXCHANGE'] = 0.15
            probabilities['DATA_TRANSFER'] = 0.10
            probabilities['CLEANUP'] = 0.05
        
        # Determine most likely stage
        stage = max(probabilities, key=probabilities.get)
        
        return {
            'stage': stage,
            'probabilities': probabilities
        }
    
    def _classify_behavior(self, features: Dict, crypto_score: float) -> Dict:
        """Classify overall behavior of the window"""
        if crypto_score > 0.7:
            return {'class': 'crypto_routine', 'confidence': crypto_score}
        elif features.get('network_syscall_ratio', 0) > 0.5:
            return {'class': 'network_io', 'confidence': 0.80}
        elif features.get('file_syscall_ratio', 0) > 0.5:
            return {'class': 'file_io', 'confidence': 0.75}
        elif features.get('loop_repetition_score', 0) > 0.6:
            return {'class': 'intensive_computation', 'confidence': 0.70}
        else:
            return {'class': 'normal_execution', 'confidence': 0.60}
    
    def _detect_anomalies(self, features: Dict) -> List[Dict]:
        """Detect anomalies in execution patterns"""
        anomalies = []
        
        # Stack entropy spike
        if features.get('stack_entropy_slope', 0) > 2.0:
            anomalies.append({
                "type": "stack_entropy_spike",
                "severity": "high" if features['stack_entropy_slope'] > 3.0 else "medium",
                "score": round(min(features['stack_entropy_slope'] / 3.0, 1.0), 2),
                "description": f"Stack entropy increased rapidly (slope: {features['stack_entropy_slope']:.2f})"
            })
        
        # Loop repetition anomaly
        if features.get('max_execution_count', 0) > 50:
            anomalies.append({
                "type": "loop_repetition_anomaly",
                "severity": "medium" if features['max_execution_count'] < 100 else "low",
                "score": round(min(features['max_execution_count'] / 100.0, 1.0), 2),
                "description": f"Block executed {features['max_execution_count']} times (tight loop)"
            })
        
        # Register churn anomaly
        if features.get('register_volatility', 0) > 200:
            anomalies.append({
                "type": "register_churn_anomaly",
                "severity": "medium",
                "score": round(min(features['register_volatility'] / 500.0, 1.0), 2),
                "description": f"High register mutation rate ({features['register_volatility']:.0f} changes)"
            })
        
        # High entropy I/O without crypto patterns
        if (features.get('avg_buffer_entropy', 0) > 7.5 and
            features.get('crypto_heuristic_score', 0) < 0.3):
            anomalies.append({
                "type": "suspicious_high_entropy_io",
                "severity": "high",
                "score": round(features['avg_buffer_entropy'] / 8.0, 2),
                "description": "High entropy I/O without crypto patterns (possible obfuscation)"
            })
        
        # Memory leak indicator
        if features.get('heap_growth', 0) > 10000:
            anomalies.append({
                "type": "memory_growth_anomaly",
                "severity": "low",
                "score": round(min(features['heap_growth'] / 100000.0, 1.0), 2),
                "description": f"Heap grew by {features['heap_growth']} bytes"
            })
        
        return anomalies
    
    def _reconstruct_trace(self, window_id: int, stage_result: Dict,
                          window_context: Optional[List[Dict]]) -> Dict:
        """Reconstruct protocol flow across windows"""
        # Get recent history (last 5 windows)
        recent_history = self.stage_history[-5:] if len(self.stage_history) >= 5 else self.stage_history
        
        # Predict next stage based on current
        current_stage = stage_result['stage']
        stage_transitions = {
            'HANDSHAKE': ('KEY_EXCHANGE', 0.85),
            'KEY_EXCHANGE': ('ENCRYPTION', 0.80),
            'ENCRYPTION': ('DATA_TRANSFER', 0.75),
            'DATA_TRANSFER': ('ENCRYPTION', 0.60),  # Can alternate
            'CLEANUP': ('HANDSHAKE', 0.50)  # New session
        }
        
        next_stage, transition_conf = stage_transitions.get(current_stage, ('ENCRYPTION', 0.50))
        
        return {
            "previous_stages": recent_history,
            "current_window_stage": {
                "window": window_id,
                "stage": current_stage
            },
            "next_expected_stage": next_stage,
            "transition_confidence": transition_conf
        }
    
    def _explain_prediction(self, features: Dict, crypto_score: float,
                           stage_result: Dict, algo_result: Dict) -> Dict:
        """
        Generate explainability information.
        
        For production, use SHAP/LIME with trained model.
        This is heuristic-based.
        """
        top_factors = []
        
        # Collect significant factors
        if features.get('xor_density', 0) > 0.15:
            top_factors.append(f"frequent XOR and shift instructions (XOR: {features['xor_density']:.2%})")
        
        if features.get('shift_density', 0) > 0.10:
            top_factors.append(f"high shift/rotate density ({features['shift_density']:.2%})")
        
        if features.get('stack_mutation_rate', 0) > 0.3:
            unique_hashes = int(features['stack_mutation_rate'] * 10)
            top_factors.append(f"stack_hash changed {unique_hashes} times in window")
        
        if features.get('loop_repetition_score', 0) > 0.3:
            max_reps = int(features.get('max_block_repetition', 0))
            top_factors.append(f"loop repetition score = high ({max_reps} identical blocks)")
        
        if features.get('stack_entropy_slope', 0) > 0.5:
            top_factors.append(f"spike in stack entropy (slope: {features['stack_entropy_slope']:.2f})")
        
        if features.get('mnemonic_entropy', 0) > 3.0:
            top_factors.append(f"mnemonic entropy = {features['mnemonic_entropy']:.2f} (high)")
        
        if features.get('avg_buffer_entropy', 0) > 7.0:
            top_factors.append(f"high buffer entropy ({features['avg_buffer_entropy']:.2f})")
        
        if features.get('has_aes_instructions', 0) > 0:
            top_factors.append("AES hardware instructions detected")
        
        if algo_result['algorithm'] in ['ChaCha/Stream', 'AES']:
            top_factors.append(f"{algo_result['algorithm']}-style add-xor-rotate pattern detected")
        
        # Calculate feature importance (normalized weights)
        # These should come from trained model's SHAP values
        # For now, use heuristic weights
        importance = {
            'xor_density': min(features.get('xor_density', 0) * 1.5, 0.25),
            'shift_density': min(features.get('shift_density', 0) * 1.2, 0.20),
            'loop_repetition_score': min(features.get('loop_repetition_score', 0), 0.20),
            'stack_entropy_slope': min(features.get('stack_entropy_slope', 0) / 5.0, 0.15),
            'register_volatility': min(features.get('register_volatility', 0) / 1000.0, 0.10),
            'avg_buffer_entropy': min(features.get('avg_buffer_entropy', 0) / 10.0, 0.10),
            'mnemonic_entropy': min(features.get('mnemonic_entropy', 0) / 50.0, 0.05)
        }
        
        # Normalize importance to sum to 1.0
        total_importance = sum(importance.values())
        if total_importance > 0:
            importance = {k: round(v / total_importance, 2) for k, v in importance.items()}
        
        return {
            "top_factors": top_factors[:8],  # Top 8 factors
            "feature_importance": importance,
            "method": "heuristic" if self.mode == 'heuristic' else "shap",
            "note": "Replace with SHAP/LIME for production ML model"
        }
    
    def reset_history(self):
        """Reset stage history (for new trace analysis)"""
        self.stage_history = []
    
    def analyze_full_trace(self, windowed_features_path: str, output_path: Optional[str] = None) -> List[Dict]:
        """
        Analyze entire trace file (all windows).
        
        Args:
            windowed_features_path: Path to windowed features JSONL
            output_path: Optional output path for results
        
        Returns:
            List of analysis results (one per window)
        """
        results = []
        
        # Reset history for new trace
        self.reset_history()
        
        print(f"[*] Analyzing windowed features: {windowed_features_path}")
        
        with open(windowed_features_path) as f:
            windows = [json.loads(line) for line in f]
        
        print(f"[*] Processing {len(windows)} windows...")
        
        for i, window in enumerate(windows):
            # Get context (previous windows)
            context = results[-5:] if len(results) >= 5 else results
            
            # Analyze window
            result = self.analyze_window(window, context)
            results.append(result)
            
            # Progress update
            if (i + 1) % 50 == 0 or (i + 1) == len(windows):
                print(f"[*] Processed {i + 1}/{len(windows)} windows...")
        
        # Save results if output path provided
        if output_path:
            output_dir = Path(output_path).parent
            output_dir.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                for result in results:
                    f.write(json.dumps(result) + '\n')
            
            print(f"[+] Results saved to: {output_path}")
        
        # Print summary
        self._print_summary(results)
        
        return results
    
    def _print_summary(self, results: List[Dict]):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        
        # Crypto detection stats
        crypto_windows = sum(1 for r in results if r['analysis']['crypto_detection']['is_crypto'])
        print(f"\n📊 Crypto Detection:")
        print(f"   Crypto windows: {crypto_windows}/{len(results)} ({crypto_windows/len(results)*100:.1f}%)")
        
        avg_crypto_prob = np.mean([r['analysis']['crypto_detection']['crypto_probability'] for r in results])
        print(f"   Avg crypto probability: {avg_crypto_prob:.2f}")
        
        # Algorithm distribution
        algorithms = [r['analysis']['crypto_detection']['encryption_algorithm_family']['algorithm'] for r in results]
        algo_counts = Counter(algorithms)
        print(f"\n🔐 Algorithm Distribution:")
        for algo, count in algo_counts.most_common():
            print(f"   {algo}: {count} ({count/len(results)*100:.1f}%)")
        
        # Stage distribution
        stages = [r['analysis']['protocol_stage']['stage'] for r in results]
        stage_counts = Counter(stages)
        print(f"\n📶 Protocol Stage Distribution:")
        for stage, count in stage_counts.most_common():
            print(f"   {stage}: {count} ({count/len(results)*100:.1f}%)")
        
        # Anomalies
        total_anomalies = sum(len(r['analysis']['anomaly_detection']) for r in results)
        print(f"\n⚠️  Anomalies Detected: {total_anomalies}")
        
        if total_anomalies > 0:
            anomaly_types = []
            for r in results:
                for anomaly in r['analysis']['anomaly_detection']:
                    anomaly_types.append(anomaly['type'])
            
            anomaly_counts = Counter(anomaly_types)
            for anom_type, count in anomaly_counts.most_common():
                print(f"   {anom_type}: {count}")
        
        print("\n" + "="*60)


def main():
    """Example usage"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Crypto Protocol Inference Engine"
    )
    parser.add_argument(
        'windowed_features',
        help='Path to windowed features JSONL file'
    )
    parser.add_argument(
        '--output',
        help='Output path for analysis results (default: auto-generate)'
    )
    parser.add_argument(
        '--mode',
        choices=['heuristic', 'ml'],
        default='heuristic',
        help='Analysis mode (default: heuristic)'
    )
    parser.add_argument(
        '--model',
        help='Path to trained ML model (required for ml mode)'
    )
    parser.add_argument(
        '--show-sample',
        action='store_true',
        help='Show first window analysis as example'
    )
    
    args = parser.parse_args()
    
    # Auto-generate output path
    if not args.output:
        input_path = Path(args.windowed_features)
        output_dir = input_path.parent.parent / 'analysis_results'
        output_dir.mkdir(parents=True, exist_ok=True)
        args.output = output_dir / f"{input_path.stem}_analysis.jsonl"
    
    # Create inference engine
    engine = CryptoProtocolInferenceEngine(
        model_path=args.model,
        mode=args.mode
    )
    
    # Analyze full trace
    results = engine.analyze_full_trace(
        args.windowed_features,
        args.output
    )
    
    # Show sample output
    if args.show_sample and results:
        print("\n" + "="*60)
        print("SAMPLE OUTPUT (First Window)")
        print("="*60)
        print(json.dumps(results[0], indent=2))
        print("="*60)


if __name__ == '__main__':
    main()
