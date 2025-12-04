#!/usr/bin/env python3
"""
Fixed Cryptographic Function Classifier - Command Line Tool

Simplified prediction tool that works with CSV/JSON files without LLM components.
Provides class-wise probabilities for all algorithms.

Usage:
    python crypto_predict.py --features sample.json
    python crypto_predict.py --csv input.csv --output predictions.csv
    python crypto_predict.py --interactive
"""

import argparse
import json
import pandas as pd
import joblib
import sys
import os
import numpy as np
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class CryptoPredictor:
    """Simple cryptographic function predictor"""
    
    def __init__(self, model_path=None, metadata_path=None):
        """Initialize the predictor with saved model"""
        
        if model_path is None:
            model_path = Path(__file__).parent / 'saved_models' / 'current_crypto_model.pkl'
        if metadata_path is None:
            metadata_path = Path(__file__).parent / 'saved_models' / 'current_model_metadata.pkl'
        
        if not os.path.exists(model_path) or not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Model files not found. Please train a model first.")
        
        self.model = joblib.load(model_path)
        self.metadata = joblib.load(metadata_path)
        
        self.class_names = self.metadata['class_names']
        self.feature_columns = self.metadata['feature_columns']
        self.categorical_features = self.metadata['categorical_features']
        self.numerical_features = self.metadata['numerical_features']
        
        print(f"Model loaded: {self.metadata['model_name']}")
        print(f"Classes: {len(self.class_names)}")
        print(f"Features: {len(self.feature_columns)}")
    
    def preprocess_features(self, features_dict):
        """Properly preprocess features handling categorical and numerical separately"""
        
        # Convert to DataFrame
        df = pd.DataFrame([features_dict])
        
        # Handle missing features
        for col in self.feature_columns:
            if col not in df.columns:
                if col in self.categorical_features:
                    df[col] = 'unknown'  # Default for categorical
                else:
                    df[col] = 0  # Default for numerical
        
        # Ensure correct order
        df = df[self.feature_columns]
        
        # Handle categorical columns properly
        for col in self.categorical_features:
            if col in df.columns:
                df[col] = df[col].astype(str).fillna('unknown')
        
        # Handle numerical columns
        for col in self.numerical_features:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        return df
    
    def predict(self, features_dict):
        """Make prediction and return all probabilities"""
        
        try:
            # Preprocess features
            df = self.preprocess_features(features_dict)
            
            # Make prediction
            prediction = self.model.predict(df)[0]
            probabilities = self.model.predict_proba(df)[0]
            
            # Create probability dictionary for all classes
            prob_dict = {}
            for i, class_name in enumerate(self.class_names):
                prob_dict[class_name] = float(probabilities[i])
            
            # Get top 3 predictions
            sorted_probs = sorted(prob_dict.items(), key=lambda x: x[1], reverse=True)
            
            result = {
                'prediction': prediction,
                'confidence': float(max(probabilities)),
                'probabilities': prob_dict,
                'top_predictions': [
                    {'class': class_name, 'probability': prob} 
                    for class_name, prob in sorted_probs[:3]
                ],
                'model_info': {
                    'model_name': self.metadata['model_name'],
                    'model_accuracy': self.metadata.get('model_accuracy', 'Unknown')
                }
            }
            
            return result
            
        except Exception as e:
            return {
                'error': str(e),
                'prediction': None,
                'confidence': 0.0
            }
    
    def predict_batch(self, features_list):
        """Predict for multiple samples"""
        results = []
        for i, features in enumerate(features_list):
            result = self.predict(features)
            result['sample_index'] = i
            results.append(result)
        return results
    
    def interactive_mode(self):
        """Interactive mode for manual feature input"""
        
        print("Interactive Crypto Function Prediction")
        print("=" * 50)
        print("Enter feature values (press Enter for default):")
        
        features = {}
        
        # Categorical features
        print("\\nCategorical Features:")
        for feature in self.categorical_features:
            default = 'x86' if feature == 'architecture' else 'gcc' if feature == 'compiler' else 'O2'
            value = input(f"{feature} (default: {default}): ").strip()
            features[feature] = value if value else default
        
        # Key numerical features for user input
        key_features = [
            'num_basic_blocks', 'num_instructions', 'cyclomatic_complexity',
            'has_aes_sbox', 'rsa_bigint_detected', 'has_aes_rcon', 'has_sha_constants'
        ]
        
        print("\\nKey Numerical Features:")
        for feature in key_features:
            if feature in self.numerical_features:
                default = 1 if feature.startswith('has_') or feature.endswith('_detected') else 0
                value = input(f"{feature} (default: {default}): ").strip()
                try:
                    features[feature] = float(value) if value else default
                except ValueError:
                    features[feature] = default
        
        # Set defaults for remaining numerical features
        for feature in self.numerical_features:
            if feature not in features:
                features[feature] = 0
        
        return features

def load_features_from_file(filepath):
    """Load features from JSON file"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None

def process_csv_file(input_file, output_file, predictor):
    """Process CSV file with predictions"""
    try:
        df = pd.read_csv(input_file)
        results = []
        
        print(f"Processing {len(df)} samples...")
        
        for idx, row in df.iterrows():
            features = row.to_dict()
            result = predictor.predict(features)
            
            # Add original data
            result_row = {
                'sample_id': idx,
                'prediction': result['prediction'],
                'confidence': result['confidence']
            }
            
            # Add all class probabilities
            for class_name in predictor.class_names:
                result_row[f'prob_{class_name}'] = result['probabilities'][class_name]
            
            # Add top 3 predictions
            for i, top_pred in enumerate(result['top_predictions']):
                result_row[f'top_{i+1}_class'] = top_pred['class']
                result_row[f'top_{i+1}_prob'] = top_pred['probability']
            
            results.append(result_row)
        
        # Save results
        results_df = pd.DataFrame(results)
        results_df.to_csv(output_file, index=False)
        
        print(f"Results saved to {output_file}")
        
        # Print summary
        pred_counts = results_df['prediction'].value_counts()
        print("\\nPrediction Summary:")
        for pred, count in pred_counts.items():
            print(f"  {pred}: {count} samples")
        
    except Exception as e:
        print(f"Error processing CSV file: {e}")

def print_prediction_results(result):
    """Print prediction results in formatted way"""
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        return
    
    print("\\nPREDICTION RESULTS")
    print("=" * 50)
    print(f"Predicted Function: {result['prediction']}")
    print(f"Confidence: {result['confidence']:.4f} ({result['confidence']*100:.1f}%)")
    
    print("\\nAll Class Probabilities:")
    sorted_probs = sorted(result['probabilities'].items(), key=lambda x: x[1], reverse=True)
    for class_name, prob in sorted_probs:
        indicator = ">>> " if class_name == result['prediction'] else "    "
        print(f"{indicator}{class_name}: {prob:.4f} ({prob*100:.1f}%)")
    
    print(f"\\nModel: {result['model_info']['model_name']}")

def main():
    parser = argparse.ArgumentParser(description="Crypto Function Classifier")
    parser.add_argument('--features', '-f', help='Input JSON file with features')
    parser.add_argument('--csv', help='Input CSV file with features')
    parser.add_argument('--output', '-o', help='Output CSV file for batch processing')
    parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--model-path', help='Path to model file')
    parser.add_argument('--metadata-path', help='Path to metadata file')
    
    args = parser.parse_args()
    
    if not any([args.features, args.csv, args.interactive]):
        parser.print_help()
        return
    
    try:
        # Initialize predictor
        predictor = CryptoPredictor(args.model_path, args.metadata_path)
        
        # Single file prediction
        if args.features:
            print(f"Loading features from: {args.features}")
            features = load_features_from_file(args.features)
            
            if features:
                result = predictor.predict(features)
                print_prediction_results(result)
            else:
                print("Failed to load features file")
        
        # CSV processing
        elif args.csv:
            if not args.output:
                print("Output file required for CSV processing")
                return
            
            print(f"Processing CSV: {args.csv}")
            process_csv_file(args.csv, args.output, predictor)
        
        # Interactive mode
        elif args.interactive:
            features = predictor.interactive_mode()
            result = predictor.predict(features)
            print_prediction_results(result)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()