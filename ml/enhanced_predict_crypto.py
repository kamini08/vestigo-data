#!/usr/bin/env python3
"""
Enhanced Cryptographic Function Classifier - Command Line Tool with LLM Analysis

This script provides comprehensive cryptographic function classification with:
- Multiple ML models with hyperparameter tuning
- LLM-powered detailed analysis and explanations
- Support for detail labels from Ghidra analysis
- Frontend-ready JSON output
- Risk assessment and confidence scoring

Usage:
    python enhanced_predict_crypto.py --features features.json
    python enhanced_predict_crypto.py --interactive
    python enhanced_predict_crypto.py --csv input.csv --output predictions.csv
    python enhanced_predict_crypto.py --batch samples/ --output batch_results.json
"""

import argparse
import json
import pandas as pd
import joblib
import sys
import os
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class EnhancedCryptoPredictor:
    """Enhanced cryptographic function predictor with LLM analysis"""
    
    def __init__(self, pipeline_path=None):
        """Initialize the predictor with saved pipeline"""
        
        if pipeline_path is None:
            pipeline_path = Path(__file__).parent / 'enhanced_crypto_pipeline.pkl'
        
        if not os.path.exists(pipeline_path):
            # Fallback to basic model if enhanced pipeline not available
            basic_model_path = Path(__file__).parent / 'saved_models' / 'current_crypto_model.pkl'
            basic_metadata_path = Path(__file__).parent / 'saved_models' / 'current_model_metadata.pkl'
            
            if os.path.exists(basic_model_path) and os.path.exists(basic_metadata_path):
                print("⚠️ Enhanced pipeline not found, using basic model...")
                self._load_basic_model(basic_model_path, basic_metadata_path)
                self.enhanced_mode = False
            else:
                raise FileNotFoundError(f"No model files found. Please train a model first.")
        else:
            self._load_enhanced_pipeline(pipeline_path)
            self.enhanced_mode = True
    
    def _load_enhanced_pipeline(self, pipeline_path):
        """Load enhanced pipeline with LLM analysis"""
        
        pipeline_data = joblib.load(pipeline_path)
        self.pipeline = pipeline_data['pipeline']
        self.model_name = pipeline_data['model_name']
        self.training_date = pipeline_data['training_date']
        self.performance_metrics = pipeline_data['performance_metrics']
        self.class_names = pipeline_data['class_names']
        self.feature_columns = pipeline_data['feature_columns']
        
        print(f"✅ Enhanced pipeline loaded: {self.model_name}")
        print(f"📅 Training date: {self.training_date}")
        print(f"🎯 Model accuracy: {self.performance_metrics['accuracy']:.4f}")
    
    def _load_basic_model(self, model_path, metadata_path):
        """Fallback to basic model loading"""
        
        self.basic_model = joblib.load(model_path)
        self.metadata = joblib.load(metadata_path)
        self.class_names = self.metadata['class_names']
        self.feature_columns = self.metadata['feature_columns']
        
        print(f"✅ Basic model loaded: {self.metadata['model_name']}")
    
    def predict(self, features, detail_label=None, return_analysis=True):
        """Make prediction with optional detailed analysis"""
        
        if self.enhanced_mode and return_analysis:
            # Use enhanced pipeline with LLM analysis
            result = self.pipeline.predict_with_analysis(features, detail_label)
            
            return {
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'probabilities': result['probabilities'],
                'detail_label': result['detail_label'],
                'risk_level': result['risk_level'],
                'analysis': {
                    'summary': result['detailed_report']['summary'],
                    'confidence_assessment': result['detailed_report']['confidence_assessment'],
                    'evidence_summary': result['detailed_report']['evidence_summary'],
                    'technical_details': result['detailed_report']['technical_details'],
                    'recommendations': result['detailed_report']['recommendations'],
                    'supporting_features': len(result['analysis']['supporting_features']),
                    'contradicting_features': len(result['analysis']['contradicting_features'])
                },
                'model_info': {
                    'model_name': self.model_name,
                    'training_date': self.training_date,
                    'model_accuracy': self.performance_metrics['accuracy']
                }
            }
        else:
            # Basic prediction without analysis
            if self.enhanced_mode:
                result = self.pipeline.predict_with_analysis(features, detail_label)
                return {
                    'prediction': result['prediction'],
                    'confidence': result['confidence'],
                    'probabilities': result['probabilities'],
                    'detail_label': result['detail_label'],
                    'model_info': {'model_name': self.model_name}
                }
            else:
                # Use basic model
                df = pd.DataFrame([features])
                for col in self.feature_columns:
                    if col not in df.columns:
                        if col in ['architecture', 'compiler', 'optimization']:
                            df[col] = 'unknown'
                        else:
                            df[col] = 0
                
                df = df[self.feature_columns]
                prediction = self.basic_model.predict(df)[0]
                probabilities = self.basic_model.predict_proba(df)[0]
                
                prob_dict = {}
                for i, class_name in enumerate(self.class_names):
                    prob_dict[class_name] = probabilities[i]
                
                return {
                    'prediction': prediction,
                    'confidence': max(probabilities),
                    'probabilities': prob_dict,
                    'detail_label': detail_label,
                    'model_info': {'model_name': self.metadata['model_name']}
                }
    
    def interactive_mode(self):
        """Interactive mode for manual feature input"""
        
        print("🔮 Enhanced Interactive Crypto Function Prediction")
        print("=" * 60)
        print("Enter feature values (press Enter for default values):")
        
        features = {}
        
        # Key features with descriptions
        key_features = {
            'architecture': ('Target architecture', 'x86'),
            'compiler': ('Compiler used', 'gcc'),
            'optimization': ('Optimization level', 'O2'),
            'function_size': ('Function size in bytes', '100'),
            'num_basic_blocks': ('Number of basic blocks', '10'),
            'cyclomatic_complexity': ('Cyclomatic complexity', '5'),
            'has_aes_sbox': ('AES S-box detected (0/1)', '0'),
            'rsa_bigint_detected': ('RSA bigint detected (0/1)', '0'),
            'has_aes_rcon': ('AES round constants detected (0/1)', '0'),
            'has_sha_constants': ('SHA constants detected (0/1)', '0'),
            'bitwise_ops': ('Number of bitwise operations', '20'),
            'crypto_constant_hits': ('Crypto constants detected', '0'),
            'xor_ratio': ('XOR operation ratio', '0.1'),
            'entropy': ('Code entropy', '6.0')
        }
        
        print(f"\n📂 Key Features:")
        for feature, (desc, default) in key_features.items():
            value = input(f"{desc} [{default}]: ").strip()
            
            if feature in ['architecture', 'compiler', 'optimization']:
                features[feature] = value if value else default
            else:
                try:
                    features[feature] = float(value) if value else float(default)
                except ValueError:
                    features[feature] = float(default)
        
        # Ask for detail label if available
        detail_label = input(f"\nDetail label (if known): ").strip()
        if not detail_label:
            detail_label = None
        
        # Set defaults for remaining features
        for col in self.feature_columns:
            if col not in features:
                if col in ['architecture', 'compiler', 'optimization']:
                    features[col] = 'unknown'
                else:
                    features[col] = 0
        
        return features, detail_label
    
    def process_csv_batch(self, input_file, output_file, include_analysis=True):
        """Process CSV file with multiple samples"""
        
        try:
            df = pd.read_csv(input_file)
            results = []
            
            print(f"📊 Processing {len(df)} samples from {input_file}...")
            
            for idx, row in df.iterrows():
                features = row.to_dict()
                detail_label = features.get('detail_label', None)
                
                # Remove non-feature columns
                for col in ['label', 'detail_label', 'dataset_source']:
                    features.pop(col, None)
                
                result = self.predict(features, detail_label, include_analysis)
                
                # Add original data
                result['original_data'] = row.to_dict()
                result['sample_id'] = idx
                
                results.append(result)
                
                if (idx + 1) % 100 == 0:
                    print(f"  Processed {idx + 1}/{len(df)} samples...")
            
            # Save results
            if output_file.endswith('.json'):
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            else:
                # Convert to CSV
                csv_results = []
                for result in results:
                    csv_row = {
                        'prediction': result['prediction'],
                        'confidence': result['confidence'],
                        'detail_label': result.get('detail_label', ''),
                        'risk_level': result.get('risk_level', 'Unknown')
                    }
                    
                    # Add top 3 probabilities
                    sorted_probs = sorted(result['probabilities'].items(), 
                                        key=lambda x: x[1], reverse=True)
                    for i, (class_name, prob) in enumerate(sorted_probs[:3]):
                        csv_row[f'prob_{i+1}_{class_name}'] = prob
                    
                    csv_results.append(csv_row)
                
                pd.DataFrame(csv_results).to_csv(output_file, index=False)
            
            print(f"✅ Results saved to: {output_file}")
            
            # Print summary
            predictions = [r['prediction'] for r in results]
            pred_counts = pd.Series(predictions).value_counts()
            
            print(f"\n📊 Prediction Summary:")
            for pred, count in pred_counts.head(10).items():
                print(f"  {pred}: {count}")
            
            if include_analysis and self.enhanced_mode:
                risk_levels = [r.get('risk_level', 'Unknown') for r in results]
                risk_counts = pd.Series(risk_levels).value_counts()
                print(f"\n⚖️ Risk Level Summary:")
                for risk, count in risk_counts.items():
                    print(f"  {risk}: {count}")
            
        except Exception as e:
            print(f"❌ Error processing CSV: {str(e)}")
            return False
        
        return True

def print_prediction_results(result):
    """Print prediction results in formatted way"""
    
    print("\n🔮 ENHANCED PREDICTION RESULTS")
    print("=" * 70)
    
    # Basic results
    print(f"🎯 Prediction: {result['prediction']}")
    print(f"🎲 Confidence: {result['confidence']:.4f} ({result['confidence']*100:.1f}%)")
    
    if result.get('detail_label'):
        print(f"🔍 Detail Type: {result['detail_label']}")
    
    if result.get('risk_level'):
        risk_emoji = {"Low": "✅", "Medium": "⚠️", "High": "❌"}.get(result['risk_level'], "❓")
        print(f"{risk_emoji} Risk Level: {result['risk_level']}")
    
    # Model info
    model_info = result.get('model_info', {})
    print(f"🤖 Model: {model_info.get('model_name', 'Unknown')}")
    if 'model_accuracy' in model_info:
        print(f"📊 Model Accuracy: {model_info['model_accuracy']:.4f}")
    
    # Probabilities
    print(f"\n📊 Class Probabilities:")
    sorted_probs = sorted(result['probabilities'].items(), key=lambda x: x[1], reverse=True)
    for i, (class_name, prob) in enumerate(sorted_probs):
        indicator = "🎯" if i == 0 else "  "
        print(f"{indicator} {class_name}: {prob:.4f} ({prob*100:.1f}%)")
    
    # Detailed analysis (if available)
    analysis = result.get('analysis')
    if analysis:
        print(f"\n📝 DETAILED ANALYSIS")
        print("-" * 40)
        print(f"Summary: {analysis['summary']}")
        print(f"Confidence Assessment: {analysis['confidence_assessment']}")
        print(f"Evidence: {analysis['evidence_summary']}")
        print(f"Recommendations: {analysis['recommendations']}")
        
        if analysis.get('technical_details'):
            print(f"\n🔧 Technical Details:")
            print(analysis['technical_details'])

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Cryptographic Function Classifier with LLM Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Interactive mode with detailed analysis
    python enhanced_predict_crypto.py --interactive
    
    # Predict from JSON with analysis
    python enhanced_predict_crypto.py --features sample.json --analysis
    
    # Batch process CSV with analysis
    python enhanced_predict_crypto.py --csv input.csv --output results.json --analysis
    
    # Quick prediction without analysis
    python enhanced_predict_crypto.py --features sample.json --no-analysis
        """
    )
    
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Interactive mode for manual feature input')
    parser.add_argument('--features', '-f', type=str,
                        help='JSON file containing features')
    parser.add_argument('--csv', '-c', type=str,
                        help='CSV file with multiple feature sets')
    parser.add_argument('--output', '-o', type=str,
                        help='Output file for batch predictions')
    parser.add_argument('--pipeline', type=str,
                        help='Path to enhanced pipeline file')
    parser.add_argument('--analysis', action='store_true', default=True,
                        help='Include detailed LLM analysis (default: True)')
    parser.add_argument('--no-analysis', action='store_true',
                        help='Skip detailed analysis for faster predictions')
    
    args = parser.parse_args()
    
    # Determine if analysis should be included
    include_analysis = args.analysis and not args.no_analysis
    
    # Initialize predictor
    try:
        predictor = EnhancedCryptoPredictor(args.pipeline)
    except Exception as e:
        print(f"❌ Error loading predictor: {str(e)}")
        sys.exit(1)
    
    # Process based on arguments
    if args.interactive:
        features, detail_label = predictor.interactive_mode()
        result = predictor.predict(features, detail_label, include_analysis)
        print_prediction_results(result)
        
    elif args.features:
        try:
            with open(args.features, 'r') as f:
                features = json.load(f)
            
            detail_label = features.pop('detail_label', None)
            result = predictor.predict(features, detail_label, include_analysis)
            print_prediction_results(result)
            
        except Exception as e:
            print(f"❌ Error processing features file: {str(e)}")
            sys.exit(1)
            
    elif args.csv:
        if not args.output:
            base_name = Path(args.csv).stem
            args.output = f"{base_name}_enhanced_predictions.json"
        
        success = predictor.process_csv_batch(args.csv, args.output, include_analysis)
        if not success:
            sys.exit(1)
            
    else:
        parser.print_help()
        print("\n💡 Tip: Use --interactive for guided prediction with detailed analysis!")

if __name__ == "__main__":
    main()