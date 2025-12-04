import joblib
import pandas as pd
import numpy as np

class CryptoPredictionAnalyzer:
    """
    Analyzes cryptographic function predictions using LLM for detailed explanations
    """
    
    def __init__(self):
        self.crypto_indicators = {
            'AES': ['has_aes_sbox', 'has_aes_rcon', 'crypto_constant_hits', 'bitwise_ops'],
            'RSA': ['rsa_bigint_detected', 'function_size', 'arithmetic_ops', 'cyclomatic_complexity'],
            'SHA': ['has_sha_constants', 'crypto_constant_hits', 'bitwise_ops', 'rotate_ratio'],
            'ECC': ['arithmetic_ops', 'multiply_ratio', 'cyclomatic_complexity', 'function_size'],
            'XOR': ['xor_ratio', 'bitwise_ops', 'logical_ratio'],
            'PRNG': ['entropy', 'arithmetic_ops', 'logical_ratio']
        }
        
        self.feature_descriptions = {
            'has_aes_sbox': 'Presence of AES S-box lookup tables',
            'has_aes_rcon': 'Presence of AES round constants',  
            'rsa_bigint_detected': 'Detection of big integer operations typical in RSA',
            'has_sha_constants': 'Presence of SHA algorithm constants',
            'crypto_constant_hits': 'Number of cryptographic constants detected',
            'bitwise_ops': 'Number of bitwise operations',
            'arithmetic_ops': 'Number of arithmetic operations',
            'xor_ratio': 'Ratio of XOR operations to total operations',
            'rotate_ratio': 'Ratio of rotate operations to total operations',
            'multiply_ratio': 'Ratio of multiplication operations',
            'cyclomatic_complexity': 'Measure of code complexity',
            'function_size': 'Size of the function in instructions',
            'entropy': 'Code entropy measure'
        }
    
    def analyze_feature_evidence(self, features, prediction, probabilities, detail_label=None):
        """
        Analyze feature values to provide evidence for the prediction
        """
        
        # Convert features to dict if it's a DataFrame row
        if hasattr(features, 'to_dict'):
            feature_dict = features.to_dict()
        else:
            feature_dict = features
        
        analysis = {
            'prediction': prediction,
            'confidence': max(probabilities),
            'detail_label': detail_label if detail_label != 'Not Available' else None,
            'evidence': [],
            'supporting_features': [],
            'contradicting_features': [],
            'risk_assessment': 'Low'
        }
        
        # Determine prediction category
        pred_category = self._get_prediction_category(prediction)
        
        # Get relevant indicators for this category
        relevant_indicators = self.crypto_indicators.get(pred_category, [])
        
        # Analyze each relevant feature
        for feature in relevant_indicators:
            if feature in feature_dict:
                value = feature_dict[feature]
                description = self.feature_descriptions.get(feature, feature)
                
                # Determine if this feature supports the prediction
                is_supporting = self._is_feature_supporting(feature, value, pred_category)
                
                evidence_item = {
                    'feature': feature,
                    'value': value,
                    'description': description,
                    'supporting': is_supporting
                }
                
                analysis['evidence'].append(evidence_item)
                
                if is_supporting:
                    analysis['supporting_features'].append(evidence_item)
                else:
                    analysis['contradicting_features'].append(evidence_item)
        
        # Assess confidence and risk
        analysis['risk_assessment'] = self._assess_risk(analysis['confidence'], 
                                                      len(analysis['supporting_features']),
                                                      len(analysis['contradicting_features']))
        
        return analysis
    
    def _get_prediction_category(self, prediction):
        """Get the main category from prediction"""
        if 'AES' in prediction:
            return 'AES'
        elif 'RSA' in prediction:
            return 'RSA'
        elif 'SHA' in prediction:
            return 'SHA'
        elif 'ECC' in prediction:
            return 'ECC'
        elif 'XOR' in prediction:
            return 'XOR'
        elif 'PRNG' in prediction:
            return 'PRNG'
        else:
            return 'Other'
    
    def _is_feature_supporting(self, feature, value, category):
        """Determine if a feature value supports the predicted category"""
        
        # Boolean features
        if feature in ['has_aes_sbox', 'has_aes_rcon', 'rsa_bigint_detected', 'has_sha_constants']:
            return value > 0
        
        # Ratio features (higher values generally indicate more activity)
        if feature in ['xor_ratio', 'rotate_ratio', 'multiply_ratio']:
            return value > 0.05  # Threshold for significant activity
        
        # Count features
        if feature in ['crypto_constant_hits', 'bitwise_ops', 'arithmetic_ops']:
            return value > 10  # Threshold for significant activity
        
        # Complexity features
        if feature in ['cyclomatic_complexity', 'function_size']:
            if category in ['RSA', 'ECC']:
                return value > 50  # RSA/ECC tend to be more complex
            else:
                return value > 10  # Other crypto functions
        
        # Entropy
        if feature == 'entropy':
            return value > 6.0  # High entropy suggests crypto operations
        
        return True  # Default to supporting
    
    def _assess_risk(self, confidence, supporting_count, contradicting_count):
        """Assess the risk level of the prediction"""
        
        if confidence > 0.9 and supporting_count > contradicting_count:
            return 'Low'
        elif confidence > 0.7 and supporting_count >= contradicting_count:
            return 'Medium'
        else:
            return 'High'
    
    def generate_detailed_report(self, analysis):
        """Generate a detailed human-readable report"""
        
        report = {
            'summary': '',
            'confidence_assessment': '',
            'evidence_summary': '',
            'technical_details': '',
            'recommendations': ''
        }
        
        pred = analysis['prediction']
        conf = analysis['confidence']
        detail = analysis['detail_label']
        risk = analysis['risk_assessment']
        
        # Summary
        if detail:
            report['summary'] = f"Predicted as {pred} (specifically {detail}) with {conf:.1%} confidence."
        else:
            report['summary'] = f"Predicted as {pred} with {conf:.1%} confidence."
        
        # Confidence assessment
        if conf > 0.9:
            conf_desc = "very high"
        elif conf > 0.7:
            conf_desc = "high" 
        elif conf > 0.5:
            conf_desc = "moderate"
        else:
            conf_desc = "low"
        
        report['confidence_assessment'] = f"This prediction has {conf_desc} confidence ({conf:.1%}). Risk level: {risk}."
        
        # Evidence summary
        supporting = len(analysis['supporting_features'])
        contradicting = len(analysis['contradicting_features'])
        
        report['evidence_summary'] = f"Found {supporting} supporting indicators and {contradicting} contradicting indicators."
        
        # Technical details
        tech_details = []
        
        for evidence in analysis['evidence'][:5]:  # Top 5 most relevant
            support_text = "supports" if evidence['supporting'] else "contradicts"
            tech_details.append(f"• {evidence['description']}: {evidence['value']} ({support_text} prediction)")
        
        report['technical_details'] = "\\n".join(tech_details)
        
        # Recommendations
        if risk == 'High':
            report['recommendations'] = "High risk prediction. Manual review recommended."
        elif risk == 'Medium':
            report['recommendations'] = "Medium risk prediction. Consider additional validation."
        else:
            report['recommendations'] = "Low risk prediction. Confidence is high."
        
        return report

class EnhancedCryptoPipeline:
    """
    Complete pipeline for crypto function prediction with LLM analysis
    """
    
    def __init__(self, model_pipeline, label_encoder, analyzer, class_names, 
                 categorical_features, numerical_features, boolean_features):
        self.model_pipeline = model_pipeline
        self.label_encoder = label_encoder
        self.analyzer = analyzer
        self.class_names = class_names
        self.categorical_features = categorical_features
        self.numerical_features = numerical_features
        self.boolean_features = boolean_features
        self.feature_columns = categorical_features + boolean_features + numerical_features
    
    def predict_with_analysis(self, features, include_detail_label=None):
        """
        Make prediction with comprehensive analysis
        """
        
        # Prepare features - handle both Series and DataFrame inputs
        if isinstance(features, dict):
            # Convert dict to DataFrame
            feature_df = pd.DataFrame([features])
        elif isinstance(features, pd.Series):
            # Convert Series to DataFrame
            feature_df = pd.DataFrame([features])
        else:
            feature_df = features.copy()
        
        # Ensure all required columns are present
        for col in self.feature_columns:
            if col not in feature_df.columns:
                if col in self.categorical_features:
                    feature_df[col] = 'unknown'
                else:
                    feature_df[col] = 0
        
        # Reorder columns
        feature_df = feature_df[self.feature_columns]
        
        # Make prediction
        prediction_encoded = self.model_pipeline.predict(feature_df)[0]
        probabilities = self.model_pipeline.predict_proba(feature_df)[0]
        
        # Convert to readable format
        prediction = self.label_encoder.inverse_transform([prediction_encoded])[0]
        
        # Create probability dictionary
        prob_dict = {}
        for i, class_name in enumerate(self.class_names):
            prob_dict[class_name] = probabilities[i]
        
        # Perform LLM analysis
        analysis = self.analyzer.analyze_feature_evidence(
            feature_df.iloc[0], prediction, probabilities, include_detail_label
        )
        
        # Generate detailed report
        detailed_report = self.analyzer.generate_detailed_report(analysis)
        
        return {
            'prediction': prediction,
            'confidence': max(probabilities),
            'probabilities': prob_dict,
            'detail_label': include_detail_label,
            'analysis': analysis,
            'detailed_report': detailed_report,
            'risk_level': analysis['risk_assessment']
        }
    
    def batch_predict_with_analysis(self, features_list, detail_labels=None):
        """
        Batch prediction with analysis
        """
        results = []
        
        for i, features in enumerate(features_list):
            detail_label = detail_labels[i] if detail_labels else None
            result = self.predict_with_analysis(features, detail_label)
            results.append(result)
        
        return results
