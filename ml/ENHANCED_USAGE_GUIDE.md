# Enhanced Cryptographic Function Classifier - Complete Guide

## Overview

This enhanced system provides state-of-the-art cryptographic function classification with:

- **Combined Dataset**: 20,388+ samples from multiple sources with harmonized labels
- **Advanced ML Models**: Multiple algorithms with hyperparameter tuning for maximum recall and accuracy
- **LLM-Powered Analysis**: Detailed explanations and risk assessments for each prediction
- **Detail Labels**: Preserves specific function types (e.g., ChaCha20, Curve25519, Blake2b)
- **Frontend Ready**: JSON output optimized for web applications

## Supported Classifications

### Main Categories (12 types)
- **AES-128, AES-192, AES-256**: Advanced Encryption Standard variants
- **RSA-1024, RSA-4096**: RSA encryption with different key sizes
- **SHA-1, SHA-224, SHA-256**: Secure Hash Algorithm variants  
- **ECC**: Elliptic Curve Cryptography
- **XOR-CIPHER**: XOR-based encryption schemes
- **PRNG**: Pseudo-Random Number Generators
- **Non-Crypto**: Regular functions without cryptographic operations

### Detail Labels (from Ghidra Analysis)
- **AES Variants**: AES, AEAD
- **Hash Functions**: Blake2b, SHA, HMAC  
- **Stream Ciphers**: ChaCha20, Poly1305
- **ECC Types**: Curve25519, EdDSA, DH (Diffie-Hellman)
- **Utilities**: KDF (Key Derivation), Elligator
- And many more specific implementations

## Dataset Processing

### Label Harmonization
The system automatically handles label variants across different datasets:

```
# RSA Harmonization
RSA → RSA-1024 (default)
RSA1024 → RSA-1024  
RSA4096 → RSA-4096

# SHA Harmonization  
SHA → SHA-1 (default)
SHA256 → SHA-256
Blake2b → SHA-256 (hash family)

# AES Harmonization
AES → AES-128 (default)
AEAD → AES-128 (authenticated encryption)
```

### Feature Categories
- **Categorical** (3): architecture, compiler, optimization
- **Boolean** (4): crypto-specific indicators (AES S-box, RSA bigint, etc.)
- **Numerical** (40+): complexity metrics, operation counts, entropy measures

## Model Performance

The system trains and compares multiple models:

1. **Random Forest** - Ensemble with balanced class weights
2. **XGBoost** - Gradient boosting with multi-class optimization
3. **LightGBM** - Fast gradient boosting
4. **Extra Trees** - Randomized ensemble
5. **Gradient Boosting** - Traditional gradient boosting
6. **SVM** - Support Vector Machine with RBF kernel
7. **Neural Network** - Multi-layer perceptron

### Hyperparameter Tuning
- **Grid Search**: Exhaustive parameter optimization
- **Custom Scoring**: 60% recall + 40% accuracy weighting
- **Cross-Validation**: Stratified 5-fold CV
- **Class Balancing**: Handles dataset imbalance

## Usage

### 1. Training (Jupyter Notebook)

```bash
cd ml
# Activate virtual environment
source ../.venv/bin/activate

# Process and combine datasets
python3 process_datasets.py

# Train enhanced models (run notebook)
jupyter notebook enhanced_model.ipynb
```

### 2. Enhanced Command Line Predictions

#### Interactive Mode
```bash
python3 enhanced_predict_crypto.py --interactive
```

#### JSON File Input
```bash
python3 enhanced_predict_crypto.py --features sample.json --analysis
```

#### Batch CSV Processing
```bash
python3 enhanced_predict_crypto.py --csv functions.csv --output results.json --analysis
```

#### Quick Prediction (No Analysis)
```bash
python3 enhanced_predict_crypto.py --features sample.json --no-analysis
```

### 3. Python API Integration

```python
from enhanced_predict_crypto import EnhancedCryptoPredictor

# Initialize predictor
predictor = EnhancedCryptoPredictor()

# Make prediction with full analysis
features = {
    'architecture': 'x86',
    'compiler': 'gcc',
    'optimization': 'O2',
    'function_size': 150,
    'has_aes_sbox': 1,
    # ... other features
}

result = predictor.predict(features, detail_label='AES', return_analysis=True)

print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']:.4f}")
print(f"Risk Level: {result['risk_level']}")
print(f"Analysis: {result['analysis']['summary']}")
```

## LLM-Powered Analysis

### What It Provides

1. **Risk Assessment**: Low/Medium/High risk levels based on confidence and evidence
2. **Evidence Analysis**: Supporting and contradicting feature indicators
3. **Technical Explanation**: Detailed reasoning behind the prediction
4. **Confidence Assessment**: Human-readable confidence interpretation
5. **Recommendations**: Action items based on risk level

### Sample Analysis Output

```json
{
  "prediction": "AES-128",
  "confidence": 0.8947,
  "risk_level": "Low",
  "analysis": {
    "summary": "Predicted as AES-128 (specifically ChaCha20) with 89.5% confidence.",
    "confidence_assessment": "This prediction has high confidence (89.5%). Risk level: Low.",
    "evidence_summary": "Found 4 supporting indicators and 1 contradicting indicators.",
    "technical_details": "• AES S-box lookup tables: 1 (supports prediction)\n• Cryptographic constants detected: 45 (supports prediction)",
    "recommendations": "✅ Low risk prediction. Confidence is high."
  }
}
```

## Frontend Integration

### JSON API Response Format

```json
{
  "prediction": "AES-128",
  "confidence": 0.8947,
  "probabilities": {
    "AES-128": 0.8947,
    "AES-256": 0.0623,
    "XOR-CIPHER": 0.0234,
    "Non-Crypto": 0.0196
  },
  "detail_label": "ChaCha20",
  "risk_level": "Low",
  "analysis": {
    "summary": "Human-readable summary",
    "confidence_assessment": "Confidence interpretation", 
    "evidence_summary": "Evidence count",
    "technical_details": "Detailed technical reasoning",
    "recommendations": "Action recommendations",
    "supporting_features": 4,
    "contradicting_features": 1
  },
  "model_info": {
    "model_name": "RandomForest_tuned",
    "training_date": "2024-12-02T...", 
    "model_accuracy": 0.9234
  }
}
```

### Frontend Display Components

#### Prediction Card
```html
<div class="prediction-card">
  <div class="prediction-header">
    <h3>🎯 {prediction}</h3>
    <span class="confidence-badge">{confidence}%</span>
  </div>
  
  <div class="detail-info">
    <span class="detail-label">Specific Type: {detail_label}</span>
    <span class="risk-level risk-{risk_level.toLowerCase()}">{risk_level} Risk</span>
  </div>
  
  <div class="analysis-summary">
    <p>{analysis.summary}</p>
    <p>{analysis.recommendations}</p>
  </div>
</div>
```

#### Probability Chart
```javascript
// Create probability visualization
const probData = Object.entries(result.probabilities)
  .sort(([,a], [,b]) => b - a)
  .slice(0, 5);

// Use Chart.js, D3.js, or similar for visualization
```

#### Technical Details Accordion
```html
<details class="technical-details">
  <summary>🔧 Technical Analysis</summary>
  <div class="evidence-grid">
    <div class="supporting">
      <h4>✅ Supporting Evidence</h4>
      <p>Found {supporting_features} indicators</p>
    </div>
    <div class="contradicting">
      <h4>❌ Contradicting Evidence</h4>
      <p>Found {contradicting_features} indicators</p>
    </div>
  </div>
  <pre class="technical-text">{analysis.technical_details}</pre>
</details>
```

## Feature Extraction Integration

### Binary Analysis Pipeline

```python
def analyze_and_classify_function(binary_path, function_address):
    """Complete analysis pipeline"""
    
    # Step 1: Extract features using your existing tools
    features = extract_features_from_ghidra(binary_path, function_address)
    
    # Step 2: Enhance with detail analysis
    detail_info = get_detailed_function_info(binary_path, function_address)
    
    # Step 3: Classify using enhanced ML
    predictor = EnhancedCryptoPredictor()
    result = predictor.predict(features, detail_info.get('detail_label'))
    
    # Step 4: Return frontend-ready results
    return {
        'function_address': function_address,
        'crypto_classification': result['prediction'],
        'confidence': result['confidence'],
        'risk_level': result['risk_level'],
        'is_cryptographic': result['prediction'] != 'Non-Crypto',
        'detailed_analysis': result['analysis'],
        'recommendations': result['analysis']['recommendations']
    }
```

## Performance Optimization

### Confidence Thresholds
- **High Confidence** (>0.9): Automatic classification
- **Medium Confidence** (0.7-0.9): Flag for review
- **Low Confidence** (<0.7): Manual analysis required

### Batch Processing
- Use `--csv` mode for large datasets
- JSON output for detailed analysis
- CSV output for simple results

### Model Selection
- **RandomForest**: Best balance of speed and accuracy
- **XGBoost**: Highest accuracy, slower training
- **LightGBM**: Fastest training, good accuracy

## Troubleshooting

### Common Issues

1. **Model Not Found**
   ```bash
   # Train models first
   python3 process_datasets.py
   jupyter notebook enhanced_model.ipynb  # Run all cells
   ```

2. **Missing Features**
   - System automatically fills missing features with defaults
   - Categorical: 'unknown'
   - Numerical: 0 or median values

3. **Poor Performance**
   - Retrain with more representative data
   - Adjust confidence thresholds
   - Use ensemble predictions

4. **Memory Issues**
   - Process in batches for large datasets
   - Use `--no-analysis` for faster processing
   - Consider feature selection

## Advanced Customization

### Custom Scoring Function
```python
def custom_scorer(y_true, y_pred):
    accuracy = accuracy_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred, average='macro')
    # Adjust weights based on your requirements
    return 0.6 * recall + 0.4 * accuracy
```

### Adding New Feature Types
1. Update `categorical_features` or `numerical_features` lists
2. Modify preprocessing pipeline
3. Retrain models with new features

### Custom Detail Label Mapping
```python
custom_mapping = {
    'MyCustomCrypto': 'AES-256',
    'SpecialHash': 'SHA-256'
}
# Add to CryptoDatasetHarmonizer.detail_to_main_mapping
```

This enhanced system provides production-ready cryptographic function classification with comprehensive analysis suitable for security research, malware analysis, and automated binary classification systems.