#!/usr/bin/env python3
"""
Extract REAL feature importance from trained model
Simple and robust version
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from pathlib import Path

def main():
    print("="*80)
    print("EXTRACTING REAL FEATURE IMPORTANCE FROM TRAINED MODEL")
    print("="*80)

    # Load model
    model_path = Path("ml/saved_models/current_crypto_model.pkl")
    metadata_path = Path("ml/saved_models/current_model_metadata.pkl")

    if not model_path.exists():
        print(f"❌ Model not found: {model_path}")
        return

    print("\n Loading model...")
    model_pipeline = joblib.load(model_path)
    metadata = joblib.load(metadata_path)

    print(f"✓ Model: {metadata['model_name']}")
    print(f"✓ Accuracy: {metadata.get('model_accuracy', 'N/A'):.4f}")
    print(f"✓ Classes: {metadata['class_names']}")

    # Get the classifier
    classifier = model_pipeline.named_steps['classifier']
    preprocessor = model_pipeline.named_steps['preprocessor']

    # Get feature names
    categorical_features = metadata['categorical_features']
    numerical_features = metadata['numerical_features']

    print(f"\n Feature Info:")
    print(f"  Categorical: {categorical_features}")
    print(f"  Numerical: {len(numerical_features)} features")

    # Get one-hot encoded feature names
    try:
        cat_encoder = preprocessor.named_transformers_['cat'].named_steps['encoder']
        cat_feature_names = list(cat_encoder.get_feature_names_out(categorical_features))
    except:
        cat_feature_names = []

    # All feature names after preprocessing
    feature_names = list(numerical_features) + cat_feature_names

    print(f"\n Total features after preprocessing: {len(feature_names)}")

    # Extract feature importance
    if hasattr(classifier, 'feature_importances_'):
        importances = classifier.feature_importances_
        print(f"✓ Extracted feature_importances_ from {type(classifier).__name__}")
        print(f"  Feature importance array length: {len(importances)}")
    else:
        print(f"❌ Model {type(classifier).__name__} doesn't have feature_importances_")
        return

    # Check length match
    if len(feature_names) != len(importances):
        print(f"⚠ Length mismatch: {len(feature_names)} feature names vs {len(importances)} importances")
        print(f"  Adjusting feature names to match...")
        # Trim or pad feature names
        if len(feature_names) < len(importances):
            feature_names += [f'unknown_feature_{i}' for i in range(len(importances) - len(feature_names))]
        else:
            feature_names = feature_names[:len(importances)]

    # Create DataFrame
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    }).sort_values('importance', ascending=False)

    print(f"\n" + "="*80)
    print("TOP 30 MOST IMPORTANT FEATURES")
    print("="*80)

    for idx, row in importance_df.head(30).iterrows():
        print(f"{row.name+1:3d}. {row['feature']:45s} : {row['importance']:.6f}")

    # Save to CSV
    importance_df.to_csv('model_feature_importance.csv', index=False)
    print(f"\n✓ Saved all features to: model_feature_importance.csv")

    # Create visualization
    print(f"\n Creating visualizations...")

    # Plot 1: Top 30 features
    plt.figure(figsize=(14, 10))

    top_30 = importance_df.head(30)

    # Color by feature type
    colors = []
    for feat in top_30['feature']:
        if feat in numerical_features:
            if 'has_' in feat or 'detected' in feat:
                colors.append('#e74c3c')  # Red for crypto signatures
            elif 'ratio' in feat or 'density' in feat:
                colors.append('#3498db')  # Blue for ratios
            elif 'entropy' in feat:
                colors.append('#1abc9c')  # Teal for entropy
            elif 'count' in feat or 'ops' in feat:
                colors.append('#2ecc71')  # Green for counts
            else:
                colors.append('#95a5a6')  # Gray for other
        else:
            colors.append('#f39c12')  # Orange for categorical

    bars = plt.barh(range(len(top_30)), top_30['importance'], color=colors, alpha=0.7, edgecolor='black')
    plt.yticks(range(len(top_30)), top_30['feature'])
    plt.xlabel('Feature Importance', fontsize=12, fontweight='bold')
    plt.title(f'Top 30 Most Important Features\n({metadata["model_name"]} Model)',
              fontsize=14, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.grid(axis='x', alpha=0.3)

    # Add value labels
    for i, (bar, imp) in enumerate(zip(bars, top_30['importance'])):
        plt.text(imp + max(importances)*0.01, bar.get_y() + bar.get_height()/2,
                f'{imp:.4f}', va='center', ha='left', fontsize=8)

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#e74c3c', alpha=0.7, label='Crypto Signatures'),
        Patch(facecolor='#3498db', alpha=0.7, label='Ratios/Densities'),
        Patch(facecolor='#1abc9c', alpha=0.7, label='Entropy Metrics'),
        Patch(facecolor='#2ecc71', alpha=0.7, label='Counts/Ops'),
        Patch(facecolor='#f39c12', alpha=0.7, label='Categorical'),
        Patch(facecolor='#95a5a6', alpha=0.7, label='Other')
    ]
    plt.legend(handles=legend_elements, loc='lower right', fontsize=9)

    plt.tight_layout()
    plt.savefig('real_model_feature_importance.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: real_model_feature_importance.png")

    # Plot 2: Feature importance by category
    plt.figure(figsize=(12, 8))

    # Categorize features
    feature_categories = {
        'Crypto Signatures': [],
        'Operation Ratios': [],
        'Entropy & Complexity': [],
        'Counts & Operations': [],
        'Control Flow': [],
        'Categorical': []
    }

    for idx, row in importance_df.iterrows():
        feat = row['feature']
        imp = row['importance']

        if feat in cat_feature_names:
            feature_categories['Categorical'].append(imp)
        elif 'has_' in feat or 'detected' in feat or 'constant' in feat:
            feature_categories['Crypto Signatures'].append(imp)
        elif 'ratio' in feat or 'density' in feat:
            feature_categories['Operation Ratios'].append(imp)
        elif 'entropy' in feat or 'complexity' in feat or 'ngram' in feat:
            feature_categories['Entropy & Complexity'].append(imp)
        elif 'count' in feat or feat.endswith('_ops'):
            feature_categories['Counts & Operations'].append(imp)
        elif 'loop' in feat or 'block' in feat or 'edge' in feat or 'branch' in feat:
            feature_categories['Control Flow'].append(imp)
        else:
            feature_categories['Counts & Operations'].append(imp)

    # Calculate total importance per category
    category_totals = {cat: sum(vals) for cat, vals in feature_categories.items()}
    category_df = pd.DataFrame(list(category_totals.items()),
                               columns=['Category', 'Total Importance']).sort_values('Total Importance', ascending=False)

    colors_cat = ['#e74c3c', '#3498db', '#1abc9c', '#2ecc71', '#9b59b6', '#f39c12']

    plt.barh(range(len(category_df)), category_df['Total Importance'],
            color=colors_cat[:len(category_df)], alpha=0.7, edgecolor='black')
    plt.yticks(range(len(category_df)), category_df['Category'])
    plt.xlabel('Total Feature Importance', fontsize=12, fontweight='bold')
    plt.title('Feature Importance by Category', fontsize=14, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.grid(axis='x', alpha=0.3)

    # Add value labels and feature counts
    for i, (idx, row) in enumerate(category_df.iterrows()):
        cat = row['Category']
        val = row['Total Importance']
        n_features = len(feature_categories[cat])
        plt.text(val + max(category_df['Total Importance'])*0.01, i,
                f'{val:.3f} ({n_features} features)', va='center', ha='left', fontsize=10)

    plt.tight_layout()
    plt.savefig('real_model_feature_categories.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: real_model_feature_categories.png")

    # Plot 3: Cumulative importance
    plt.figure(figsize=(14, 7))

    sorted_importance = np.sort(importances)[::-1]
    cumulative_importance = np.cumsum(sorted_importance)

    plt.plot(range(1, len(cumulative_importance)+1), cumulative_importance,
            linewidth=2, color='#3498db')
    plt.axhline(y=0.9, color='#e74c3c', linestyle='--', linewidth=2,
               label='90% importance threshold')

    # Find number of features for 90% importance
    n_features_90 = np.argmax(cumulative_importance >= 0.9) + 1
    plt.axvline(x=n_features_90, color='#2ecc71', linestyle='--', linewidth=2,
               label=f'{n_features_90} features = 90% importance')

    plt.xlabel('Number of Features', fontsize=12, fontweight='bold')
    plt.ylabel('Cumulative Importance', fontsize=12, fontweight='bold')
    plt.title('Cumulative Feature Importance', fontsize=14, fontweight='bold')
    plt.grid(alpha=0.3)
    plt.legend(fontsize=11)

    plt.tight_layout()
    plt.savefig('real_model_cumulative_importance.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: real_model_cumulative_importance.png")

    print(f"\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"\nKey Insights:")
    print(f"  • Top feature: {importance_df.iloc[0]['feature']} ({importance_df.iloc[0]['importance']:.6f})")
    print(f"  • Features for 90% importance: {n_features_90} out of {len(feature_names)}")
    print(f"  • Most important category: {category_df.iloc[0]['Category']} ({category_df.iloc[0]['Total Importance']:.4f})")

    print(f"\n Top 10 Crypto-Related Features:")
    crypto_features = importance_df[importance_df['feature'].str.contains('has_|detected|constant|xor|rotate|bitwise|aes|rsa|sha', case=False, na=False)]
    for idx, row in crypto_features.head(10).iterrows():
        print(f"  • {row['feature']:40s}: {row['importance']:.6f}")

    print(f"\n" + "="*80)
    print("Analysis complete!")
    print("="*80)

    plt.show()

if __name__ == "__main__":
    main()
