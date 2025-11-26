#!/usr/bin/env python3
"""
Train XGBoostClassifier on the aggregated function-level features.
Optimized for XGBoost 1.6.2 (supports early_stopping_rounds + eval_metric).
"""

import argparse
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    classification_report, confusion_matrix
)
from xgboost import XGBClassifier

# ----------------------------------------------------------------
#  Required numeric features (your exact list)
# ----------------------------------------------------------------
NUMERIC_FEATURES = [
    "num_basic_blocks",
    "num_edges",
    "cyclomatic_complexity",
    "loop_count",
    "loop_depth",
    "branch_density",
    "average_block_size",
    "num_entry_exit_paths",
    "strongly_connected_components",
    "instruction_count",
    "xor_ratio",
    "immediate_entropy",
    "logical_ratio",
    "load_store_ratio",
    "bitwise_op_density",
    "table_lookup_presence",
    "crypto_constant_hits",
    "branch_condition_complexity",
    "num_conditional_edges",
    "num_unconditional_edges",
    "num_loop_edges",
    "avg_edge_branch_condition_complexity"
]

# ----------------------------------------------------------------
#  Load CSV + fix missing columns
# ----------------------------------------------------------------
def load_features(csv_path: Path):
    df = pd.read_csv(csv_path)

    # Auto-fix typos
    if "avg_edge_branch_complexity" in df.columns:
        print("NOTE: Renaming 'avg_edge_branch_complexity' → 'avg_edge_branch_condition_complexity'")
        df.rename(columns={"avg_edge_branch_complexity": "avg_edge_branch_condition_complexity"}, inplace=True)

    # Missing columns → zero filled
    for col in NUMERIC_FEATURES:
        if col not in df.columns:
            print(f"WARNING: Missing `{col}` → creating zero column.")
            df[col] = 0.0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Remove rows without label
    df = df[~df["label"].isna()]

    return df

# ----------------------------------------------------------------
#  Train/val/test split (stratified)
# ----------------------------------------------------------------
def stratified_split(X, y, test_frac=0.15, val_frac=0.15):
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=test_frac, stratify=y, random_state=42
    )

    val_rel = val_frac / (1 - test_frac)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=val_rel, stratify=y_temp, random_state=42
    )

    return X_train, X_val, X_test, y_train, y_val, y_test

# ----------------------------------------------------------------
#  Evaluation helper
# ----------------------------------------------------------------
def evaluate(model, X, y, label_encoder, name="Test"):
    y_pred = model.predict(X)

    acc = accuracy_score(y, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y, y_pred, average="weighted", zero_division=0
    )

    print(f"\n===== {name} Metrics =====")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")

    print("\nClassification Report:")
    print(classification_report(y, y_pred, zero_division=0))

    print("Confusion Matrix:")
    print(confusion_matrix(y, y_pred))

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}

# ----------------------------------------------------------------
#  MAIN TRAINING PIPELINE
# ----------------------------------------------------------------
def main(args):
    csv_path = Path(args.csv)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(exist_ok=True, parents=True)

    print(f"\nLoading CSV: {csv_path}")
    df = load_features(csv_path)

    # Labels
    le = LabelEncoder()
    y = le.fit_transform(df["label"].astype(str))

    # Features
    X = df[NUMERIC_FEATURES].values

    print(f"Found classes: {list(le.classes_)} (n={len(le.classes_)})")
    print(f"Feature matrix shape: {X.shape}")

    # Splits
    X_train, X_val, X_test, y_train, y_val, y_test = stratified_split(
        X, y, test_frac=args.test_frac, val_frac=args.val_frac
    )
    print(f"Splits -> train: {len(X_train)}, val: {len(X_val)}, test: {len(X_test)}")

    # Scaling
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)

    joblib.dump(scaler, out_dir / "scaler.joblib")
    joblib.dump(le, out_dir / "label_encoder.joblib")

    # XGBoost v1.6.2 compatible parameters
    eval_metric = "mlogloss" if len(le.classes_) > 2 else "logloss"

    model = XGBClassifier(
        n_estimators=500,
        max_depth=7,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softmax" if len(le.classes_) > 2 else "binary:logistic",
        eval_metric=eval_metric,   # works in 1.6.2
        n_jobs=-1,
        random_state=42
    )

    print("\nTraining XGBoost (compatible with v1.6.2)...")

    model.fit(
        X_train_s, y_train,
        eval_set=[(X_val_s, y_val)],
        early_stopping_rounds=30,   # ✔ WORKS IN 1.6.2
        verbose=True
    )

    print("\nTraining completed!")

    # Evaluate
    val_metrics = evaluate(model, X_val_s, y_val, le, "Validation")
    test_metrics = evaluate(model, X_test_s, y_test, le, "Test")

    # Save artifacts
    joblib.dump(model, out_dir / "xgb_model.joblib")
    joblib.dump(
        {
            "val": val_metrics,
            "test": test_metrics,
            "classes": list(le.classes_),
        },
        out_dir / "metrics_summary.joblib"
    )

    print(f"\nAll artifacts saved in {out_dir.resolve()}")


# CLI
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=str, default="features_output.csv")
    parser.add_argument("--out_dir", type=str, default="xgb_out")
    parser.add_argument("--test_frac", type=float, default=0.15)
    parser.add_argument("--val_frac", type=float, default=0.15)
    args = parser.parse_args()
    main(args)

