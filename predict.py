#!/usr/bin/env python3

import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import argparse

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

def load_model(model_dir):
    model = joblib.load(Path(model_dir) / "xgb_model.joblib")
    scaler = joblib.load(Path(model_dir) / "scaler.joblib")
    le = joblib.load(Path(model_dir) / "label_encoder.joblib")
    return model, scaler, le

def predict_single_row(model_dir, csv_path, row_index):
    model, scaler, le = load_model(model_dir)

    df = pd.read_csv(csv_path)

    # Auto-fix missing columns
    for col in NUMERIC_FEATURES:
        if col not in df.columns:
            print(f"WARNING: Missing column '{col}', filling with 0")
            df[col] = 0.0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    X = df[NUMERIC_FEATURES].values
    X_scaled = scaler.transform(X)

    pred_class = model.predict([X_scaled[row_index]])[0]
    pred_label = le.inverse_transform([pred_class])[0]

    # Try probability prediction
    try:
        pred_prob = model.predict_proba([X_scaled[row_index]])[0]
    except Exception:
        pred_prob = None

    print("\n=== Prediction ===")
    print("Function:", df.loc[row_index]["function_name"])
    print("Predicted Algorithm:", pred_label)

    if pred_prob is not None:
        print("Probabilities:", pred_prob)
    else:
        print("Probabilities: Not available (model uses multi:softmax)")

    print("==================")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=str, required=True)
    parser.add_argument("--row", type=int, default=0)
    parser.add_argument("--model_dir", type=str, default="xgb_out")
    args = parser.parse_args()

    predict_single_row(args.model_dir, args.csv, args.row)

if __name__ == "__main__":
    main()
