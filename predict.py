#!/usr/bin/env python3

import pandas as pd
import random

def predict_from_dataframe(df, model_dir="xgb_out"):
    """
    Dummy predictor that simulates ML inference.
    Returns a list of dictionaries with mock predictions.
    """
    results = []
    
    # Check if we have the necessary columns to make a heuristic guess
    has_constants = "crypto_constant_hits" in df.columns
    
    for i in range(len(df)):
        row = df.iloc[i]
        func_name = row.get("function_name", "Unknown")
        
        # Simple Mock Logic
        # If we found constants in static analysis, predict a crypto algo
        # Otherwise, mostly predict Non-Crypto
        
        predicted_label = "Non-Crypto"
        confidence = 0.95
        
        if has_constants and row["crypto_constant_hits"] > 0:
            # Simulate detection
            predicted_label = random.choice(["AES", "SHA-256", "MD5", "ChaCha20"])
            confidence = 0.99
        elif "encrypt" in str(func_name).lower():
            predicted_label = "AES"
            confidence = 0.85
        elif "hash" in str(func_name).lower():
            predicted_label = "SHA-256"
            confidence = 0.88
            
        res = {
            "function_name": func_name,
            "predicted_algorithm": predicted_label,
            "confidence": confidence
        }
        results.append(res)
        
    return results

def main():
    print("Dummy Predictor: Run via analyzer.py")

if __name__ == "__main__":
    main()
