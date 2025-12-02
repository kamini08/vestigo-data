#!/usr/bin/env python3
"""
Enhanced Crypto Function Dataset Processor
Combines multiple datasets, harmonizes labels, and creates comprehensive ML pipeline
"""

import pandas as pd
import numpy as np
import os
import warnings
warnings.filterwarnings('ignore')

class CryptoDatasetHarmonizer:
    """
    Harmonizes labels across different datasets and handles various crypto function variants
    """
    
    def __init__(self):
        # Define label harmonization mapping
        self.label_mapping = {
            # AES variants -> standardized AES labels
            'AES': 'AES-128',  # Default AES to AES-128
            'AES128': 'AES-128',
            'AES-128': 'AES-128',
            'AES192': 'AES-192', 
            'AES-192': 'AES-192',
            'AES256': 'AES-256',
            'AES-256': 'AES-256',
            
            # RSA variants -> standardized RSA labels  
            'RSA': 'RSA-1024',  # Default RSA to RSA-1024
            'RSA1024': 'RSA-1024',
            'RSA-1024': 'RSA-1024',
            'RSA4096': 'RSA-4096',
            'RSA-4096': 'RSA-4096',
            
            # SHA variants -> standardized SHA labels
            'SHA': 'SHA-1',  # Default SHA to SHA-1
            'SHA1': 'SHA-1',
            'SHA-1': 'SHA-1', 
            'SHA224': 'SHA-224',
            'SHA-224': 'SHA-224',
            'SHA256': 'SHA-256',
            'SHA-256': 'SHA-256',
            
            # XOR variants
            'XOR': 'XOR-CIPHER',
            'XOR-CIPHER': 'XOR-CIPHER',
            
            # ECC (keep as is)
            'ECC': 'ECC',
            
            # PRNG (keep as is) 
            'PRNG': 'PRNG',
            
            # Non-Crypto (keep as is)
            'Non-Crypto': 'Non-Crypto'
        }
        
        # Detail label to main label mapping for ghidra dataset
        self.detail_to_main_mapping = {
            # AES related
            'AES': 'AES-128',
            'AEAD': 'AES-128',  # AEAD often uses AES
            
            # Hash functions
            'Blake2b': 'SHA-256',  # Blake2b is a hash function similar to SHA
            'SHA': 'SHA-1',
            'HMAC': 'SHA-1',  # HMAC typically uses SHA
            
            # Stream ciphers
            'ChaCha20': 'XOR-CIPHER',
            'Poly1305': 'XOR-CIPHER',
            
            # ECC related  
            'Curve25519': 'ECC',
            'EdDSA': 'ECC', 
            'DH': 'ECC',  # Diffie-Hellman on elliptic curves
            'ECC': 'ECC',
            'Elligator': 'ECC',
            
            # RSA
            'RSA': 'RSA-1024',
            
            # Utilities and non-crypto
            'Non-Crypto': 'Non-Crypto',
            'Utility': 'Non-Crypto',
            'KDF': 'Non-Crypto',  # Key derivation functions
        }
        
        # Standard features expected in all datasets
        self.standard_features = [
            'architecture', 'compiler', 'optimization', 'filename', 'function_name',
            'function_address', 'label', 'num_basic_blocks', 'num_edges', 
            'cyclomatic_complexity', 'loop_count', 'loop_depth', 'branch_density',
            'average_block_size', 'num_entry_exit_paths', 'strongly_connected_components',
            'instruction_count', 'immediate_entropy', 'bitwise_op_density', 
            'crypto_constant_hits', 'branch_condition_complexity', 'add_ratio',
            'logical_ratio', 'load_store_ratio', 'xor_ratio', 'multiply_ratio',
            'rotate_ratio', 'has_aes_sbox', 'rsa_bigint_detected', 'has_aes_rcon',
            'has_sha_constants', 'rodata_refs_count', 'string_refs_count',
            'stack_frame_size', 'bitwise_ops', 'crypto_like_ops', 'arithmetic_ops',
            'mem_ops_ratio', 'function_byte_entropy', 'opcode_entropy',
            'cyclomatic_complexity_density', 'unique_ngram_count'
        ]
    
    def clean_and_normalize_dataset(self, df, dataset_name):
        """Clean and normalize a single dataset"""
        print(f"Processing {dataset_name}...")
        print(f"Original shape: {df.shape}")
        
        # Remove completely empty rows
        df = df.dropna(how='all')
        
        # Clean label column - remove any malformed entries
        if 'label' in df.columns:
            # Remove rows with malformed labels (containing JSON or other artifacts)
            mask = df['label'].astype(str).str.contains(r'[{}"]|load_store_ratio|opcode_ratios', na=False)
            if mask.any():
                print(f"Removing {mask.sum()} rows with malformed labels")
                df = df[~mask]
            
            # Remove rows with empty or numeric-only labels
            mask = df['label'].astype(str).str.match(r'^\s*$|^\d+$', na=False)
            if mask.any():
                print(f"Removing {mask.sum()} rows with empty/numeric labels")
                df = df[~mask]
        
        # Add dataset source
        df['dataset_source'] = dataset_name
        
        # Handle detail_label if it exists (only in ghidra dataset)
        if 'detail_label' in df.columns:
            df['detail_label'] = df['detail_label'].fillna('Unknown')
        else:
            df['detail_label'] = 'Not Available'
        
        # Standardize boolean columns
        bool_columns = ['has_aes_sbox', 'rsa_bigint_detected', 'has_aes_rcon', 'has_sha_constants']
        for col in bool_columns:
            if col in df.columns:
                # Convert various boolean representations to 0/1
                df[col] = df[col].astype(str).str.upper()
                df[col] = df[col].replace({'TRUE': 1, 'FALSE': 0, 'True': 1, 'False': 1, '1': 1, '0': 0, 'NAN': 0})
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
        
        print(f"Cleaned shape: {df.shape}")
        return df
    
    def harmonize_labels(self, df, use_detail_mapping=False):
        """Harmonize labels across datasets"""
        if 'label' not in df.columns:
            return df
            
        # For ghidra dataset, first map detail_label to main categories if requested
        if use_detail_mapping and 'detail_label' in df.columns:
            df['original_label'] = df['label'].copy()
            df['label'] = df['detail_label'].map(self.detail_to_main_mapping).fillna(df['label'])
        
        # Apply main label harmonization
        df['standardized_label'] = df['label'].map(self.label_mapping).fillna(df['label'])
        
        # Update the label column
        df['label'] = df['standardized_label']
        df = df.drop(columns=['standardized_label'], errors='ignore')
        
        return df
    
    def align_features(self, df):
        """Ensure all datasets have the same feature columns"""
        # Add missing columns with default values
        for feature in self.standard_features:
            if feature not in df.columns:
                if feature in ['architecture', 'compiler', 'optimization', 'filename', 'function_name', 'function_address']:
                    df[feature] = 'unknown'
                elif feature == 'label':
                    df[feature] = 'Non-Crypto' 
                else:
                    df[feature] = 0
        
        # Reorder columns to match standard order
        available_features = [f for f in self.standard_features if f in df.columns]
        additional_cols = ['detail_label', 'dataset_source'] + [col for col in df.columns 
                          if col not in available_features and col not in ['detail_label', 'dataset_source']]
        
        df = df[available_features + additional_cols]
        
        return df
    
    def load_and_process_datasets(self, dataset_paths):
        """Load and process all datasets"""
        processed_datasets = []
        
        for path, name in dataset_paths:
            if not os.path.exists(path):
                print(f"Warning: {path} not found, skipping...")
                continue
                
            try:
                # Load dataset
                df = pd.read_csv(path)
                
                # Clean and normalize
                df = self.clean_and_normalize_dataset(df, name)
                
                # Harmonize labels (use detail mapping only for ghidra dataset)
                use_detail = (name == 'ghidra')
                df = self.harmonize_labels(df, use_detail_mapping=use_detail)
                
                # Align features
                df = self.align_features(df)
                
                processed_datasets.append(df)
                print(f"✅ Successfully processed {name}: {df.shape}")
                
            except Exception as e:
                print(f"❌ Error processing {name}: {str(e)}")
                continue
        
        return processed_datasets
    
    def combine_datasets(self, datasets):
        """Combine all processed datasets"""
        if not datasets:
            raise ValueError("No datasets to combine")
        
        print(f"\nCombining {len(datasets)} datasets...")
        combined = pd.concat(datasets, ignore_index=True, sort=False)
        
        # Final cleaning
        combined = combined.dropna(subset=['label'])
        
        # Convert numeric columns
        numeric_columns = [col for col in combined.columns 
                          if col not in ['architecture', 'compiler', 'optimization', 'filename', 
                                       'function_name', 'function_address', 'label', 'detail_label', 
                                       'dataset_source', 'source_file']]
        
        for col in numeric_columns:
            combined[col] = pd.to_numeric(combined[col], errors='coerce')
        
        # Fill remaining NaN values
        combined = combined.fillna({col: 0 for col in numeric_columns})
        combined = combined.fillna({col: 'unknown' for col in combined.select_dtypes(include=['object']).columns})
        
        print(f"✅ Combined dataset shape: {combined.shape}")
        
        # Print label distribution
        print(f"\n📊 Final label distribution:")
        label_counts = combined['label'].value_counts()
        for label, count in label_counts.items():
            print(f"  {label}: {count}")
        
        return combined

def main():
    """Main processing function"""
    print("🚀 Starting Enhanced Crypto Dataset Processing...")
    
    # Initialize harmonizer
    harmonizer = CryptoDatasetHarmonizer()
    
    # Define dataset paths
    base_path = "/home/bhoomi/Desktop/compilerRepo/vestigo-data"
    dataset_paths = [
        (f"{base_path}/ml/dataset.csv", "training"),
        (f"{base_path}/ml/test_dataset.csv", "testing"), 
        (f"{base_path}/ghidra_features_labeled.csv", "ghidra")
    ]
    
    # Process datasets
    processed_datasets = harmonizer.load_and_process_datasets(dataset_paths)
    
    if not processed_datasets:
        print("❌ No datasets could be processed!")
        return None
    
    # Combine datasets
    combined_df = harmonizer.combine_datasets(processed_datasets)
    
    # Save combined dataset
    output_path = f"{base_path}/ml/combined_harmonized_dataset.csv"
    combined_df.to_csv(output_path, index=False)
    print(f"✅ Combined dataset saved to: {output_path}")
    
    # Create detailed analysis
    print(f"\n📈 Dataset Analysis:")
    print(f"Total samples: {len(combined_df)}")
    print(f"Total features: {len(combined_df.columns)}")
    
    print(f"\n📊 Dataset sources:")
    source_counts = combined_df['dataset_source'].value_counts()
    for source, count in source_counts.items():
        print(f"  {source}: {count}")
    
    print(f"\n🏷️ Detail label distribution (from ghidra dataset):")
    ghidra_data = combined_df[combined_df['dataset_source'] == 'ghidra']
    if len(ghidra_data) > 0:
        detail_counts = ghidra_data['detail_label'].value_counts()
        for detail, count in detail_counts.head(10).items():
            print(f"  {detail}: {count}")
    
    return combined_df

if __name__ == "__main__":
    combined_data = main()