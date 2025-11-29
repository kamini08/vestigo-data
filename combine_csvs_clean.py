#!/usr/bin/env python3
"""
Clean script to combine CSV files with exactly 47 columns.
Handles malformed CSV files and ensures consistent schema.
"""

import pandas as pd
import numpy as np
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

def combine_csv_files_clean():
    # Define the exact 47 columns we want
    EXPECTED_COLUMNS = [
        'architecture', 'algorithm', 'compiler', 'optimization', 
        'filename', 'function_name', 'function_address', 'label',
        'num_basic_blocks', 'num_edges', 'cyclomatic_complexity', 
        'loop_count', 'loop_depth', 'branch_density', 
        'average_block_size', 'num_entry_exit_paths', 
        'strongly_connected_components', 'num_conditional_edges',
        'num_unconditional_edges', 'num_loop_edges', 
        'avg_edge_branch_condition_complexplexity', 'instruction_count',
        'immediate_entropy', 'bitwise_op_density', 'crypto_constant_hits',
        'branch_condition_complexity', 'add_ratio', 'logical_ratio',
        'load_store_ratio', 'xor_ratio', 'multiply_ratio', 'rotate_ratio',
        'has_aes_sbox', 'rsa_bigint_detected', 'has_aes_rcon', 
        'has_sha_constants', 'rodata_refs_count', 'string_refs_count',
        'stack_frame_size', 'bitwise_ops', 'crypto_like_ops', 
        'arithmetic_ops', 'mem_ops_ratio', 'function_byte_entropy',
        'opcode_entropy', 'cyclomatic_complexity_density', 'unique_ngram_count'
    ]
    
    csvfiles_dir = Path("ml/csvfiles")
    output_file = "dataset.csv"
    
    print("=== Clean CSV Dataset Combiner (47 columns) ===")
    print(f"Target columns: {len(EXPECTED_COLUMNS)}")
    
    csv_files = list(csvfiles_dir.glob("*.csv"))
    print(f"Found {len(csv_files)} CSV files")
    
    combined_data = []
    
    for csv_file in csv_files:
        print(f"\n--- Processing {csv_file.name} ---")
        
        try:
            # Read the CSV file without column restrictions first
            df = pd.read_csv(csv_file)
            
            print(f"  Original columns: {len(df.columns)}")
            print(f"  Rows: {len(df)}")
            
            # Handle different cases
            if len(df.columns) == 47:
                # Perfect case - rename to expected columns
                df.columns = EXPECTED_COLUMNS
                print(f"  ✅ Perfect match - renamed to standard columns")
                
            elif len(df.columns) < 47:
                # Missing columns case (like xor with 43 cols)
                print(f"  ⚠️  File has {len(df.columns)} columns, need 47")
                
                # For xor file specifically, we know it's missing 4 boolean columns
                if csv_file.name == 'xor_crypto_dataset.csv' and len(df.columns) == 43:
                    # xor file has columns 1-32, then missing 33-36, then has 33-43 (which are actually 37-47)
                    # So we need to insert the 4 missing boolean columns at positions 33-36
                    
                    # First, get the current column names
                    current_cols = list(df.columns)
                    
                    # Create a new dataframe with the correct structure
                    new_df = pd.DataFrame(index=df.index)
                    
                    # Copy first 32 columns (architecture through rotate_ratio)
                    for i in range(32):
                        new_df[EXPECTED_COLUMNS[i]] = df.iloc[:, i]
                    
                    # Add the 4 missing boolean columns with NaN
                    missing_bool_cols = ['has_aes_sbox', 'rsa_bigint_detected', 'has_aes_rcon', 'has_sha_constants']
                    for col in missing_bool_cols:
                        new_df[col] = np.nan
                    
                    # Copy remaining columns (rodata_refs_count through unique_ngram_count)
                    for i in range(32, 43):  # remaining columns in xor file
                        new_df[EXPECTED_COLUMNS[i + 4]] = df.iloc[:, i]  # +4 offset due to inserted columns
                    
                    df = new_df
                    print(f"  ✅ Fixed xor file structure - added 4 missing boolean columns with NaN")
                else:
                    # Generic handling for other files with missing columns
                    existing_cols = min(len(df.columns), len(EXPECTED_COLUMNS))
                    df.columns = EXPECTED_COLUMNS[:existing_cols]
                    
                    # Add missing columns with NaN
                    for col in EXPECTED_COLUMNS[existing_cols:]:
                        df[col] = np.nan
                    
                    # Reorder to match expected order
                    df = df[EXPECTED_COLUMNS]
                    print(f"  ✅ Added {47 - existing_cols} missing columns with NaN")
                
            else:
                # Too many columns - take only first 47 meaningful columns
                # This handles malformed CSV files with extra commas
                df = df.iloc[:, :47]
                df.columns = EXPECTED_COLUMNS
                print(f"  ⚠️  Truncated from {len(df.columns) + (df.shape[1] - 47)} to 47 columns")
            
            # Add source file tracking
            df['source_file'] = csv_file.name
            
            # Verify final structure
            assert len(df.columns) == 48  # 47 + source_file
            assert list(df.columns[:47]) == EXPECTED_COLUMNS
            
            combined_data.append(df)
            print(f"  ✅ Successfully processed: {len(df)} rows × {len(df.columns)} columns")
            
        except Exception as e:
            print(f"  ❌ Error processing {csv_file.name}: {e}")
            continue
    
    if not combined_data:
        print("❌ No files were successfully processed!")
        return
    
    # Combine all dataframes
    print(f"\n=== Combining {len(combined_data)} DataFrames ===")
    final_df = pd.concat(combined_data, ignore_index=True)
    
    print(f"Final dataset shape: {final_df.shape}")
    print(f"Columns: {len(final_df.columns)} (47 features + 1 source)")
    
    # Verify column structure
    expected_final_cols = EXPECTED_COLUMNS + ['source_file']
    assert list(final_df.columns) == expected_final_cols, "Column mismatch!"
    
    # Show summary statistics
    print(f"\n=== Dataset Summary ===")
    print(f"Total rows: {len(final_df):,}")
    print(f"Total columns: {len(final_df.columns)} (47 features + source)")
    
    print(f"\n=== Source File Distribution ===")
    source_counts = final_df['source_file'].value_counts()
    for source, count in source_counts.items():
        print(f"  {source}: {count:,} rows")
    
    print(f"\n=== Algorithm Distribution ===")
    if 'algorithm' in final_df.columns:
        algo_counts = final_df['algorithm'].value_counts().head(15)
        for algo, count in algo_counts.items():
            print(f"  {algo}: {count:,} rows")
    
    print(f"\n=== Label Distribution ===")
    if 'label' in final_df.columns:
        label_counts = final_df['label'].value_counts().head(15)
        for label, count in label_counts.items():
            print(f"  {label}: {count:,} rows")
    
    # Calculate data completeness
    print(f"\n=== Data Completeness ===")
    total_cells = len(final_df) * 47  # Only count the 47 feature columns
    feature_df = final_df[EXPECTED_COLUMNS]
    non_null_cells = feature_df.count().sum()
    null_cells = total_cells - non_null_cells
    print(f"Feature cells: {total_cells:,}")
    print(f"Non-null: {non_null_cells:,} ({100*non_null_cells/total_cells:.1f}%)")
    print(f"Null: {null_cells:,} ({100*null_cells/total_cells:.1f}%)")
    
    # Save the clean dataset
    print(f"\n=== Saving Clean Dataset ===")
    final_df.to_csv(output_file, index=False)
    print(f"✅ Saved to: {output_file}")
    print(f"   Shape: {final_df.shape}")
    print(f"   Columns: {list(final_df.columns[:8])} ... + {len(final_df.columns)-8} more")
    
    return final_df

if __name__ == "__main__":
    try:
        df = combine_csv_files_clean()
        print(f"\n🎉 Success! Clean dataset with exactly 47 features + source column created.")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()