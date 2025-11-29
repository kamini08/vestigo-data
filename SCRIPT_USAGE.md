# JSON to CSV Feature Matching Script

## Overview

This script (`match_json_to_csv.py`) processes Ghidra output JSON files and matches their features to the columns defined in `features.csv`. **It creates one CSV row for EACH FUNCTION in each binary**, providing granular function-level analysis across all combinations of:
- **Architectures**: ARM, AVR, RISCV, MIPS, x86 (and Z-80 if available)
- **Algorithms**: AES128, AES192, AES256, RSA1024, RSA2048, RSA4096, SHA1, SHA224, XOR, ECC, PRNG
- **Compilers**: gcc, clang, avr-gcc, mips-linux-gnu-gcc, riscv64-linux-gnu-gcc
- **Optimizations**: O0, O1, O2, O3, Os

## Features

✅ **Per-Function Output**: Creates one CSV row for each function in each binary  
✅ **Automatic Feature Matching**: Only extracts features that are listed in the CSV column headers  
✅ **Smart Filename Parsing**: Handles complex naming patterns like `{algo}_{arch}_{compiler}_{opt}.elf.json`  
✅ **Complete Function Features**: Extracts graph-level, node-level, edge-level, and additional function metadata  
✅ **Comprehensive Coverage**: Processes all JSON files in the `ghidra_output/` directory  
✅ **Error Handling**: Gracefully handles missing files and parsing errors  

## Prerequisites

No external dependencies required! The script uses only Python standard library.

## Usage

### Basic Usage

Simply run the script from the repository root:

```bash
python match_json_to_csv.py
```

### What the Script Does

1. **Reads `features.csv`** to determine which feature columns are required
2. **Scans `ghidra_output/`** directory for all `.json` files
3. **Parses filenames** to extract:
   - Algorithm (e.g., aes128, rsa2048)
   - Architecture (e.g., ARM, x86, MIPS)
   - Compiler (e.g., clang, gcc, mips-linux-gnu-gcc)
   - Optimization level (e.g., O0, O1, O2, O3, Os)
4. **Extracts features for EACH FUNCTION** from JSON:
   - Function metadata (name, address)
   - Graph-level features (CFG metrics)
   - Node-level features (instruction statistics)
   - Edge-level features (control flow)
   - Crypto signatures
   - Data references
   - Operation categories
   - Instruction sequences
   - Entropy metrics
5. **Creates one CSV row per function** with binary metadata + function features
6. **Writes output** to `features_output.csv`

## JSON File Naming Convention

The script expects JSON files to follow this naming pattern:

```
{algorithm}_{architecture}_{compiler}_{optimization}.elf.json
```

**Examples:**
- `aes128_ARM_clang_O1.elf.json`
- `rsa2048_x86_gcc_O3.elf.json`
- `sha1_MIPS_mips-linux-gnu-gcc_Os.elf.json`
- `ecc_RISCV_riscv64-linux-gnu-gcc_O2.elf.json`

## Output Format

The script generates `features_output.csv` with **one row per function**:

```csv
archietecture,algorithm,optimization,compiler,function_name,function_address,num_basic_blocks,num_edges,...
ARM,AES128,O1,clang,main,00010460,5,8,...
ARM,AES128,O1,clang,encrypt_block,000105a8,12,15,...
ARM,AES128,O1,clang,key_expansion,00010710,8,10,...
ARM,AES128,O2,clang,main,00010460,4,6,...
x86,RSA2048,O3,gcc,rsa_encrypt,00010a20,45,60,...
...
```

**Key Points:**
- Each row represents **one function** from a binary
- If a binary has 20 functions, it will produce 20 rows
- Binary metadata (architecture, algorithm, optimization, compiler) is repeated for each function
- Function-specific data (name, address, features) is unique per row

## Feature Extraction (Per Function)

The script extracts features for each individual function. For features that span multiple nodes/edges within a function, aggregation uses:

- **Numeric features**: Mean (average) across all nodes in the function
- **Count features**: Sum across all nodes in the function  
- **Histogram features**: Combined counts across all nodes in the function
- **Boolean features**: Proportion/mean (0 to 1) across nodes

### Supported Feature Categories

1. **Function Metadata**:
   - function_name, function_address

2. **Graph-level features** (from `graph_level`):
   - num_basic_blocks, num_edges, cyclomatic_complexity
   - loop_count, loop_depth, branch_density
   - average_block_size, num_entry_exit_paths
   - strongly_connected_components

3. **Node-level features** (aggregated from all `node_level` entries):
   - instruction_count, opcode_histogram
   - xor_ratio, add_ratio, multiply_ratio
   - logical_ratio, load_store_ratio
   - bitwise_op_density, immediate_entropy
   - table_lookup_presence, crypto_constant_hits
   - branch_condition_complexity

4. **Edge-level features** (aggregated from all `edge_level` entries):
   - edge_type, is_loop_edge

5. **Crypto Signatures** (from `crypto_signatures`):
   - has_aes_sbox, rsa_bigint_detected
   - has_aes_rcon, has_sha_constants

6. **Data References** (from `data_references`):
   - rodata_refs_count, string_refs_count
   - stack_frame_size

7. **Operation Categories** (from `op_category_counts`):
   - bitwise_ops, crypto_like_ops
   - arithmetic_ops, mem_ops_ratio

8. **Instruction Sequence** (from `instruction_sequence`):
   - unique_ngram_count, top_5_bigrams

9. **Entropy Metrics** (from `entropy_metrics`):
   - function_byte_entropy, opcode_entropy
   - cyclomatic_complexity_density

10. **Label**:
    - label (e.g., "Crypto", "Non-Crypto")

## Example Output

```
======================================================================
JSON to CSV Feature Matching Script
======================================================================

1. Reading feature columns from CSV: features.csv
   Found 35 feature columns

2. Processing JSON files from: ghidra_output
Processing: aes128_ARM_clang_O1.elf.json
  ✓ Extracted features from 15 functions
Processing: aes128_ARM_clang_O2.elf.json
  ✓ Extracted features from 13 functions
Processing: aes128_x86_gcc_O3.elf.json
  ✓ Extracted features from 18 functions
...

3. Writing results to: features_output.csv

✓ Successfully wrote 8,450 rows to features_output.csv

======================================================================
Processing complete!
======================================================================

Summary:
  Total rows (functions): 8,450
  Total unique binaries: 450
  Architectures: ARM, AVR, MIPS, RISCV, x86
  Algorithms: AES128, AES192, AES256, ECC, PRNG, RSA1024, ...
  Compilers: avr-gcc, clang, gcc, mips-linux-gnu-gcc, ...
  Optimizations: O0, O1, O2, O3, Os
```

**Note:** The total number of rows will be much higher than the number of binaries since each function generates one row. For example, if you have 450 binaries with an average of ~18 functions each, you'll get approximately 8,000+ rows.

## Important Notes

⚠️ **Per-Function Output**: The script creates **one row per function**, not per binary. If you need binary-level aggregation, you'll need to aggregate the output CSV afterwards.

⚠️ **Feature Matching**: The script ONLY extracts features that are listed in the `features.csv` column headers. No extra features from JSON will be added.

⚠️ **Run After JSON Generation**: Wait until all JSON files are generated before running this script to ensure complete coverage.

⚠️ **CSV Column Names**: Make sure the column names in `features.csv` match the feature names in the JSON files (case-sensitive).

⚠️ **Large Output Files**: Since each function creates a row, the output CSV can be quite large (thousands to tens of thousands of rows depending on your binaries).

## Troubleshooting

### Issue: "No feature columns found in CSV"
**Solution**: Check that `features.csv` has column headers and they're not all metadata columns (architecture, algorithm, optimization).

### Issue: "Unable to parse filename"
**Solution**: Ensure JSON files follow the naming convention: `{algo}_{arch}_{compiler}_{opt}.elf.json`

### Issue: Missing features in output
**Solution**: 
1. Check that the feature name in CSV exactly matches the JSON structure
2. Add custom mapping in the `map_feature_to_json()` function if needed

## Customization

To add custom feature mappings, edit the `map_feature_to_json()` function in the script:

```python
def map_feature_to_json(feature_name, json_features):
    # Add your custom mappings here
    if feature_name == 'custom_feature':
        return calculate_custom_feature(json_features)
    
    # Default behavior
    if feature_name in json_features:
        return json_features[feature_name]
    
    return ''
```

## Contact

For issues or questions about this script, please refer to the main project documentation.
