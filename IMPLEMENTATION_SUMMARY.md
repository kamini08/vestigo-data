# Summary: JSON to CSV Feature Matching Script

## What Was Created

### 1. Main Script: `match_json_to_csv.py`
A comprehensive Python script that:
- ✅ Reads `features.csv` to understand which feature columns are needed
- ✅ Processes ALL JSON files in `ghidra_output/` folder
- ✅ **Creates ONE CSV ROW FOR EACH FUNCTION in each binary** (not aggregated to binary-level)
- ✅ Extracts features that match CSV column headers
- ✅ Handles all architectures: ARM, AVR, RISCV, MIPS, x86, Z-80
- ✅ Handles all algorithms: AES128, AES192, AES256, RSA1024, RSA2048, RSA4096, SHA1, SHA224, XOR, ECC, PRNG
- ✅ Handles all compilers: gcc, clang, avr-gcc, mips-linux-gnu-gcc, riscv64-linux-gnu-gcc
- ✅ Handles all optimizations: O0, O1, O2, O3, Os

### 2. Documentation: `SCRIPT_USAGE.md`
Complete usage guide with:
- Overview and features
- Prerequisites (none! Uses only Python standard library)
- Usage instructions
- JSON filename format requirements
- Output format details
- Feature categories
- Example output
- Troubleshooting tips

## Key Features of the Script

### Per-Function Processing
**IMPORTANT:** The script creates **one CSV row per function**, not per binary.

**Example:**
- If `aes128_ARM_clang_O1.elf.json` has 15 functions → 15 rows in output CSV
- If you have 450 binaries with avg ~18 functions each → ~8,100 rows total

### What Features Are Extracted

For each function, the script extracts:

1. **Binary Metadata** (repeated for each function):
   - Architecture (ARM, x86, MIPS, etc.)
   - Algorithm (AES128, RSA2048, etc.)
   - Compiler (gcc, clang, etc.)
   - Optimization (O0, O1, O2, O3, Os)

2. **Function Metadata**:
   - function_name
   - function_address

3. **Graph-Level Features**:
   - num_basic_blocks, num_edges
   - cyclomatic_complexity
   - loop_count, loop_depth
   - branch_density
   - average_block_size
   - num_entry_exit_paths
   - strongly_connected_components

4. **Node-Level Features** (aggregated across all nodes in the function):
   - instruction_count
   - opcode_histogram
   - xor_ratio, add_ratio, multiply_ratio
   - logical_ratio, load_store_ratio
   - bitwise_op_density
   - immediate_entropy
   - table_lookup_presence
   - crypto_constant_hits
   - branch_condition_complexity

5. **Edge-Level Features** (aggregated across all edges in the function):
   - edge_type
   - is_loop_edge

6. **Additional Features**:
   - Crypto signatures (has_aes_sbox, rsa_bigint_detected, etc.)
   - Data references (rodata_refs_count, string_refs_count, stack_frame_size)
   - Operation categories (bitwise_ops, crypto_like_ops, arithmetic_ops, mem_ops_ratio)
   - Instruction sequences (unique_ngram_count, top_5_bigrams)
   - Entropy metrics (function_byte_entropy, opcode_entropy, cyclomatic_complexity_density)
   - Label (Crypto/Non-Crypto)

### Feature Matching Logic

The script **ONLY extracts features listed in the CSV column headers**. It will:
- Map CSV column names to JSON feature names
- Return empty string if a feature is not found in JSON
- Handle complex features (dicts, lists) by converting to strings

## How to Use

### Step 1: Wait for JSON Generation
Make sure all JSON files are generated in `ghidra_output/` before running the script.

### Step 2: Run the Script
```bash
cd /home/bhoomi/Desktop/compilerRepo/vestigo-data
python3 match_json_to_csv.py
```

### Step 3: Check Output
The script will create `features_output.csv` with one row per function.

## Expected Output Format

```csv
archietecture,algorithm,optimization,compiler,function_name,function_address,num_basic_blocks,num_edges,...
ARM,AES128,O1,clang,_init,000103ec,1,1,2,0,0,...
ARM,AES128,O1,clang,_start,00010460,1,2,15,0,0,...
ARM,AES128,O1,clang,call_weak_fn,00010494,3,3,3.33,0,0,...
ARM,AES128,O1,clang,deregister_tm_clones,000104b8,4,5,3.25,0,0,...
...
```

## Filename Parsing

The script expects JSON files named as:
```
{algorithm}_{architecture}_{compiler}_{optimization}.elf.json
```

**Examples:**
- `aes128_ARM_clang_O1.elf.json` → AES128, ARM, clang, O1
- `rsa2048_x86_gcc_O3.elf.json` → RSA2048, x86, gcc, O3
- `sha1_MIPS_mips-linux-gnu-gcc_Os.elf.json` → SHA1, MIPS, mips-linux-gnu-gcc, Os

The script handles multi-part compiler names (e.g., `mips-linux-gnu-gcc`) correctly.

## Important Notes

✅ **No Dependencies**: Uses only Python standard library (no pip install needed)
✅ **Automatic Detection**: Automatically finds all JSON files in `ghidra_output/`
✅ **Error Handling**: Continues processing even if some files have errors
✅ **Progress Reporting**: Shows progress as it processes each file
✅ **Summary Statistics**: Displays summary of architectures, algorithms, compilers found

⚠️ **Large Output**: Output CSV will have many rows (one per function)
⚠️ **Feature Matching**: Only extracts features in CSV column headers
⚠️ **Case Sensitive**: Feature names must match exactly

## Next Steps

1. **Wait** for all JSON files to be generated
2. **Run** the script: `python3 match_json_to_csv.py`
3. **Review** the output: `features_output.csv`
4. **Analyze** the per-function data for your research

## Troubleshooting

### Issue: "No feature columns found in CSV"
- Check that `features.csv` exists and has column headers

### Issue: "Unable to parse filename"
- Ensure JSON files follow the naming pattern: `{algo}_{arch}_{compiler}_{opt}.elf.json`

### Issue: Missing features in output
- Verify feature names in CSV match JSON structure (case-sensitive)
- Check the `map_feature_to_json()` function for custom mappings

## Customization

To add custom feature mappings, edit the `map_feature_to_json()` function in `match_json_to_csv.py`.

---

**Script Created:** November 23, 2025
**Purpose:** Extract per-function features from Ghidra JSON output for ML/analysis
