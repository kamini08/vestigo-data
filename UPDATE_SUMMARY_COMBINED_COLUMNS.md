# Script Update Summary - Combined Feature Columns

## Date: November 26, 2025

## Changes Made

The script has been successfully updated to **combine multiple related features into single columns** as requested, matching the exact column names in `features.csv`.

## ✅ Successfully Processed
- **Total rows created**: 7,647 rows (one per function across all binaries)
- **Output file**: `features_output.csv`

---

## Feature Column Organization

### 1. **Raw Opcode Counts** → Combined into ONE column
**Column name**: `Raw opcode counts(count_mov, count_add, count_sub, count_mul, count_div, count_xor, count_and, count_or, count_not, count_shl, count_shr, count_ror, count_rol, count_cmp, count_jmp, count_call, count_ret, count_ldr, count_str, count_push, count_pop)`

**Format**: Python dictionary as string
```python
"{'count_mov': 54, 'count_add': 29, 'count_sub': 16, 'count_mul': 4, 'count_div': 0, 'count_xor': 3, 'count_and': 45, 'count_or': 28, 'count_not': 11, 'count_shl': 0, 'count_shr': 2, 'count_ror': 0, 'count_rol': 0, 'count_cmp': 75, 'count_jmp': 5, 'count_call': 2, 'count_ret': 1, 'count_ldr': 17, 'count_str': 15, 'count_push': 0, 'count_pop': 16}"
```

**Content**:
- count_mov: COPY/MOV operations
- count_add: ADD operations
- count_sub: SUB operations
- count_mul: MUL operations
- count_div: DIV operations
- count_xor: XOR operations
- count_and: AND operations
- count_or: OR operations
- count_not: NOT/NEGATE operations
- count_shl: Shift left
- count_shr: Shift right
- count_ror: Rotate right
- count_rol: Rotate left
- count_cmp: Compare operations
- count_jmp: Jump/Branch
- count_call: Call operations
- count_ret: Return operations
- count_ldr: Load operations
- count_str: Store operations
- count_push: Push operations
- count_pop: Pop operations

---

### 2. **Opcode Category Buckets** → Combined into ONE column
**Column name**: `Opcode category buckets`

**Format**: Python dictionary as string
```python
"{'arithmetic_opcodes': 49, 'logical_opcodes': 87, 'memory_opcodes': 48, 'control_flow_opcodes': 8, 'comparison_opcodes': 75, 'bitwise_opcodes': 5}"
```

**Content**:
- arithmetic_opcodes: ADD, SUB, MUL, DIV
- logical_opcodes: AND, OR, NOT
- memory_opcodes: LOAD, STORE, PUSH, POP
- control_flow_opcodes: BRANCH, CALL, RETURN
- comparison_opcodes: EQUAL, LESS, CARRY, BORROW
- bitwise_opcodes: XOR, SHL, SHR, ROT

---

### 3. **N-gram Features** → Combined into ONE column
**Column name**: `N-gram features`

**Format**: Python dictionary as string
```python
"{'unique_ngram_count': 39, 'top_5_bigrams': ['MOV MOV', 'PUSH PUSH', 'POP POP', 'MOV ADD', 'MOV XOR']}"
```

**Content**:
- unique_ngram_count: Number of unique n-grams
- top_5_bigrams: List of top 5 most frequent bigrams

---

### 4. **Individual Columns** (Not Combined)

The following features remain as separate columns:

| Column Name | Type | Description |
|-------------|------|-------------|
| total_instructions | integer | Total instruction count |
| text_size | integer | .text section size (placeholder: 0) |
| rodata_size | integer | .rodata section size (placeholder: 0) |
| data_size | integer | .data section size (placeholder: 0) |
| large_table_flag | integer | Large table flag (placeholder: 0) |
| string_count | integer | String reference count |
| string_density | float | String density (placeholder: 0) |
| number_of_tables | integer | Number of tables (placeholder: 0) |

---

## Complete CSV Column Structure

```
archietecture
algorithm
optimization
compiler
num_basic_blocks
num_edges
cyclomatic_complexity
loop_count
loop_depth
branch_density
average_block_size
num_entry_exit_paths
strongly_connected_components
instruction_count
opcode_histogram
xor_ratio
add_ratio
multiply_ratio
logical_ratio
load_store_ratio
bitwise_op_density
immediate_entropy
table_lookup_presence
crypto_constant_hits
edge_type
is_loop_edge
branch_condition_complexity
(empty column)
Raw opcode counts(count_mov, count_add, count_sub, count_mul, count_div, count_xor, count_and, count_or, count_not, count_shl, count_shr, count_ror, count_rol, count_cmp, count_jmp, count_call, count_ret, count_ldr, count_str, count_push, count_pop)
Opcode category buckets
N-gram features
total_instructions
text_size
rodata_size
data_size
large_table_flag
string_count
string_density
number_of_tables
```

---

## How to Parse the Combined Columns

If you need to extract individual values from the combined columns in Python:

```python
import csv
import ast

# Read the CSV
with open('features_output.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        # Parse Raw opcode counts
        raw_opcodes = ast.literal_eval(row['Raw opcode counts(count_mov, count_add, count_sub, count_mul, count_div, count_xor, count_and, count_or, count_not, count_shl, count_shr, count_ror, count_rol, count_cmp, count_jmp, count_call, count_ret, count_ldr, count_str, count_push, count_pop)'])
        print(f"MOV count: {raw_opcodes['count_mov']}")
        
        # Parse Opcode category buckets
        opcode_cats = ast.literal_eval(row['Opcode category buckets'])
        print(f"Arithmetic ops: {opcode_cats['arithmetic_opcodes']}")
        
        # Parse N-gram features
        ngrams = ast.literal_eval(row['N-gram features'])
        print(f"Top bigrams: {ngrams['top_5_bigrams']}")
```

---

## Example Data Row

```csv
ARM,AES128,O1,clang,encrypt_block,000105a8,19,25,8,...,
"{'count_mov': 54, 'count_add': 29, 'count_sub': 16, ...}",
"{'arithmetic_opcodes': 49, 'logical_opcodes': 87, ...}",
"{'unique_ngram_count': 39, 'top_5_bigrams': ['MOV MOV', ...]}",
150,0,0,0,0,3,0,0
```

---

## Benefits of This Approach

✅ **Matches CSV column headers exactly** - No column mismatch errors
✅ **Reduces column count** - 21 + 6 + 2 = 29 features in just 3 columns
✅ **Preserves all data** - No information loss
✅ **Easy to parse** - Use `ast.literal_eval()` in Python
✅ **Flexible** - Add more features to dictionaries without changing column count

---

## Statistics

- **Total binaries processed**: ~450+ (across all architectures, algorithms, compilers, optimizations)
- **Average functions per binary**: ~17 functions
- **Total function rows**: 7,647
- **Architectures**: ARM, AVR, MIPS, RISCV, x86
- **Algorithms**: AES128, AES192, AES256, ECC, PRNG, RSA1024, RSA2048, RSA4096, SHA1, SHA224, SHA256, XOR
- **Compilers**: clang, gcc, avr-gcc, mips-linux-gnu-gcc, riscv64-linux-gnu-gcc
- **Optimizations**: O0, O1, O2, O3, Os

---

## Next Steps

The CSV is ready for:
1. ✅ Machine Learning feature engineering
2. ✅ Statistical analysis
3. ✅ Cross-architecture comparisons
4. ✅ Compiler optimization studies
5. ✅ Cryptographic algorithm detection

To use the data, simply:
```python
import pandas as pd
df = pd.read_csv('features_output.csv')
```

And parse the combined columns as needed using `ast.literal_eval()`.

---

**Script Status**: ✅ Successfully completed
**Output**: `features_output.csv` with 7,647 rows
**Date**: November 26, 2025
