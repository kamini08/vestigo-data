# generate_dataset.py — ML Dataset Generation

This script processes all JSON files in `ghidra_output/`, extracts features for each function using OpenAI LLM, and generates a complete CSV dataset for machine learning training.

## What it does

1. **Parses filenames** to extract metadata:
   - Filename format: `{algorithm}_{architecture}_{compiler}_{optimization}.elf.json`
   - Example: `aes128_ARM_clang_O0.elf.json` → algorithm=aes128, architecture=ARM, compiler=clang, optimization=O0

2. **Processes each function** in each JSON file:
   - Extracts available features locally from `graph_level`, `advanced_features`, `node_level`, `edge_level`
   - Calls OpenAI LLM to classify the function and fill missing features
   - Classifies label as one of: `AES-128`, `AES-192`, `AES-256`, `ECC`, `PRNG`, `RSA-1024`, `RSA-4096`, `SHA-1`, `SHA-224`, `MD5(XOR)`, or `Non-Crypto`

3. **Outputs one CSV row per function** with all columns from `features.txt`:
   - Metadata: architecture, algorithm, compiler, optimization, filename, function_name, function_address
   - Label: final classification
   - ~50 feature columns (numeric, boolean, ratios, entropy, etc.)
   - Boolean features marked as `true`/`false` or empty if unavailable
   - Numeric features filled with value or empty if not present

## Usage

### 1. Install dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Set your OpenAI API key
```bash
export OPENAI_API_KEY="sk-..."
```
Or pass it with `--api-key` flag, or put it in a `.env` file.

### 3. Run the script

**Process all ~495 JSON files (full dataset generation):**
```bash
python3 generate_dataset.py --input-dir ghidra_output --output dataset_output.csv
```

**Test with a limited number of files:**
```bash
python3 generate_dataset.py --input-dir ghidra_output --output test_dataset.csv --limit 10
```

**Override API key and batch size:**
```bash
python3 generate_dataset.py \
  --input-dir ghidra_output \
  --output dataset_output.csv \
  --api-key "sk-..." \
  --batch-size 3
```

## Command-line options

- `--input-dir` : Directory containing JSON files (default: `ghidra_output`)
- `--output`, `-o` : Output CSV file (default: `dataset_output.csv`)
- `--api-key` : OpenAI API key (overrides environment)
- `--batch-size` : Number of functions to process per LLM batch (default: 5, reduce if hitting token limits)
- `--limit` : Limit number of JSON files to process (useful for testing)

## Output CSV format

The output CSV contains these columns (from `features.txt`):

**Metadata (8 columns):**
- architecture, algorithm, compiler, optimization, filename, function_name, function_address, label

**Features (~50 columns):**
- Graph-level: num_basic_blocks, num_edges, cyclomatic_complexity, loop_count, branch_density, etc.
- Node-level aggregated: instruction_count, immediate_entropy, bitwise_op_density, crypto_constant_hits, etc.
- Edge-level aggregated: num_conditional_edges, num_unconditional_edges, num_loop_edges, etc.
- Algorithm-specific: has_aes_sbox, rsa_bigint_detected, has_aes_rcon, has_sha_constants
- Other: rodata_refs_count, string_refs_count, stack_frame_size, function_byte_entropy, etc.

**Label values:**
- Crypto: `AES-128`, `AES-192`, `AES-256`, `ECC`, `PRNG`, `RSA-1024`, `RSA-4096`, `SHA-1`, `SHA-224`, `MD5(XOR)`
- Non-crypto: `Non-Crypto`

## Expected output

- Processing ~495 files with ~20 functions each → ~10,000 rows in the output CSV
- Each row represents one function with all extracted/classified features
- Console logs show progress: `[N/495] Processing aes128_ARM_clang_O0.elf.json... → Extracted M function rows`

## Troubleshooting

**Token limit errors:**
- Reduce `--batch-size` (default 5, try 3 or 1)
- The script processes functions in small batches to avoid exceeding model context limits

**Missing features in output:**
- Features not computable from JSON are marked as empty string or `false` (for booleans)
- This is expected; the LLM will infer what it can and leave the rest empty

**API rate limits:**
- OpenAI may rate-limit requests; the script will log errors and continue
- For large runs, consider adding retry logic or running in smaller batches with `--limit`

## Next steps

After generating the CSV:
1. Inspect `dataset_output.csv` to verify feature extraction quality
2. Use the CSV to train your ML model (e.g., with `train_xgboost.py`)
3. If needed, refine the LLM prompt in `generate_dataset.py` (search for `prompt_text` variable)

