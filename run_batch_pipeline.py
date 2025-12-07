#!/usr/bin/env python3
"""
Optimized batch Ghidra extraction pipeline with progress tracking
Processes binaries in batches to handle large datasets efficiently
"""
import os
import subprocess
import json
import glob
import time
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
# Configuration
GHIDRA_HOME = os.getenv("GHIDRA_HOME")

# Auto-detect Ghidra if not set
if not GHIDRA_HOME:
    common_paths = ["/opt/ghidra", "/usr/local/ghidra", os.path.expanduser("~/ghidra")]
    for path in common_paths:
        if os.path.exists(os.path.join(path, "support", "analyzeHeadless")):
            GHIDRA_HOME = path
            print(f"Auto-detected Ghidra at: {GHIDRA_HOME}")
            break
    
    if not GHIDRA_HOME:
        print("ERROR: GHIDRA_HOME not set and Ghidra not found in common locations.")
        print("Please set GHIDRA_HOME environment variable or install Ghidra.")
        exit(1)

BINARY_DIRS = ["builds_new"]  # Process both directories
OUTPUT_DIR = "ghidra_json_new"  # Combined output directory
PROJECT_DIR = "/tmp/ghidra_batch_project"
PROJECT_NAME = f"batch_extraction_{int(time.time())}"
SCRIPT_PATH = "ghidra_scripts/extract_features.py"
BATCH_SIZE = 10  # Process in batches to show progress
TIMEOUT_PER_BINARY = 180  # 3 minutes per binary

import shutil

def run_ghidra_on_binary(binary_path):
    """Run Ghidra analysis on a single binary"""
    analyzer_bin = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")
    # analyzer_bin = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless.bat")

    binary_name = os.path.basename(binary_path)
    
    # Ensure a clean temporary project directory
    if os.path.isdir(PROJECT_DIR):
        shutil.rmtree(PROJECT_DIR)
    os.makedirs(PROJECT_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    cmd = [
        analyzer_bin,
        PROJECT_DIR,
        PROJECT_NAME,
        "-import", binary_path,
        "-postScript", os.path.abspath(SCRIPT_PATH),
        os.path.abspath(OUTPUT_DIR),  # Pass output directory as argument
        "-deleteProject"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.getcwd(),
            timeout=TIMEOUT_PER_BINARY
        )
        
        # Check for output in ghidra_output directory
        # Note: extract_features.py appends "_features.json"
        output_file = os.path.join(OUTPUT_DIR, binary_name + "_features.json")
        
        if os.path.exists(output_file):
            # Validate JSON
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            return True, len(data.get('functions', []))
        else:
            return False, 0
            
    except subprocess.TimeoutExpired:
        return False, 0
    except Exception as e:
        return False, 0

def main():
    start_time = time.time()
    
    print("=" * 80)
    print("ENHANCED GHIDRA EXTRACTION PIPELINE")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    print()
    
    # Setup
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    binaries = []

    # Process both builds and builds_x86 directories
    for binary_dir in BINARY_DIRS:
        if not os.path.isdir(binary_dir):
            print(f"Warning: Directory '{binary_dir}' not found, skipping...")
            continue
            
        print(f"Scanning directory: {binary_dir}/")
        
        # 1) Collect all .o, .a, and .elf files recursively
        for root, dirs, files in os.walk(binary_dir):
            for fname in files:
                if fname.endswith(".o") or fname.endswith(".a") or fname.endswith(".elf"):
                    full_path = os.path.join(root, fname)
                    binaries.append(full_path)
        
        # 2) Add negative samples from negative folder (if exists)
            negative_dir = os.path.join(binary_dir, "negetive")
            if os.path.isdir(negative_dir):
                print(f"  Found negative samples: {negative_dir}/")
                for root, dirs, files in os.walk(negative_dir):
                    for fname in files:
                        # Accept common binary formats in negative folder
                        if fname.endswith(("_unstripped", ".elf", ".out", ".bin")) or \
                           fname.startswith("busybox_"):
                            full_path = os.path.join(root, fname)
                            binaries.append(full_path)

    # 3) Deduplicate and sort
    binaries = sorted(set(binaries))

    if not binaries:
        print(f"✗ No binaries found in {BINARY_DIRS}")
        print(f"  Expected: .o, .a, .elf files and negative samples")
        return

    print(f"\nFound {len(binaries)} total binaries across all directories")
    print(f"Processing in batches of {BATCH_SIZE}")
    print()
    
    # Track results
    results = {
        'success': 0,
        'failed': 0,
        'total_functions': 0,
        'failed_binaries': []
    }
    
    # Process in batches
    for batch_start in range(0, len(binaries), BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, len(binaries))
        batch_num = (batch_start // BATCH_SIZE) + 1
        total_batches = (len(binaries) + BATCH_SIZE - 1) // BATCH_SIZE
        
        print(f"Batch {batch_num}/{total_batches} (binaries {batch_start+1}-{batch_end})")
        print("-" * 80)
        
        for i in range(batch_start, batch_end):
            binary_path = binaries[i]
            binary_name = os.path.basename(binary_path)
            
            # Check if already processed
            output_file = os.path.join(OUTPUT_DIR, binary_name + "_features.json")
            if os.path.exists(output_file):
                print(f"  [{i+1}/{len(binaries)}] {binary_name[:40]:40s} ⊙ SKIP (exists)")
                results['success'] += 1
                continue
            
            print(f"  [{i+1}/{len(binaries)}] {binary_name[:40]:40s} ", end='', flush=True)
            
            success, num_funcs = run_ghidra_on_binary(binary_path)
            
            if success:
                results['success'] += 1
                results['total_functions'] += num_funcs
                print(f"✓ ({num_funcs} funcs)")
            else:
                results['failed'] += 1
                results['failed_binaries'].append(binary_name)
                print(f"✗ FAILED")
        
        # Batch summary
        elapsed = time.time() - start_time
        rate = (batch_end / elapsed) * 60 if elapsed > 0 else 0
        print(f"\n  Progress: {results['success']}/{len(binaries)} | "
              f"Rate: {rate:.1f} binaries/min | "
              f"Elapsed: {elapsed/60:.1f}min\n")
    
    # Final summary
    elapsed_total = time.time() - start_time
    print("=" * 80)
    print("PIPELINE COMPLETE")
    print("=" * 80)
    print(f"Total binaries: {len(binaries)}")
    print(f"Successfully analyzed: {results['success']}")
    print(f"Failed: {results['failed']}")
    print(f"Total functions extracted: {results['total_functions']}")
    print(f"Total time: {elapsed_total/60:.1f} minutes")
    print(f"Average: {elapsed_total/len(binaries):.1f} seconds per binary")
    print()
    
    if results['failed_binaries']:
        print(f"Failed binaries ({len(results['failed_binaries'])}):")
        for binary in results['failed_binaries']:
            print(f"  - {binary}")
    
    print()
    print(f"✓ Output directory: {OUTPUT_DIR}/")
    print(f"✓ JSON files created: {results['success']}")

if __name__ == "__main__":
    main()
