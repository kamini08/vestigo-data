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

# Configuration
GHIDRA_HOME = os.getenv("GHIDRA_HOME")
BINARY_DIR = "dataset_binaries"
OUTPUT_DIR = "ghidra_output"
PROJECT_DIR = "/tmp/ghidra_batch_project"
PROJECT_NAME = "batch_extraction"
SCRIPT_PATH = "ghidra/extract.py"
BATCH_SIZE = 10  # Process in batches to show progress
TIMEOUT_PER_BINARY = 180  # 3 minutes per binary

def run_ghidra_on_binary(binary_path):
    """Run Ghidra analysis on a single binary"""
    analyzer_bin = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")
    binary_name = os.path.basename(binary_path)
    
    os.makedirs(PROJECT_DIR, exist_ok=True)
    
    cmd = [
        analyzer_bin,
        PROJECT_DIR,
        PROJECT_NAME,
        "-import", binary_path,
        "-postScript", os.path.abspath(SCRIPT_PATH),
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
        
        # Check for output
        output_file = os.path.join(PROJECT_DIR, binary_name + ".json")
        
        if os.path.exists(output_file):
            # Move to final location
            final_path = os.path.join(OUTPUT_DIR, binary_name + ".json")
            os.rename(output_file, final_path)
            
            # Validate
            with open(final_path, 'r') as f:
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
    
    # Find binaries
    binaries = sorted(glob.glob(os.path.join(BINARY_DIR, "*.elf")))
    binaries.extend(sorted(glob.glob(os.path.join(BINARY_DIR, "*.ihx"))))
    
    if not binaries:
        print(f"✗ No binaries found in {BINARY_DIR}")
        return
    
    print(f"Found {len(binaries)} binaries")
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
            output_file = os.path.join(OUTPUT_DIR, binary_name + ".json")
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
        for binary in results['failed_binaries'][:20]:
            print(f"  - {binary}")
        if len(results['failed_binaries']) > 20:
            print(f"  ... and {len(results['failed_binaries']) - 20} more")
    
    print()
    print(f"✓ Output directory: {OUTPUT_DIR}/")
    print(f"✓ JSON files created: {results['success']}")

if __name__ == "__main__":
    main()
