#!/usr/bin/env python3
"""
Run enhanced Ghidra extraction pipeline on all dataset binaries
"""
import os
import subprocess
import json
import glob
from pathlib import Path

# Configuration
GHIDRA_HOME = os.getenv("GHIDRA_HOME")
BINARY_DIR = "dataset_binaries"
OUTPUT_DIR = "ghidra_output"
PROJECT_DIR = "/tmp/ghidra_extraction_project"
PROJECT_NAME = "enhanced_extraction"
SCRIPT_PATH = "ghidra/extract.py"

def run_ghidra_analysis(binary_path, output_dir):
    """Run Ghidra headless analysis on a binary"""
    analyzer_bin = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")
    binary_name = os.path.basename(binary_path)
    
    # Create project directory if it doesn't exist
    os.makedirs(PROJECT_DIR, exist_ok=True)
    
    cmd = [
        analyzer_bin,
        PROJECT_DIR,
        PROJECT_NAME,
        "-import", binary_path,
        "-postScript", SCRIPT_PATH,
        "-deleteProject"
    ]
    
    print(f"  Analyzing {binary_name}...")
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            cwd=os.getcwd(),
            timeout=300  # 5 minute timeout per binary
        )
        
        # Check if output JSON was created
        output_file = os.path.join(PROJECT_DIR, binary_name + ".json")
        
        if os.path.exists(output_file):
            # Move to output directory
            final_path = os.path.join(output_dir, binary_name + ".json")
            os.rename(output_file, final_path)
            
            # Validate JSON
            with open(final_path, 'r') as f:
                data = json.load(f)
            
            num_functions = len(data.get('functions', []))
            print(f"    ✓ Success: {num_functions} functions extracted")
            return True, num_functions
        else:
            print(f"    ✗ Failed: No output file generated")
            if "ERROR" in result.stderr:
                print(f"    Error: {result.stderr[-500:]}")
            return False, 0
            
    except subprocess.TimeoutExpired:
        print(f"    ✗ Timeout: Analysis took too long")
        return False, 0
    except Exception as e:
        print(f"    ✗ Error: {str(e)}")
        return False, 0

def main():
    print("=" * 80)
    print("ENHANCED GHIDRA EXTRACTION PIPELINE")
    print("=" * 80)
    print()
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Find all binaries
    binaries = glob.glob(os.path.join(BINARY_DIR, "*.elf"))
    binaries.extend(glob.glob(os.path.join(BINARY_DIR, "*.ihx")))
    
    if not binaries:
        print(f"✗ No binaries found in {BINARY_DIR}")
        return
    
    print(f"Found {len(binaries)} binaries to analyze")
    print()
    
    # Process each binary
    success_count = 0
    total_functions = 0
    failed_binaries = []
    
    for i, binary_path in enumerate(binaries, 1):
        print(f"[{i}/{len(binaries)}] {os.path.basename(binary_path)}")
        
        success, num_funcs = run_ghidra_analysis(binary_path, OUTPUT_DIR)
        
        if success:
            success_count += 1
            total_functions += num_funcs
        else:
            failed_binaries.append(os.path.basename(binary_path))
        
        print()
    
    # Summary
    print("=" * 80)
    print("PIPELINE SUMMARY")
    print("=" * 80)
    print(f"Total binaries: {len(binaries)}")
    print(f"Successfully analyzed: {success_count}")
    print(f"Failed: {len(failed_binaries)}")
    print(f"Total functions extracted: {total_functions}")
    print()
    
    if failed_binaries:
        print("Failed binaries:")
        for binary in failed_binaries[:10]:  # Show first 10
            print(f"  - {binary}")
        if len(failed_binaries) > 10:
            print(f"  ... and {len(failed_binaries) - 10} more")
    
    print()
    print(f"Output directory: {OUTPUT_DIR}")
    print(f"JSON files created: {success_count}")
    
    # Show sample output
    if success_count > 0:
        sample_files = glob.glob(os.path.join(OUTPUT_DIR, "*.json"))[:1]
        if sample_files:
            print()
            print("Sample output structure:")
            with open(sample_files[0], 'r') as f:
                data = json.load(f)
            if data.get('functions'):
                func = data['functions'][0]
                print(f"  Function: {func.get('name')}")
                print(f"  Enhanced features present:")
                for key in ['crypto_signatures', 'entropy_metrics', 'instruction_sequence', 
                           'data_references', 'op_category_counts']:
                    present = "✓" if key in func else "✗"
                    print(f"    {present} {key}")

if __name__ == "__main__":
    main()
