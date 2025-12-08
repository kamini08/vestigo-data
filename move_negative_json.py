#!/usr/bin/env python3
"""
Script to move JSON files from ghidra_json_new to ghidra_json_new/negative
based on matching binaries in builds_new/negetive folder.
"""

import os
import shutil
from pathlib import Path

# Define paths
BUILDS_NEGATIVE_DIR = Path("builds_new/negetive")
GHIDRA_JSON_DIR = Path("filtered_json")
GHIDRA_NEGATIVE_DIR = GHIDRA_JSON_DIR / "negative"

def get_binary_basenames():
    """
    Get all binary file basenames from builds_new/negetive folder.
    Returns a set of basenames without extensions.
    """
    if not BUILDS_NEGATIVE_DIR.exists():
        print(f"Error: Directory {BUILDS_NEGATIVE_DIR} does not exist!")
        return set()
    
    binaries = set()
    for file in BUILDS_NEGATIVE_DIR.iterdir():
        if file.is_file() and file.suffix in ['.o', '.a', '.elf']:
            # Store the full filename (e.g., "adler32.o_zlib_arm32_O0.o")
            binaries.add(file.name)
    
    print(f"Found {len(binaries)} binary files in {BUILDS_NEGATIVE_DIR}")
    return binaries

def find_matching_json_files(binary_names):
    """
    Find JSON files in ghidra_json_new that match the binary names.
    JSON files have format: <binary_name>_features.json
    """
    if not GHIDRA_JSON_DIR.exists():
        print(f"Error: Directory {GHIDRA_JSON_DIR} does not exist!")
        return []
    
    matching_files = []
    
    for json_file in GHIDRA_JSON_DIR.iterdir():
        if json_file.is_file() and json_file.suffix == '.json':
            # Check if this JSON file corresponds to any binary
            # JSON format: <binary_name>_features.json
            json_name = json_file.name
            
            # Remove the "_features.json" suffix to get the potential binary name
            if json_name.endswith("_features.json"):
                potential_binary = json_name.replace("_features.json", "")
                
                # Check if this matches any binary in our set
                if potential_binary in binary_names:
                    matching_files.append(json_file)
    
    print(f"Found {len(matching_files)} matching JSON files")
    return matching_files

def move_json_files(json_files):
    """
    Create negative folder and move matching JSON files there.
    """
    if not json_files:
        print("No files to move!")
        return
    
    # Create the negative directory if it doesn't exist
    GHIDRA_NEGATIVE_DIR.mkdir(exist_ok=True)
    print(f"Created/verified directory: {GHIDRA_NEGATIVE_DIR}")
    
    moved_count = 0
    for json_file in json_files:
        try:
            destination = GHIDRA_NEGATIVE_DIR / json_file.name
            shutil.move(str(json_file), str(destination))
            print(f"Moved: {json_file.name}")
            moved_count += 1
        except Exception as e:
            print(f"Error moving {json_file.name}: {e}")
    
    print(f"\nSuccessfully moved {moved_count} files to {GHIDRA_NEGATIVE_DIR}")

def main():
    print("=" * 60)
    print("Moving Negative JSON Files")
    print("=" * 60)
    
    # Step 1: Get binary filenames from builds_new/negetive
    print("\nStep 1: Reading binary files from builds_new/negetive...")
    binary_names = get_binary_basenames()
    
    if not binary_names:
        print("No binary files found. Exiting.")
        return
    
    # Display a few examples
    print(f"\nExample binary names (first 5):")
    for i, name in enumerate(list(binary_names)[:5]):
        print(f"  - {name}")
    
    # Step 2: Find matching JSON files
    print("\nStep 2: Finding matching JSON files in ghidra_json_new...")
    matching_json_files = find_matching_json_files(binary_names)
    
    if not matching_json_files:
        print("No matching JSON files found. Exiting.")
        return
    
    # Display a few examples
    print(f"\nExample JSON files to move (first 5):")
    for i, file in enumerate(matching_json_files[:5]):
        print(f"  - {file.name}")
    
    # Step 3: Confirm and move
    print(f"\nReady to move {len(matching_json_files)} files.")
    response = input("Proceed with moving files? (yes/no): ").strip().lower()
    
    if response in ['yes', 'y']:
        print("\nStep 3: Moving files...")
        move_json_files(matching_json_files)
        print("\nDone!")
    else:
        print("Operation cancelled.")

if __name__ == "__main__":
    main()
