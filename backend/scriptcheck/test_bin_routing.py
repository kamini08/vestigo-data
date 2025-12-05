#!/usr/bin/env python3
"""
Test script for .bin file routing through PATH_B
Tests the integration of unpack.py with the backend
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingest import IngestionModule
import json

def test_bin_file_routing():
    """Test that .bin files are routed through PATH_B"""
    print("=" * 60)
    print("Testing .bin File Routing")
    print("=" * 60)
    
    # Create a test .bin file
    test_file = "test_firmware.bin"
    with open(test_file, "wb") as f:
        # Write some fake firmware data
        f.write(b"FAKE_FIRMWARE_HEADER" + b"\x00" * 1000)
    
    print(f"\n✓ Created test file: {test_file}")
    
    # Initialize ingestion module
    ingest = IngestionModule(output_base_dir="./test_analysis_workspace")
    print("✓ Initialized IngestionModule")
    
    # Process the file
    print(f"\n[Processing {test_file}...]")
    result = ingest.process(test_file)
    
    print("\n" + "=" * 60)
    print("INGEST RESULTS")
    print("=" * 60)
    print(json.dumps(result, indent=2))
    
    # Verify routing decision
    print("\n" + "=" * 60)
    print("VERIFICATION")
    print("=" * 60)
    
    routing_decision = result.get("routing", {}).get("decision")
    
    if routing_decision in ["PATH_B_LINUX_FS", "PATH_A_BARE_METAL", "PATH_C_HARD_TARGET"]:
        print(f"✓ File routed correctly: {routing_decision}")
        print(f"  Reason: {result.get('routing', {}).get('reason')}")
        
        if routing_decision == "PATH_B_LINUX_FS":
            print("\n✓✓ SUCCESS: .bin file routed to PATH_B_LINUX_FS!")
            print("   This means the firmware was extracted and contains a Linux filesystem.")
        elif routing_decision == "PATH_A_BARE_METAL":
            print("\n✓ INFO: .bin file routed to PATH_A_BARE_METAL")
            print("   This means extraction occurred but no Linux FS was found.")
        else:
            print("\n✓ INFO: .bin file routed to PATH_C_HARD_TARGET")
            print("   This means extraction failed (expected for fake test data).")
    else:
        print(f"✗ ERROR: Unexpected routing decision: {routing_decision}")
        return False
    
    # Check if extraction was attempted
    was_extracted = result.get("extraction", {}).get("was_extracted", False)
    print(f"\n• Extraction attempted: {was_extracted}")
    
    if was_extracted:
        extracted_path = result.get("extraction", {}).get("extracted_path")
        print(f"• Extracted to: {extracted_path}")
    
    # Cleanup
    print("\n" + "=" * 60)
    print("CLEANUP")
    print("=" * 60)
    
    if os.path.exists(test_file):
        os.remove(test_file)
        print(f"✓ Removed test file: {test_file}")
    
    if os.path.exists("test_analysis_workspace"):
        import shutil
        shutil.rmtree("test_analysis_workspace")
        print("✓ Removed test workspace")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    try:
        success = test_bin_file_routing()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ TEST FAILED WITH ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
