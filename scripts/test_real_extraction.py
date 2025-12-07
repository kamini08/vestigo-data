#!/usr/bin/env python3
"""
Test script to demonstrate real Ghidra integration
This tests the feature extraction service directly without web server
"""

import sys
import os
import asyncio
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent / "backend"
sys.path.append(str(backend_path))

from services.feature_extraction_service import FeatureExtractionService

async def test_feature_extraction():
    """Test the real feature extraction service"""
    
    print("=== Vestigo Real Feature Extraction Test ===\n")
    
    # Initialize service
    service = FeatureExtractionService()
    
    # Test binaries
    test_binaries = [
        "builds/tinycrypt_aes_encrypt_arm32_O2.o",  # Small AES binary
        "builds/mbedtls_arm32_O2.a",                # Larger mbedTLS library
    ]
    
    project_root = Path(__file__).parent
    
    for binary_path in test_binaries:
        full_path = project_root / binary_path
        
        if not full_path.exists():
            print(f"⚠️  Binary not found: {full_path}")
            continue
            
        print(f"🔍 Testing: {binary_path}")
        print(f"   Size: {full_path.stat().st_size} bytes")
        
        job_id = f"test_{binary_path.replace('/', '_').replace('.', '_')}"
        
        try:
            # Test standalone analysis (no Ghidra required)
            print("   ├─ Running standalone analysis...")
            if service.feature_extractor:
                standalone_result = await service.extract_features_standalone(str(full_path), job_id + "_standalone")
                print(f"   │  ✅ Standalone: {standalone_result['summary']['total_functions']} crypto functions detected")
            else:
                print("   │  ⚠️  Standalone analysis not available (vestigo_features library missing)")
            
            # Test Ghidra analysis (requires Ghidra installation)
            print("   ├─ Testing Ghidra analysis...")
            if os.path.exists(service.ghidra_headless):
                print(f"   │  Ghidra found at: {service.ghidra_headless}")
                ghidra_result = await service.extract_features_from_binary(job_id + "_ghidra", str(full_path))
                
                summary = ghidra_result["summary"]
                print(f"   │  ✅ Ghidra Analysis Complete!")
                print(f"   │  │  Binary: {ghidra_result['binary_name']}")
                print(f"   │  │  Total Functions: {summary['total_functions']}")
                print(f"   │  │  Crypto Functions: {summary['crypto_functions']}")
                print(f"   │  │  Non-Crypto Functions: {summary['non_crypto_functions']}")
                print(f"   │  │  Crypto Constants: {summary['total_crypto_constants']}")
                print(f"   │  │  Avg Entropy: {summary['average_entropy']}")
                print(f"   │  │  Text Size: {summary['binary_sections']['text_size']} bytes")
                
                # Show sample functions
                functions = ghidra_result.get("functions", [])[:3]  # First 3 functions
                if functions:
                    print(f"   │  └─ Sample Functions:")
                    for func in functions:
                        label = func.get("label", "Unknown")
                        name = func.get("name", "unknown")
                        addr = func.get("address", "unknown")
                        print(f"   │     • {name} ({label}) @ {addr}")
                
            else:
                print(f"   │  ⚠️  Ghidra not found at: {service.ghidra_headless}")
                print(f"   │     Set GHIDRA_INSTALL_DIR environment variable to test real Ghidra")
                
        except Exception as e:
            print(f"   └─ ❌ Error: {str(e)}")
        
        print()
    
    print("=== Test Summary ===")
    print(f"✅ Feature Extraction Service: Initialized")
    print(f"{'✅' if service.feature_extractor else '⚠️ '} Standalone Analysis: {'Available' if service.feature_extractor else 'vestigo_features library missing'}")
    print(f"{'✅' if os.path.exists(service.ghidra_headless) else '⚠️ '} Ghidra Integration: {'Available' if os.path.exists(service.ghidra_headless) else 'Ghidra not installed'}")
    print(f"📍 Ghidra Script: {service.extract_features_script}")
    
    if not os.path.exists(service.ghidra_headless):
        print(f"\n💡 To enable Ghidra analysis:")
        print(f"   1. Install Ghidra from https://ghidra-sre.org/")
        print(f"   2. Set environment: export GHIDRA_INSTALL_DIR=/path/to/ghidra")
        print(f"   3. Re-run this test")

if __name__ == "__main__":
    asyncio.run(test_feature_extraction())