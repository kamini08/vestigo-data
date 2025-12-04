#!/usr/bin/env python3
"""
Quick Ingestion Test - Simple validation of ingest_service.py routing

This script provides a quick test of the ingestion service with a few sample files.
Use this for rapid validation during development.
"""

import sys
import os
import asyncio
from pathlib import Path

# Add parent directory for imports
sys.path.append(str(Path(__file__).parent.parent))

from services.ingest_service import IngestService

async def quick_test():
    """Run a quick test of ingestion routing"""
    print("🚀 Quick Ingestion Route Test")
    print("=" * 35)
    
    # Initialize service
    service = IngestService()
    print(f"✅ IngestService initialized")
    print(f"   Workspace: {service.analysis_workspace_base}")
    
    # Test files from builds directory
    builds_dir = Path(__file__).parent.parent.parent / "builds"
    
    test_files = [
        "tinycrypt_aes_encrypt_arm32_O2.o",
        "tinycrypt_sha256_arm32_O2.o", 
        "mbedtls_arm32_O2.a"
    ]
    
    print(f"\n📁 Looking for test files in: {builds_dir}")
    
    for filename in test_files:
        file_path = builds_dir / filename
        
        if not file_path.exists():
            print(f"⚠️  {filename} - Not found")
            continue
            
        try:
            # Read file
            with open(file_path, 'rb') as f:
                content = f.read()
            
            print(f"\n🔍 Testing: {filename}")
            print(f"   Size: {len(content)} bytes")
            
            # Process through ingest service
            result = await service.process_uploaded_file(content, filename)
            
            # Print key results
            print(f"   🆔 Job ID: {result['jobId']}")
            print(f"   🛣️  Route: {result['analysis']['routing_decision']}")
            print(f"   📋 File Type: {result['analysis']['file_type']}")
            print(f"   ✅ Status: {result['status']}")
            
            # Next actions
            next_actions = result.get('next_actions', [])
            if next_actions:
                actions = [action['action'] for action in next_actions]
                print(f"   📌 Next: {', '.join(actions)}")
            
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")
    
    # Test with synthetic data
    print(f"\n🧪 Testing synthetic files:")
    
    synthetic_tests = [
        {
            "name": "random_data.bin",
            "content": os.urandom(1024),
            "description": "Random encrypted-like data"
        },
        {
            "name": "text_file.txt", 
            "content": b"Hello world! This is a text file.",
            "description": "Plain text content"
        },
        {
            "name": "empty_file.dat",
            "content": b"",
            "description": "Empty file"
        }
    ]
    
    for test in synthetic_tests:
        try:
            print(f"\n🔬 {test['name']} - {test['description']}")
            result = await service.process_uploaded_file(test['content'], test['name'])
            
            print(f"   🛣️  Route: {result['analysis']['routing_decision']}")
            print(f"   📊 Reason: {result['analysis']['routing_reason']}")
            
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")
    
    print(f"\n✅ Quick test completed!")
    print(f"💡 For comprehensive testing, run: ./test_ingestion_routing.py")

if __name__ == "__main__":
    asyncio.run(quick_test())