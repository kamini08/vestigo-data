#!/usr/bin/env python3
"""
Quick test script to verify Qiling integration in backend
"""

import sys
import os
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Test imports
try:
    from services.qiling_dynamic_analysis_service import QilingDynamicAnalysisService
    print("✓ Successfully imported QilingDynamicAnalysisService")
except ImportError as e:
    print(f"✗ Failed to import QilingDynamicAnalysisService: {e}")
    sys.exit(1)

# Test service initialization
try:
    service = QilingDynamicAnalysisService()
    print("✓ Successfully initialized QilingDynamicAnalysisService")
    print(f"  - Qiling analysis dir: {service.qiling_analysis_dir}")
    print(f"  - Verify crypto script: {service.verify_crypto_script}")
    print(f"  - Output directory: {service.output_dir}")
    print(f"  - Python executable: {service.python_executable}")
except Exception as e:
    print(f"✗ Failed to initialize service: {e}")
    sys.exit(1)

# Check if verify_crypto.py exists
if service.verify_crypto_script.exists():
    print("✓ verify_crypto.py found")
else:
    print("✗ verify_crypto.py not found - Qiling analysis will fail")
    print(f"  Expected at: {service.verify_crypto_script}")

# Check if output directory exists
if service.output_dir.exists():
    print("✓ qiling_output directory exists")
else:
    print("✗ qiling_output directory not found")

# Check if Qiling venv exists
if service.python_executable != "python3" and Path(service.python_executable).exists():
    print("✓ Qiling virtual environment found")
else:
    print("⚠ Qiling virtual environment not found - using system python3")
    print(f"  Expected at: {service.qiling_venv}")

# Test ELF detection
print("\nTesting ELF detection:")
test_cases = [
    ("/bin/ls", True),  # Should be ELF
    ("/etc/passwd", False),  # Should not be ELF
    ("/nonexistent", False),  # Should handle missing files
]

for path, expected in test_cases:
    if os.path.exists(path):
        result = service._is_elf_binary(path)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {path}: {result} (expected {expected})")

print("\n" + "="*60)
print("Integration test complete!")
print("="*60)
print("\nNext steps:")
print("1. Ensure Qiling is installed: cd qiling_analysis && source qiling_env/bin/activate")
print("2. Test manually: python3 tests/verify_crypto.py /path/to/elf")
print("3. Start backend: cd backend && uvicorn main:app --reload")
print("4. Upload ELF binary: curl -X POST http://localhost:50475/analyze -F 'file=@binary.elf'")
