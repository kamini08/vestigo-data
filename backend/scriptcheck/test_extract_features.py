import sys
import os
import asyncio
import logging

# Add backend to sys.path so imports work
sys.path.append(os.path.join(os.getcwd(), "backend"))

# Mock logger to avoid import errors if config is missing or complex
# But let's try to import the real service first.
# If config.logging_config fails, we might need to mock it or adjust path further.

try:
    from services.feature_extraction_service import FeatureExtractionService
except ImportError as e:
    print(f"ImportError: {e}")
    # Try adding current dir to path too
    sys.path.append(os.getcwd())
    from backend.services.feature_extraction_service import FeatureExtractionService

async def main():
    # Initialize service
    service = FeatureExtractionService()
    
    # Test binary
    binary_path = os.path.abspath("dataset_binaries/aes128_arm_gcc_O0.elf")
    job_id = "test_run_001"
    
    print(f"Running extraction for {binary_path}...")
    
    try:
        result = await service.extract_features_from_binary(job_id, binary_path)
        print("Extraction successful!")
        print(f"Functions extracted: {len(result.get('functions', []))}")
        
        # Verify output directory
        expected_output_dir = os.path.join(os.getcwd(), "ghidra_final_output")
        expected_file = os.path.join(expected_output_dir, "aes128_arm_gcc_O0.elf_features.json")
        
        if os.path.exists(expected_file):
            print(f"Output file found at: {expected_file}")
        else:
            print(f"ERROR: Output file NOT found at: {expected_file}")
            
    except Exception as e:
        print(f"Extraction failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Configure basic logging
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
