#!/bin/bash

# Cleanup script for unused documentation and files
# Generated on 2025-12-04

set -e

BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"

echo "==================================="
echo "Cleaning Up Unused Files"
echo "==================================="
echo ""
echo "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Function to move file to backup
backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        echo "  Moving: $file"
        mv "$file" "$BACKUP_DIR/"
    fi
}

echo ""
echo "1. Removing redundant/outdated ROOT documentation..."

# Historical/redundant documentation
backup_file "AVALANCHE_DETECTION.md"
backup_file "AVALANCHE_FIXES.md"
backup_file "AVALANCHE_SUMMARY.md"
backup_file "BATCH_PROCESSING.md"
backup_file "FIXES_APPLIED.md"
backup_file "FIXES_COMPLETE.md"
backup_file "PROJECT_SUMMARY.md"
backup_file "QNA.md"
backup_file "QUICKSTART.md"  # Keeping QUICKSTART_GUIDE.md
backup_file "WHAT_TO_DO_NOW.md"
backup_file "avalanche_workflow.txt"

echo ""
echo "2. Removing outdated DOCS directory files..."

# Historical documentation in docs/
backup_file "docs/FINAL_STATUS.md"
backup_file "docs/FINAL_TEST_RESULTS.md"
backup_file "docs/IMPROVEMENT_PLAN.md"
backup_file "docs/IMPROVEMENTS_SUMMARY.md"
backup_file "docs/V2_IMPROVEMENTS.md"
backup_file "docs/NOTES.md"
backup_file "docs/ADVANCED_FEATURES.md"

echo ""
echo "3. Checking Python utility scripts..."

# These are still used by batch processing
echo "  KEEPING: analyze_crypto_loops.py (used by batch_extract_features.py)"
echo "  KEEPING: detect_avalanche.py (standalone utility)"

# This one is not referenced anywhere
if [ -f "analyze_trace.py" ]; then
    echo "  Moving: analyze_trace.py (not referenced)"
    mv "analyze_trace.py" "$BACKUP_DIR/"
fi

echo ""
echo "==================================="
echo "Cleanup Summary"
echo "==================================="
echo ""
echo "FILES KEPT (Essential):"
echo "  Root documentation:"
echo "    - README.md (main documentation)"
echo "    - INSTALLATION.md (referenced in README)"
echo "    - QUICKSTART_GUIDE.md (quick start)"
echo "    - FEATURE_EXTRACTOR_README.md (ML pipeline)"
echo "    - ML_FEATURE_EXTRACTION_README.md (ML pipeline)"
echo ""
echo "  Docs directory:"
echo "    - docs/CRYPTO_DETECTOR_SUMMARY.md (referenced in README)"
echo "    - docs/QUICK_REFERENCE.md (referenced in README)"
echo "    - docs/STRIPPED_BINARY_SUPPORT.md (referenced in README)"
echo "    - docs/YARA_IMPLEMENTATION.md (useful reference)"
echo ""
echo "  Python scripts:"
echo "    - feature_extractor.py (main ML pipeline)"
echo "    - batch_extract_features.py (batch processing)"
echo "    - ml_preprocessor.py (ML preprocessing)"
echo "    - trace_analyzer.py (trace analysis)"
echo "    - analyze_crypto_loops.py (used by batch processor)"
echo "    - detect_avalanche.py (avalanche testing utility)"
echo "    - tests/verify_crypto.py (main detector)"
echo ""
echo "  Scripts:"
echo "    - setup.sh (installation)"
echo "    - test_installation.sh (testing)"
echo "    - test_yara.sh (YARA testing)"
echo "    - example_workflow.sh (example usage)"
echo ""
echo "BACKUP LOCATION:"
echo "  All removed files are in: $BACKUP_DIR/"
echo "  To restore a file: mv $BACKUP_DIR/filename ."
echo "  To permanently delete backup: rm -rf $BACKUP_DIR/"
echo ""
echo "✅ Cleanup complete!"
