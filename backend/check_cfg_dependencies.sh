#!/bin/bash
# Check and Install CFG Analysis Dependencies
# This script checks for required tools and provides installation instructions

echo "=================================="
echo "CFG Analysis Dependency Checker"
echo "=================================="
echo ""

MISSING=0

# Check for radare2
echo -n "Checking for radare2... "
if command -v r2 &> /dev/null || command -v radare2 &> /dev/null; then
    echo "✓ Found"
    if command -v r2 &> /dev/null; then
        R2_VERSION=$(r2 -v | head -n 1)
        echo "  Version: $R2_VERSION"
    fi
else
    echo "✗ Not found"
    MISSING=1
    echo "  Install: sudo apt-get install radare2"
    echo "  Or build from source: https://github.com/radareorg/radare2"
fi

# Check for GraphViz (dot command)
echo -n "Checking for GraphViz... "
if command -v dot &> /dev/null; then
    echo "✓ Found"
    DOT_VERSION=$(dot -V 2>&1)
    echo "  Version: $DOT_VERSION"
else
    echo "✗ Not found"
    MISSING=1
    echo "  Install: sudo apt-get install graphviz"
fi

# Check for binwalk (used by analysis script)
echo -n "Checking for binwalk... "
if command -v binwalk &> /dev/null; then
    echo "✓ Found"
    BINWALK_VERSION=$(binwalk --version 2>&1 | head -n 1)
    echo "  Version: $BINWALK_VERSION"
else
    echo "⚠ Not found (optional)"
    echo "  Install: sudo apt-get install binwalk"
fi

echo ""
echo "=================================="

if [ $MISSING -eq 0 ]; then
    echo "✓ All required dependencies are installed!"
    echo "You can run CFG analysis successfully."
else
    echo "✗ Some dependencies are missing."
    echo ""
    echo "Quick install all (Ubuntu/Debian):"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install -y radare2 graphviz binwalk"
    echo ""
    echo "After installing, restart the backend server."
    exit 1
fi

echo "=================================="
