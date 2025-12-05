#!/bin/bash
# Vestigo Environment Activation Script

# Activate Python virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "✓ Python virtual environment activated"
else
    echo "✗ Virtual environment not found. Run setup.sh first."
    exit 1
fi

# Set Ghidra path if installed
if [ -d "/opt/ghidra" ]; then
    export GHIDRA_INSTALL_DIR="/opt/ghidra"
    echo "✓ Ghidra path set: $GHIDRA_INSTALL_DIR"
fi

# Show status
echo ""
echo "Vestigo environment ready!"
echo "Python: $(python --version)"
echo "Working directory: $(pwd)"
echo ""
echo "To run the backend:"
echo "  cd backend && uvicorn main:app --reload"
echo ""
echo "To deactivate: deactivate"
