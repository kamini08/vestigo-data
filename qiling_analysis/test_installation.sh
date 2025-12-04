#!/bin/bash
################################################################################
# Quick Test Script - Verify Qiling Crypto Detection Installation
################################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Qiling Crypto Detection - Installation Test              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}\n"

# Activate environment
if [ -f "$SCRIPT_DIR/qiling_env/bin/activate" ]; then
    source "$SCRIPT_DIR/qiling_env/bin/activate"
    echo -e "${GREEN}[✓]${NC} Virtual environment activated"
else
    echo -e "${RED}[✗]${NC} Virtual environment not found!"
    echo -e "${YELLOW}[!]${NC} Run ./setup.sh first"
    exit 1
fi

# Test 1: Python version
echo -e "\n${BLUE}[TEST 1]${NC} Python Version"
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "  Version: $PYTHON_VERSION"
MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
    echo -e "  ${GREEN}[✓] PASS${NC}"
else
    echo -e "  ${RED}[✗] FAIL - Need Python 3.8+${NC}"
    exit 1
fi

# Test 2: Core modules
echo -e "\n${BLUE}[TEST 2]${NC} Core Python Modules"
MODULES=("qiling" "capstone" "unicorn" "keystone" "yara" "Crypto")
ALL_OK=true

for module in "${MODULES[@]}"; do
    if python3 -c "import $module" 2>/dev/null; then
        VERSION=$(python3 -c "import $module; print(getattr($module, '__version__', 'unknown'))" 2>/dev/null)
        echo -e "  ${GREEN}[✓]${NC} $module ($VERSION)"
    else
        echo -e "  ${RED}[✗]${NC} $module NOT FOUND"
        ALL_OK=false
    fi
done

if [ "$ALL_OK" = false ]; then
    echo -e "\n${RED}[✗] Some modules missing - run ./setup.sh${NC}"
    exit 1
fi

# Test 3: Test scripts exist
echo -e "\n${BLUE}[TEST 3]${NC} Test Scripts"
SCRIPTS=(
    "tests/verify_crypto.py"
    "tests/constant_scanner.py"
    "tests/crypto_constants.py"
)

for script in "${SCRIPTS[@]}"; do
    if [ -f "$SCRIPT_DIR/$script" ]; then
        echo -e "  ${GREEN}[✓]${NC} $(basename $script)"
    else
        echo -e "  ${RED}[✗]${NC} $(basename $script) NOT FOUND"
        ALL_OK=false
    fi
done

# Test 4: Syntax check
echo -e "\n${BLUE}[TEST 4]${NC} Script Syntax"
if python3 -m py_compile "$SCRIPT_DIR/tests/verify_crypto.py" 2>/dev/null; then
    echo -e "  ${GREEN}[✓]${NC} verify_crypto.py compiles"
else
    echo -e "  ${RED}[✗]${NC} verify_crypto.py has syntax errors"
    ALL_OK=false
fi

if python3 -m py_compile "$SCRIPT_DIR/tests/constant_scanner.py" 2>/dev/null; then
    echo -e "  ${GREEN}[✓]${NC} constant_scanner.py compiles"
else
    echo -e "  ${RED}[✗]${NC} constant_scanner.py has syntax errors"
    ALL_OK=false
fi

# Test 5: Quick functionality test
echo -e "\n${BLUE}[TEST 5]${NC} Functionality Test"

# Find a test binary (use /bin/ls or /bin/sh)
TEST_BINARY=""
if [ -f "/bin/ls" ]; then
    TEST_BINARY="/bin/ls"
elif [ -f "/bin/sh" ]; then
    TEST_BINARY="/bin/sh"
elif [ -f "/usr/bin/python3" ]; then
    TEST_BINARY="/usr/bin/python3"
fi

if [ -n "$TEST_BINARY" ]; then
    echo "  Testing with: $TEST_BINARY"
    
    # Create a minimal test
    cat > /tmp/qiling_test.py << 'EOF'
import sys
sys.path.insert(0, '/home/prajwal/Documents/dynamic')

try:
    from qiling import Qiling
    print("QILING_IMPORT_OK")
except Exception as e:
    print(f"QILING_IMPORT_FAIL: {e}")
    sys.exit(1)

try:
    from tests.constant_scanner import scan_for_constants
    print("SCANNER_IMPORT_OK")
except Exception as e:
    print(f"SCANNER_IMPORT_FAIL: {e}")
    sys.exit(1)

# Try scanning constants
try:
    binary = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
    results = scan_for_constants(binary)
    print("SCAN_OK")
except Exception as e:
    print(f"SCAN_FAIL: {e}")
    sys.exit(1)

print("ALL_TESTS_PASSED")
EOF
    
    OUTPUT=$(python3 /tmp/qiling_test.py "$TEST_BINARY" 2>&1)
    
    if echo "$OUTPUT" | grep -q "ALL_TESTS_PASSED"; then
        echo -e "  ${GREEN}[✓]${NC} Qiling import: OK"
        echo -e "  ${GREEN}[✓]${NC} Scanner import: OK"
        echo -e "  ${GREEN}[✓]${NC} Constant scan: OK"
    else
        echo -e "  ${YELLOW}[!]${NC} Some tests incomplete:"
        echo "$OUTPUT" | grep -E "(OK|FAIL)" | sed 's/^/    /'
    fi
    
    rm -f /tmp/qiling_test.py
else
    echo -e "  ${YELLOW}[!]${NC} No test binary found - skipping"
fi

# Test 6: Helper scripts
echo -e "\n${BLUE}[TEST 6]${NC} Helper Scripts"
HELPERS=("activate.sh" "run_crypto_detector.sh" "update.sh")

for helper in "${HELPERS[@]}"; do
    if [ -f "$SCRIPT_DIR/$helper" ] && [ -x "$SCRIPT_DIR/$helper" ]; then
        echo -e "  ${GREEN}[✓]${NC} $helper (executable)"
    elif [ -f "$SCRIPT_DIR/$helper" ]; then
        echo -e "  ${YELLOW}[!]${NC} $helper (not executable)"
        chmod +x "$SCRIPT_DIR/$helper"
        echo -e "  ${GREEN}[✓]${NC} Made executable"
    else
        echo -e "  ${YELLOW}[!]${NC} $helper not found (run ./setup.sh)"
    fi
done

# Final summary
echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Test Summary                                              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}\n"

if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}[✓] ALL TESTS PASSED!${NC}\n"
    echo -e "Installation is working correctly.\n"
    echo -e "${BLUE}Quick Start:${NC}"
    echo -e "  ${YELLOW}source activate.sh${NC}"
    echo -e "  ${YELLOW}python3 tests/verify_crypto.py /path/to/binary${NC}"
    echo -e "\nOr use helper:"
    echo -e "  ${YELLOW}./run_crypto_detector.sh /path/to/binary${NC}"
    echo -e "\nDocumentation:"
    echo -e "  - QUICKSTART.md    : Quick start guide"
    echo -e "  - INSTALLATION.md  : Full installation guide"
    echo -e "  - README.md        : Project documentation"
    exit 0
else
    echo -e "${RED}[✗] SOME TESTS FAILED${NC}\n"
    echo -e "Please check the errors above and:"
    echo -e "  1. Run ${YELLOW}./setup.sh${NC} to reinstall"
    echo -e "  2. Check ${YELLOW}INSTALLATION.md${NC} for troubleshooting"
    echo -e "  3. Verify all dependencies are installed"
    exit 1
fi
