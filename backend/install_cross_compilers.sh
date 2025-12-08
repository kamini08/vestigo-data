#!/bin/bash
# Install cross-compiler toolchains for embedded binary analysis
# This enables .o to .elf conversion for different architectures

echo "=========================================="
echo "Cross-Compiler Toolchain Installation"
echo "=========================================="
echo ""
echo "This script will install binutils for:"
echo "  - ARM64 (aarch64)"
echo "  - ARM32 (arm)"
echo "  - MIPS"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

echo ""
echo "Installing cross-compiler toolchains..."
echo ""

# Detect package manager
if command -v apt &> /dev/null; then
    echo "Using apt package manager..."
    sudo apt update
    sudo apt install -y \
        binutils-aarch64-linux-gnu \
        binutils-arm-linux-gnueabi \
        binutils-arm-linux-gnueabihf \
        binutils-mips-linux-gnu \
        binutils-mipsel-linux-gnu
    
elif command -v yum &> /dev/null; then
    echo "Using yum package manager..."
    sudo yum install -y \
        binutils-aarch64-linux-gnu \
        binutils-arm-linux-gnu \
        binutils-mips-linux-gnu
    
elif command -v dnf &> /dev/null; then
    echo "Using dnf package manager..."
    sudo dnf install -y \
        binutils-aarch64-linux-gnu \
        binutils-arm-linux-gnu \
        binutils-mips-linux-gnu
    
else
    echo "ERROR: No supported package manager found (apt/yum/dnf)"
    echo "Please install manually:"
    echo "  - binutils-aarch64-linux-gnu"
    echo "  - binutils-arm-linux-gnueabi"
    echo "  - binutils-mips-linux-gnu"
    exit 1
fi

echo ""
echo "=========================================="
echo "Verifying installation..."
echo "=========================================="
echo ""

# Verify installation
tools_found=0
tools_total=3

echo -n "Checking aarch64-linux-gnu-ld... "
if command -v aarch64-linux-gnu-ld &> /dev/null; then
    echo "✓ Found"
    ((tools_found++))
else
    echo "✗ Not found"
fi

echo -n "Checking arm-linux-gnueabi-ld... "
if command -v arm-linux-gnueabi-ld &> /dev/null; then
    echo "✓ Found"
    ((tools_found++))
else
    echo "✗ Not found"
fi

echo -n "Checking mips-linux-gnu-ld... "
if command -v mips-linux-gnu-ld &> /dev/null; then
    echo "✓ Found"
    ((tools_found++))
else
    echo "✗ Not found"
fi

echo ""
echo "=========================================="
echo "Installation complete: $tools_found/$tools_total tools installed"
echo "=========================================="
echo ""

if [ $tools_found -eq $tools_total ]; then
    echo "✓ All cross-compiler toolchains installed successfully!"
    echo ""
    echo "The backend can now convert .o files for:"
    echo "  - ARM64/AArch64 binaries"
    echo "  - ARM32 binaries"
    echo "  - MIPS binaries"
else
    echo "⚠ Some toolchains are missing. The backend will skip"
    echo "  .o to .elf conversion for unsupported architectures."
    echo ""
    echo "  Qiling will attempt to analyze .o files directly,"
    echo "  but this may have limited success."
fi

echo ""
