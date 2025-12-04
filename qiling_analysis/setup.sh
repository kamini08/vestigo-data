#!/bin/bash
################################################################################
# Qiling Crypto Detection Framework - Complete Setup Script
################################################################################
# This script installs all necessary dependencies and sets up the environment
# for running crypto function detection on binary files.
#
# Supported OS: Ubuntu/Debian, Fedora/RHEL, Arch Linux, macOS
# Requirements: sudo access, internet connection
#
# Usage: ./setup.sh [--skip-system-deps] [--skip-venv] [--dev]
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/qiling_env"
ROOTFS_DIR="${SCRIPT_DIR}/rootfs"
QILING_DIR="${SCRIPT_DIR}/qiling"
TESTS_DIR="${SCRIPT_DIR}/tests"

# Parse command line arguments
SKIP_SYSTEM_DEPS=false
SKIP_VENV=false
DEV_MODE=false

for arg in "$@"; do
    case $arg in
        --skip-system-deps)
            SKIP_SYSTEM_DEPS=true
            shift
            ;;
        --skip-venv)
            SKIP_VENV=true
            shift
            ;;
        --dev)
            DEV_MODE=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}"
            echo "Usage: $0 [--skip-system-deps] [--skip-venv] [--dev]"
            exit 1
            ;;
    esac
done

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
        elif [ -f /etc/debian_version ]; then
            OS="debian"
        elif [ -f /etc/redhat-release ]; then
            OS="rhel"
        else
            OS="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    echo $OS
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

################################################################################
# System Dependencies Installation
################################################################################

install_system_deps() {
    print_header "Installing System Dependencies"
    
    OS=$(detect_os)
    print_info "Detected OS: $OS"
    
    case $OS in
        ubuntu|debian|pop)
            print_info "Installing dependencies for Debian/Ubuntu..."
            sudo apt-get update
            sudo apt-get install -y \
                python3 \
                python3-pip \
                python3-venv \
                python3-dev \
                git \
                build-essential \
                cmake \
                libffi-dev \
                libssl-dev \
                libtool \
                autoconf \
                automake \
                pkg-config \
                wget \
                curl \
                gcc \
                g++ \
                make \
                zlib1g-dev \
                libbz2-dev \
                libreadline-dev \
                libsqlite3-dev \
                llvm \
                libncurses5-dev \
                libncursesw5-dev \
                xz-utils \
                tk-dev \
                libxml2-dev \
                libxmlsec1-dev \
                libffi-dev \
                liblzma-dev \
                yara \
                binutils \
                file
            ;;
            
        fedora|rhel|centos)
            print_info "Installing dependencies for Fedora/RHEL..."
            sudo dnf install -y \
                python3 \
                python3-pip \
                python3-devel \
                git \
                gcc \
                gcc-c++ \
                make \
                cmake \
                libffi-devel \
                openssl-devel \
                zlib-devel \
                bzip2-devel \
                readline-devel \
                sqlite-devel \
                llvm \
                ncurses-devel \
                xz-devel \
                tk-devel \
                libxml2-devel \
                xmlsec1-devel \
                yara \
                binutils \
                file
            ;;
            
        arch|manjaro)
            print_info "Installing dependencies for Arch Linux..."
            sudo pacman -Sy --noconfirm \
                python \
                python-pip \
                git \
                base-devel \
                cmake \
                libffi \
                openssl \
                zlib \
                bzip2 \
                readline \
                sqlite \
                llvm \
                ncurses \
                xz \
                tk \
                libxml2 \
                xmlsec \
                yara \
                binutils \
                file
            ;;
            
        macos)
            print_info "Installing dependencies for macOS..."
            if ! check_command brew; then
                print_error "Homebrew not found. Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            
            brew update
            brew install \
                python@3.11 \
                git \
                cmake \
                libffi \
                openssl@3 \
                zlib \
                bzip2 \
                readline \
                sqlite \
                llvm \
                ncurses \
                xz \
                tk \
                libxml2 \
                xmlsec1 \
                yara \
                binutils
            ;;
            
        *)
            print_error "Unsupported OS: $OS"
            print_warning "Please install dependencies manually:"
            print_info "  - Python 3.8+"
            print_info "  - pip"
            print_info "  - git"
            print_info "  - gcc/g++ (build tools)"
            print_info "  - cmake"
            print_info "  - libffi, openssl, zlib (development headers)"
            exit 1
            ;;
    esac
    
    print_success "System dependencies installed"
}

################################################################################
# Python Virtual Environment Setup
################################################################################

setup_venv() {
    print_header "Setting Up Python Virtual Environment"
    
    # Check Python version
    if ! check_command python3; then
        print_error "Python 3 not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    print_info "Python version: $PYTHON_VERSION"
    
    # Check if version is at least 3.8
    MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 8 ]); then
        print_error "Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
        exit 1
    fi
    
    # Create virtual environment
    if [ -d "$VENV_DIR" ]; then
        print_warning "Virtual environment already exists at $VENV_DIR"
        read -p "Remove and recreate? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Removing existing virtual environment..."
            rm -rf "$VENV_DIR"
        else
            print_info "Using existing virtual environment"
            return
        fi
    fi
    
    print_info "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    
    print_success "Virtual environment created"
}

################################################################################
# Python Dependencies Installation
################################################################################

install_python_deps() {
    print_header "Installing Python Dependencies"
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    print_info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel
    
    # Install core dependencies
    print_info "Installing core Qiling dependencies..."
    pip install \
        'capstone>=4' \
        'unicorn==2.1.3' \
        'pefile>=2022.5.30' \
        'python-registry>=1.3.1' \
        'keystone-engine>=0.9.2' \
        'pyelftools>=0.28' \
        'gevent>=20.9.0' \
        'multiprocess>=0.70.12.2' \
        'pyyaml>=6.0.1' \
        'python-fx' \
        'questionary' \
        'termcolor'
    
    # Install crypto analysis dependencies
    print_info "Installing crypto analysis tools..."
    pip install \
        'yara-python' \
        'pycryptodome' \
        'z3-solver'
    
    # Install symbolic execution tools (optional, for CryptoHunt-style analysis)
    if [ "$DEV_MODE" = true ]; then
        print_info "Installing symbolic execution tools (dev mode)..."
        pip install \
            'angr' \
            'claripy' \
            'cle' \
            'archinfo'
    fi
    
    # Install Qiling from source
    print_info "Installing Qiling from source..."
    if [ -d "$QILING_DIR" ]; then
        pip install -e "$QILING_DIR"
    else
        print_warning "Qiling source directory not found at $QILING_DIR"
        print_info "Cloning Qiling repository..."
        git clone https://github.com/qilingframework/qiling.git "$QILING_DIR"
        pip install -e "$QILING_DIR"
    fi
    
    # Install testing and development tools
    print_info "Installing development tools..."
    pip install \
        'pytest' \
        'pytest-cov' \
        'black' \
        'flake8' \
        'mypy'
    
    print_success "Python dependencies installed"
}

################################################################################
# Rootfs Setup
################################################################################

setup_rootfs() {
    print_header "Setting Up Rootfs (Root Filesystems)"
    
    if [ ! -d "$ROOTFS_DIR" ]; then
        print_info "Creating rootfs directory..."
        mkdir -p "$ROOTFS_DIR"
    fi
    
    # Check if rootfs is already populated
    if [ "$(ls -A $ROOTFS_DIR 2>/dev/null)" ]; then
        print_info "Rootfs directory is already populated"
        print_info "Contents: $(ls -1 $ROOTFS_DIR | wc -l) directories"
        return
    fi
    
    print_info "Downloading sample rootfs files..."
    print_warning "Full rootfs setup requires downloading from Qiling's repository"
    print_info "You can manually populate rootfs or use Qiling's provided rootfs"
    
    # Create basic directory structure
    ARCHS=("x86_linux" "x8664_linux" "arm_linux" "arm64_linux" "mips32el_linux" "x86_windows" "x8664_windows")
    
    for arch in "${ARCHS[@]}"; do
        mkdir -p "$ROOTFS_DIR/$arch"
        print_info "Created $arch rootfs directory"
    done
    
    # Create README
    cat > "$ROOTFS_DIR/README.md" << 'EOF'
# Qiling Rootfs

This directory contains root filesystems for different architectures.

## Setup Instructions

1. Download pre-built rootfs from Qiling's repository:
   ```bash
   git clone https://github.com/qilingframework/rootfs.git
   ```

2. Or build your own by copying system libraries:
   ```bash
   # For x8664 Linux
   mkdir -p x8664_linux/lib
   cp -r /lib/x86_64-linux-gnu/* x8664_linux/lib/
   cp -r /usr/lib/x86_64-linux-gnu/* x8664_linux/lib/
   ```

3. For Windows DLLs, you need to copy from a Windows installation

## Directory Structure

- x86_linux/     - 32-bit Linux binaries
- x8664_linux/   - 64-bit Linux binaries
- arm_linux/     - ARM 32-bit Linux
- arm64_linux/   - ARM 64-bit Linux
- mips32el_linux/ - MIPS 32-bit little-endian Linux
- x86_windows/   - 32-bit Windows binaries
- x8664_windows/ - 64-bit Windows binaries
EOF
    
    print_success "Rootfs directory structure created"
    print_warning "Note: You need to populate rootfs with actual system libraries"
    print_info "See $ROOTFS_DIR/README.md for instructions"
}

################################################################################
# Verify Installation
################################################################################

verify_installation() {
    print_header "Verifying Installation"
    
    source "$VENV_DIR/bin/activate"
    
    # Check Python modules
    print_info "Checking Python modules..."
    
    MODULES=("qiling" "capstone" "unicorn" "keystone" "yara" "Crypto" "z3")
    ALL_OK=true
    
    for module in "${MODULES[@]}"; do
        if python3 -c "import $module" 2>/dev/null; then
            print_success "$module installed"
        else
            print_error "$module NOT installed"
            ALL_OK=false
        fi
    done
    
    # Check test scripts
    print_info "Checking test scripts..."
    
    SCRIPTS=(
        "$TESTS_DIR/verify_crypto.py"
        "$TESTS_DIR/constant_scanner.py"
        "$TESTS_DIR/crypto_constants.py"
    )
    
    for script in "${SCRIPTS[@]}"; do
        if [ -f "$script" ]; then
            print_success "$(basename $script) found"
        else
            print_error "$(basename $script) NOT found"
            ALL_OK=false
        fi
    done
    
    # Check if scripts are executable
    if [ -f "$TESTS_DIR/verify_crypto.py" ]; then
        if python3 -m py_compile "$TESTS_DIR/verify_crypto.py" 2>/dev/null; then
            print_success "verify_crypto.py compiles successfully"
        else
            print_error "verify_crypto.py has syntax errors"
            ALL_OK=false
        fi
    fi
    
    if [ "$ALL_OK" = true ]; then
        print_success "All checks passed!"
        return 0
    else
        print_error "Some checks failed"
        return 1
    fi
}

################################################################################
# Create Helper Scripts
################################################################################

create_helpers() {
    print_header "Creating Helper Scripts"
    
    # Create activation script
    cat > "$SCRIPT_DIR/activate.sh" << 'EOF'
#!/bin/bash
# Quick activation script for Qiling environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/qiling_env/bin/activate"

echo "Qiling environment activated!"
echo "Python: $(which python3)"
echo "Qiling version: $(python3 -c 'import qiling; print(qiling.__version__)' 2>/dev/null || echo 'unknown')"
echo ""
echo "Available test scripts:"
echo "  - tests/verify_crypto.py      : Main crypto detection script"
echo "  - tests/constant_scanner.py   : Constant detection only"
echo "  - tests/crypto_scanner.py     : Alternative scanner"
echo ""
echo "Usage example:"
echo "  python3 tests/verify_crypto.py /path/to/binary"
EOF
    chmod +x "$SCRIPT_DIR/activate.sh"
    print_success "Created activate.sh"
    
    # Create run script
    cat > "$SCRIPT_DIR/run_crypto_detector.sh" << 'EOF'
#!/bin/bash
# Quick run script for crypto detection

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/qiling_env/bin/activate"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <binary_path> [options]"
    echo ""
    echo "Options:"
    echo "  --verbose    : Enable verbose output"
    echo "  --no-const   : Skip constant scanning"
    echo "  --threads N  : Use N threads (default: 4)"
    echo ""
    exit 1
fi

python3 "$SCRIPT_DIR/tests/verify_crypto.py" "$@"
EOF
    chmod +x "$SCRIPT_DIR/run_crypto_detector.sh"
    print_success "Created run_crypto_detector.sh"
    
    # Create update script
    cat > "$SCRIPT_DIR/update.sh" << 'EOF'
#!/bin/bash
# Update Qiling and dependencies

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/qiling_env/bin/activate"

echo "Updating Qiling..."
cd "$SCRIPT_DIR/qiling"
git pull

echo "Updating Python dependencies..."
pip install --upgrade pip
pip install --upgrade qiling capstone unicorn keystone

echo "Update complete!"
EOF
    chmod +x "$SCRIPT_DIR/update.sh"
    print_success "Created update.sh"
}

################################################################################
# Print Usage Information
################################################################################

print_usage() {
    print_header "Setup Complete!"
    
    cat << EOF
${GREEN}Installation successful!${NC}

${BLUE}Quick Start:${NC}
  1. Activate the environment:
     ${YELLOW}source activate.sh${NC}
     
  2. Run crypto detection:
     ${YELLOW}python3 tests/verify_crypto.py /path/to/binary${NC}
     
  Or use the helper script:
     ${YELLOW}./run_crypto_detector.sh /path/to/binary${NC}

${BLUE}Available Scripts:${NC}
  ${GREEN}activate.sh${NC}              - Activate virtual environment
  ${GREEN}run_crypto_detector.sh${NC}   - Run crypto detection on a binary
  ${GREEN}update.sh${NC}                - Update Qiling and dependencies

${BLUE}Test Scripts:${NC}
  ${GREEN}tests/verify_crypto.py${NC}        - Main crypto function detector
  ${GREEN}tests/constant_scanner.py${NC}     - Standalone constant scanner
  ${GREEN}tests/crypto_constants.py${NC}     - Crypto constant definitions
  ${GREEN}tests/verify_crypto_v2.py${NC}     - Enhanced version
  ${GREEN}tests/universal_verifier.py${NC}   - Universal crypto verifier

${BLUE}Configuration:${NC}
  Virtual Environment: ${YELLOW}$VENV_DIR${NC}
  Qiling Source:       ${YELLOW}$QILING_DIR${NC}
  Rootfs:              ${YELLOW}$ROOTFS_DIR${NC}
  Tests:               ${YELLOW}$TESTS_DIR${NC}

${BLUE}Next Steps:${NC}
  1. Populate rootfs with system libraries (see rootfs/README.md)
  2. Test with a sample binary:
     ${YELLOW}source activate.sh${NC}
     ${YELLOW}python3 tests/verify_crypto.py /bin/ls${NC}

${BLUE}Documentation:${NC}
  - Qiling docs: https://docs.qiling.io
  - Project README: $SCRIPT_DIR/README.md

${YELLOW}Note: Rootfs requires manual setup for full functionality.${NC}
${YELLOW}See $ROOTFS_DIR/README.md for details.${NC}

For issues or questions, check the Qiling documentation or GitHub issues.
EOF
}

################################################################################
# Main Installation Flow
################################################################################

main() {
    clear
    cat << "EOF"
  ___  _ _ _               ___                  _        
 / _ \(_) (_)_ _  __ _    / __|_ _ _  _ _ __ | |_ ___  
| (_) | | | | ' \/ _` |  | (__| '_| || | '_ \|  _/ _ \ 
 \__\_\_|_|_|_||_\__, |   \___|_|  \_, | .__/ \__\___/ 
                  |___/             |__/|_|             
   ___     _           _   _                            
  |   \ ___| |_ ___ __| |_(_)___ _ _                    
  | |) / -_)  _/ -_) _|  _| / _ \ ' \                   
  |___/\___|\__\___\__|\__|_\___/_||_|                  
                                                         
  Complete Setup Script v1.0
EOF
    
    print_info "Starting installation at $(date)"
    print_info "Installation directory: $SCRIPT_DIR"
    echo ""
    
    # System dependencies
    if [ "$SKIP_SYSTEM_DEPS" = false ]; then
        install_system_deps
    else
        print_warning "Skipping system dependencies installation"
    fi
    
    # Virtual environment
    if [ "$SKIP_VENV" = false ]; then
        setup_venv
        install_python_deps
    else
        print_warning "Skipping virtual environment setup"
    fi
    
    # Rootfs
    setup_rootfs
    
    # Helper scripts
    create_helpers
    
    # Verification
    if verify_installation; then
        print_usage
        exit 0
    else
        print_error "Installation verification failed"
        print_warning "Some components may not work correctly"
        exit 1
    fi
}

################################################################################
# Run Main
################################################################################

main "$@"
