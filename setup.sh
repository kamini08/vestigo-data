#!/bin/bash

################################################################################
# Vestigo Project Setup Script
# 
# This script sets up the complete Vestigo development environment including:
# - System dependencies (Podman, Python, build tools)
# - Python virtual environment with required packages
# - Firmware extractor container image
# - Ghidra installation (optional)
# - Database setup (PostgreSQL with Prisma)
#
# Supports: Fedora/RHEL and Ubuntu/Debian based systems
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PYTHON_VERSION="3.10"
VENV_DIR="venv"
CONTAINER_IMAGE_NAME="firmware-extractor"
GHIDRA_VERSION="11.0.1"
GHIDRA_INSTALL_DIR="/opt/ghidra"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_error "Please do not run this script as root. It will request sudo when needed."
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        print_info "Detected OS: $NAME $VERSION"
    else
        print_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
}

################################################################################
# System Package Installation
################################################################################

install_fedora_packages() {
    print_header "Installing Fedora/RHEL System Packages"
    
    sudo dnf update -y || print_warning "Failed to update package list"
    
    sudo dnf install -y \
        python3 \
        python3-pip \
        python3-devel \
        podman \
        git \
        gcc \
        gcc-c++ \
        make \
        automake \
        autoconf \
        libtool \
        zlib-devel \
        xz-devel \
        lzo-devel \
        openssl-devel \
        libmagic \
        file-devel \
        postgresql \
        postgresql-server \
        postgresql-devel \
        wget \
        curl \
        patch \
        || print_error "Some packages failed to install"
    
    print_success "Fedora packages installed"
}

install_ubuntu_packages() {
    print_header "Installing Ubuntu/Debian System Packages"
    
    sudo apt-get update || print_warning "Failed to update package list"
    
    sudo apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        podman \
        git \
        build-essential \
        gcc \
        g++ \
        make \
        automake \
        autoconf \
        libtool \
        zlib1g-dev \
        liblzma-dev \
        liblzo2-dev \
        libssl-dev \
        libmagic1 \
        libmagic-dev \
        postgresql \
        postgresql-contrib \
        libpq-dev \
        wget \
        curl \
        patch \
        || print_error "Some packages failed to install"
    
    print_success "Ubuntu packages installed"
}

install_system_packages() {
    case $OS in
        fedora|rhel|centos)
            install_fedora_packages
            ;;
        ubuntu|debian)
            install_ubuntu_packages
            ;;
        *)
            print_error "Unsupported OS: $OS"
            print_info "Supported: Fedora, RHEL, CentOS, Ubuntu, Debian"
            exit 1
            ;;
    esac
}

################################################################################
# Podman and Container Setup
################################################################################

setup_podman() {
    print_header "Setting Up Podman"
    
    # Verify podman installation
    if ! command -v podman &> /dev/null; then
        print_error "Podman is not installed or not in PATH"
        exit 1
    fi
    
    print_success "Podman is available: $(podman --version)"
    
    # Enable podman socket for rootless operation
    systemctl --user enable --now podman.socket 2>/dev/null || print_warning "Could not enable podman socket"
    
    print_success "Podman setup complete"
}

build_firmware_extractor_image() {
    print_header "Building Firmware Extractor Container Image"
    
    if [ ! -f "Containerfile" ]; then
        print_error "Containerfile not found in current directory"
        print_info "Please run this script from the project root directory"
        exit 1
    fi
    
    print_info "Building container image: $CONTAINER_IMAGE_NAME"
    print_info "This may take 5-15 minutes depending on your internet speed..."
    
    podman build -t $CONTAINER_IMAGE_NAME -f Containerfile . || {
        print_error "Container image build failed"
        exit 1
    }
    
    print_success "Container image '$CONTAINER_IMAGE_NAME' built successfully"
    
    # Verify the image
    podman images | grep $CONTAINER_IMAGE_NAME && print_success "Image verified"
}

################################################################################
# Python Environment Setup
################################################################################

setup_python_venv() {
    print_header "Setting Up Python Virtual Environment"
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    PYTHON_VER=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    print_info "Python version: $PYTHON_VER"
    
    # Create virtual environment
    if [ -d "$VENV_DIR" ]; then
        print_warning "Virtual environment already exists at $VENV_DIR"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf $VENV_DIR
            python3 -m venv $VENV_DIR
            print_success "Virtual environment recreated"
        else
            print_info "Using existing virtual environment"
        fi
    else
        python3 -m venv $VENV_DIR
        print_success "Virtual environment created at $VENV_DIR"
    fi
    
    # Activate virtual environment
    source $VENV_DIR/bin/activate
    
    # Upgrade pip
    print_info "Upgrading pip..."
    pip install --upgrade pip wheel setuptools
    
    print_success "Python virtual environment ready"
}

install_python_packages() {
    print_header "Installing Python Packages"
    
    # Ensure we're in the virtual environment
    if [ -z "$VIRTUAL_ENV" ]; then
        print_error "Virtual environment is not activated"
        exit 1
    fi
    
    # Install root requirements
    if [ -f "requirements.txt" ]; then
        print_info "Installing root requirements..."
        pip install -r requirements.txt || print_warning "Some root packages failed to install"
        print_success "Root requirements installed"
    fi
    
    # Install backend requirements
    if [ -f "backend/requirements.txt" ]; then
        print_info "Installing backend requirements..."
        pip install -r backend/requirements.txt || print_warning "Some backend packages failed to install"
        print_success "Backend requirements installed"
    fi
    
    # Install production requirements if exists
    if [ -f "requirements_production.txt" ]; then
        print_info "Installing production requirements..."
        pip install -r requirements_production.txt || print_warning "Some production packages failed to install"
    fi
    
    print_success "Python packages installation complete"
}

################################################################################
# Ghidra Setup (Optional)
################################################################################

install_ghidra() {
    print_header "Ghidra Installation (Optional)"
    
    read -p "Do you want to install Ghidra for binary analysis? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Skipping Ghidra installation"
        print_warning "Note: Binary feature extraction will not work without Ghidra"
        return
    fi
    
    # Check if Java is installed
    if ! command -v java &> /dev/null; then
        print_info "Installing Java (required for Ghidra)..."
        case $OS in
            fedora|rhel|centos)
                sudo dnf install -y java-17-openjdk java-17-openjdk-devel
                ;;
            ubuntu|debian)
                sudo apt-get install -y openjdk-17-jdk openjdk-17-jre
                ;;
        esac
    fi
    
    JAVA_VERSION=$(java -version 2>&1 | head -n 1)
    print_info "Java version: $JAVA_VERSION"
    
    # Check if Ghidra is already installed
    if [ -d "$GHIDRA_INSTALL_DIR" ]; then
        print_warning "Ghidra appears to be already installed at $GHIDRA_INSTALL_DIR"
        read -p "Do you want to reinstall? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Using existing Ghidra installation"
            return
        fi
        sudo rm -rf $GHIDRA_INSTALL_DIR
    fi
    
    print_info "Downloading Ghidra $GHIDRA_VERSION..."
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20240130.zip"
    
    # Try multiple download sources
    TEMP_DIR=$(mktemp -d)
    cd $TEMP_DIR
    
    if ! wget -q --show-progress "$GHIDRA_URL"; then
        print_warning "Direct download failed, trying alternative method..."
        print_info "Please download Ghidra manually from:"
        print_info "https://github.com/NationalSecurityAgency/ghidra/releases"
        print_info "Then extract it to $GHIDRA_INSTALL_DIR"
        cd - > /dev/null
        return
    fi
    
    print_info "Extracting Ghidra..."
    unzip -q ghidra_*.zip
    
    sudo mkdir -p /opt
    sudo mv ghidra_*_PUBLIC $GHIDRA_INSTALL_DIR
    
    cd - > /dev/null
    rm -rf $TEMP_DIR
    
    if [ -f "$GHIDRA_INSTALL_DIR/ghidraRun" ]; then
        print_success "Ghidra installed successfully at $GHIDRA_INSTALL_DIR"
    else
        print_error "Ghidra installation failed - ghidraRun not found at $GHIDRA_INSTALL_DIR"
        return
    fi
    
    # Set environment variable
    echo "export GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >> ~/.bashrc
    echo "export GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >> ~/.zshrc 2>/dev/null || true
    export GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR
    
    print_success "GHIDRA_INSTALL_DIR environment variable set"
}

################################################################################
# Database Setup
################################################################################

setup_database() {
    print_header "Database Setup"
    
    read -p "Do you want to set up PostgreSQL database? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Skipping database setup"
        print_warning "You'll need to configure DATABASE_URL manually in .env file"
        return
    fi
    
    # Initialize PostgreSQL (if not already done)
    case $OS in
        fedora|rhel|centos)
            if [ ! -d "/var/lib/pgsql/data/base" ]; then
                print_info "Initializing PostgreSQL..."
                sudo postgresql-setup --initdb || print_warning "PostgreSQL may already be initialized"
            fi
            sudo systemctl enable postgresql
            sudo systemctl start postgresql
            ;;
        ubuntu|debian)
            sudo systemctl enable postgresql
            sudo systemctl start postgresql
            ;;
    esac
    
    print_success "PostgreSQL service started"
    
    # Create database and user
    DB_NAME="vestigo"
    DB_USER="vestigo_user"
    DB_PASS=$(openssl rand -base64 12)
    
    print_info "Creating database and user..."
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || print_warning "Database may already exist"
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" 2>/dev/null || print_warning "User may already exist"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    
    # Create .env file
    if [ ! -f "backend/.env" ]; then
        print_info "Creating backend/.env file..."
        cat > backend/.env <<EOF
DATABASE_URL="postgresql://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME?schema=public"
EOF
        print_success "Database configuration saved to backend/.env"
    else
        print_warning "backend/.env already exists, not overwriting"
        print_info "Database connection string: postgresql://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME?schema=public"
    fi
    
    # Generate Prisma client
    print_info "Generating Prisma client..."
    cd backend
    if [ -n "$VIRTUAL_ENV" ]; then
        prisma generate || print_warning "Prisma generate failed - run manually later"
        prisma db push || print_warning "Prisma db push failed - run manually later"
    fi
    cd ..
    
    print_success "Database setup complete"
}

################################################################################
# Project Structure Verification
################################################################################

verify_project_structure() {
    print_header "Verifying Project Structure"
    
    REQUIRED_DIRS=("backend" "ghidra_scripts" "source_code" "analysis")
    REQUIRED_FILES=("Containerfile" "requirements.txt" "ingest.py" "unpack.py")
    
    for dir in "${REQUIRED_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            print_success "Directory '$dir' exists"
        else
            print_warning "Directory '$dir' not found (may be created on first run)"
        fi
    done
    
    for file in "${REQUIRED_FILES[@]}"; do
        if [ -f "$file" ]; then
            print_success "File '$file' exists"
        else
            print_error "File '$file' not found"
        fi
    done
    
    # Create necessary directories
    mkdir -p analysis_workspace ghidra_json ghidra_final_output logs job_storage
    print_success "Created working directories"
}

################################################################################
# Final Setup and Instructions
################################################################################

create_activation_script() {
    print_header "Creating Activation Helper"
    
    cat > activate_vestigo.sh <<'EOF'
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
EOF
    
    chmod +x activate_vestigo.sh
    print_success "Created activation script: ./activate_vestigo.sh"
}

print_final_instructions() {
    print_header "Setup Complete!"
    
    cat <<EOF
${GREEN}Vestigo project setup is complete!${NC}

${BLUE}Quick Start:${NC}
  1. Activate the environment:
     ${YELLOW}source ./activate_vestigo.sh${NC}
  
  2. Run the backend server:
     ${YELLOW}cd backend && uvicorn main:app --reload${NC}
  
  3. Access the API at:
     ${YELLOW}http://localhost:8000${NC}

${BLUE}Container Image:${NC}
  - Image name: ${YELLOW}$CONTAINER_IMAGE_NAME${NC}
  - Used by: ${YELLOW}unpack.py${NC} for firmware extraction
  - Test with: ${YELLOW}podman images | grep $CONTAINER_IMAGE_NAME${NC}

${BLUE}Environment:${NC}
  - Python venv: ${YELLOW}./$VENV_DIR${NC}
  - Activate: ${YELLOW}source $VENV_DIR/bin/activate${NC}
  - Ghidra: ${YELLOW}${GHIDRA_INSTALL_DIR:-Not installed}${NC}

${BLUE}Important Files:${NC}
  - Backend config: ${YELLOW}backend/.env${NC}
  - Logs: ${YELLOW}backend/logs/${NC}
  - Job storage: ${YELLOW}job_storage/${NC}
  - Ghidra output: ${YELLOW}ghidra_json/${NC}

${BLUE}Next Steps:${NC}
  - Test firmware extraction: ${YELLOW}python unpack.py <firmware.bin>${NC}
  - Test backend upload: ${YELLOW}curl -F "file=@test.bin" http://localhost:8000/analyze${NC}
  - View API docs: ${YELLOW}http://localhost:8000/docs${NC}

${YELLOW}Need help?${NC} Check the README files or run this script again.

EOF
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header "Vestigo Project Setup"
    print_info "This script will set up the complete Vestigo environment"
    print_info "Estimated time: 10-20 minutes"
    echo ""
    
    check_root
    detect_os
    
    # Core setup steps
    install_system_packages
    setup_podman
    build_firmware_extractor_image
    
    setup_python_venv
    install_python_packages
    
    # Optional components
    install_ghidra
    setup_database
    
    # Finalization
    verify_project_structure
    create_activation_script
    print_final_instructions
}

# Run main function
main
