# Quick Setup Guide

Fast installation guide for the Qiling Crypto Detection Framework.

## Prerequisites

- Python 3.8+
- Git
- Linux or macOS
- strace (for system call tracing)

## Installation Steps

### 1. Install System Dependencies

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git strace

# RHEL/CentOS/Fedora
sudo yum install -y python3 python3-pip git strace

# macOS (via Homebrew)
brew install python git
# Note: strace is not available on macOS, but the tool will skip it gracefully
```

### 2. Create Virtual Environment

```bash
cd qiling_analysis
python3 -m venv qiling_env
source qiling_env/bin/activate
```

### 3. Install Core Dependencies

```bash
pip install --upgrade pip setuptools wheel

pip install 'capstone>=4' \
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
```

### 4. Install Analysis Tools

```bash
pip install 'yara-python' \
            'pycryptodome' \
            'z3-solver'
```

### 5. Install Development Tools (Optional)

```bash
pip install 'pytest' \
            'pytest-cov' \
            'black' \
            'flake8' \
            'mypy'
```

### 6. Install Qiling Framework

```bash
git clone https://github.com/qilingframework/qiling.git
pip install -e ./qiling
```

### 7. Setup Rootfs

```bash
git clone https://github.com/qilingframework/rootfs.git
```

## Verify Installation

```bash
source qiling_env/bin/activate
python3 -c "import qiling; print('Qiling installed successfully')"
ls rootfs/
strace --version  # Should show strace version
```

## Usage

```bash
source qiling_env/bin/activate
python3 tests/verify_crypto.py /path/to/binary.elf
```

**Note:** The script will automatically:
- Run strace to capture native system calls (if strace is installed)
- Store strace logs in `tests/strace_logs/` directory
- Fall back to Qiling emulation if strace fails or is unavailable

### Strace Logs

Strace logs are saved with timestamps:
```
tests/strace_logs/strace_<binary_name>_<timestamp>.log
```

These logs capture:
- All system calls made by the binary
- `getrandom()` calls with sizes
- Random device reads (`/dev/random`, `/dev/urandom`)
- File operations related to crypto
- Memory operations (mmap, mprotect)

## Directory Structure

After installation, you should have:

```
qiling_analysis/
├── tests/
│   ├── verify_crypto.py
│   └── strace_logs/         # Auto-generated strace logs
|── qiling               # Cloned from Github
├── rootfs/              # Cloned from GitHub
│   ├── arm64_linux/
│   ├── arm_linux/
│   ├── x8664_linux/
│   ├── x86_linux/
│   └── ...
├── qiling_env/          # Virtual environment
└── README.md
```

## Troubleshooting

### strace Not Installed
```bash
# Debian/Ubuntu
sudo apt install strace

# RHEL/CentOS
sudo yum install strace

# macOS - strace not available, script will skip it automatically
```

### Rootfs Not Found
```bash
cd qiling_analysis
git clone https://github.com/qilingframework/rootfs.git
```

### Virtual Environment Not Active
```bash
source qiling_env/bin/activate
```

### Module Not Found
```bash
pip install -e ./qiling
```

## One-Line Installer

Save this as `quick_install.sh`:

```bash
#!/bin/bash
# Install system dependencies first (requires sudo)
if command -v apt &> /dev/null; then
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv git strace
elif command -v yum &> /dev/null; then
    sudo yum install -y python3 python3-pip git strace
fi

# Setup Python environment
python3 -m venv qiling_env && \
source qiling_env/bin/activate && \
pip install --upgrade pip setuptools wheel && \
pip install 'capstone>=4' 'unicorn==2.1.3' 'pefile>=2022.5.30' 'python-registry>=1.3.1' 'keystone-engine>=0.9.2' 'pyelftools>=0.28' 'gevent>=20.9.0' 'multiprocess>=0.70.12.2' 'pyyaml>=6.0.1' 'python-fx' 'questionary' 'termcolor' && \
pip install 'yara-python' 'pycryptodome' 'z3-solver' && \
cd .. && git clone https://github.com/qilingframework/qiling.git && pip install -e ./qiling && cd qiling_analysis && \
git clone https://github.com/qilingframework/rootfs.git && \
echo "✓ Installation complete! Run: source qiling_env/bin/activate"
```

Then run:
```bash
chmod +x quick_install.sh
./quick_install.sh
```

## Full Documentation

See [INSTALLATION.md](INSTALLATION.md) for detailed installation guide and troubleshooting.
