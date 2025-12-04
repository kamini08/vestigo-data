# Installation Guide

## Quick Installation

The easiest way to set up the entire Qiling Crypto Detection Framework:

```bash
./setup.sh
```

This will automatically:
1. ✅ Install all system dependencies
2. ✅ Create Python virtual environment
3. ✅ Install Qiling and all Python packages
4. ✅ Set up rootfs directory structure
5. ✅ Create helper scripts
6. ✅ Verify installation

## Installation Options

### Full Installation (Recommended)
```bash
./setup.sh
```

### Skip System Dependencies
If you already have build tools and system libraries installed:
```bash
./setup.sh --skip-system-deps
```

### Skip Virtual Environment
If you want to use your own Python environment:
```bash
./setup.sh --skip-venv
```

### Development Mode
Includes symbolic execution tools (angr, z3) for advanced analysis:
```bash
./setup.sh --dev
```

## Supported Operating Systems

- ✅ **Ubuntu/Debian** (18.04+)
- ✅ **Fedora/RHEL** (8+)
- ✅ **Arch Linux/Manjaro**
- ✅ **macOS** (10.15+)

## System Requirements

### Minimum
- **CPU**: x86_64 (64-bit)
- **RAM**: 4 GB
- **Disk**: 2 GB free space
- **Python**: 3.8 or higher

### Recommended
- **CPU**: Multi-core x86_64
- **RAM**: 8 GB or more
- **Disk**: 5 GB free space (for rootfs)
- **Python**: 3.10 or higher

## Manual Installation

If the automated script doesn't work for your system, follow these steps:

### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv git build-essential \
    cmake libffi-dev libssl-dev zlib1g-dev yara binutils
```

**Fedora/RHEL:**
```bash
sudo dnf install -y python3 python3-pip python3-devel git gcc gcc-c++ \
    cmake libffi-devel openssl-devel zlib-devel yara binutils
```

**macOS:**
```bash
brew install python@3.11 git cmake libffi openssl zlib yara binutils
```

### 2. Create Virtual Environment
```bash
python3 -m venv qiling_env
source qiling_env/bin/activate
```

### 3. Install Python Packages
```bash
pip install --upgrade pip setuptools wheel

# Core Qiling dependencies
pip install 'capstone>=4' 'unicorn==2.1.3' 'pefile>=2022.5.30' \
    'python-registry>=1.3.1' 'keystone-engine>=0.9.2' 'pyelftools>=0.28' \
    'gevent>=20.9.0' 'multiprocess>=0.70.12.2' 'pyyaml>=6.0.1' \
    'python-fx' 'questionary' 'termcolor'

# Crypto analysis tools
pip install 'yara-python' 'pycryptodome' 'z3-solver'

# Install Qiling from source
pip install -e ./qiling
```

### 4. Set Up Rootfs
```bash
mkdir -p rootfs/{x86_linux,x8664_linux,arm_linux,arm64_linux,mips32el_linux,x86_windows,x8664_windows}
```

For actual binary emulation, you'll need to populate rootfs with system libraries (see Rootfs Setup below).

## Rootfs Setup

The rootfs (root filesystem) contains system libraries required for binary emulation.

### Option 1: Download Pre-built Rootfs (Recommended)
```bash
cd rootfs
git clone https://github.com/qilingframework/rootfs.git temp_rootfs
mv temp_rootfs/* .
rm -rf temp_rootfs
```

### Option 2: Build Your Own (Linux Only)

**For x86_64 Linux binaries:**
```bash
mkdir -p rootfs/x8664_linux/lib
cp -r /lib/x86_64-linux-gnu/* rootfs/x8664_linux/lib/
cp -r /usr/lib/x86_64-linux-gnu/* rootfs/x8664_linux/lib/
```

**For 32-bit Linux binaries:**
```bash
sudo apt-get install libc6-i386
mkdir -p rootfs/x86_linux/lib
cp -r /lib/i386-linux-gnu/* rootfs/x86_linux/lib/
cp -r /usr/lib/i386-linux-gnu/* rootfs/x86_linux/lib/
```

### Option 3: Windows DLLs

For Windows binaries, you need DLLs from a Windows installation:
```bash
# From a Windows machine, copy:
C:\Windows\System32\*.dll → rootfs/x8664_windows/dlls/
C:\Windows\SysWOW64\*.dll → rootfs/x86_windows/dlls/
```

## Verification

After installation, verify everything works:

```bash
# Activate environment
source activate.sh

# Check Qiling
python3 -c "import qiling; print(f'Qiling {qiling.__version__}')"

# Check dependencies
python3 -c "import capstone, unicorn, keystone, yara; print('All modules OK')"

# Run crypto detector on a test binary
python3 tests/verify_crypto.py /bin/ls
```

Expected output:
```
[*] Starting Crypto Function Detection
[*] Binary: /bin/ls
[*] Architecture: x8664
[+] Detected 3 crypto-like functions
...
```

## Troubleshooting

### Issue: "Python 3.8+ required"
**Solution:** Install newer Python:
```bash
# Ubuntu
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install python3.11 python3.11-venv

# Use Python 3.11
python3.11 -m venv qiling_env
```

### Issue: "unicorn installation failed"
**Solution:** Install from system package first:
```bash
# Ubuntu
sudo apt-get install python3-unicorn

# Or build from source
git clone https://github.com/unicorn-engine/unicorn
cd unicorn
./make.sh
sudo ./make.sh install
```

### Issue: "keystone installation failed"
**Solution:** Install system dependencies:
```bash
# Ubuntu
sudo apt-get install cmake libboost-dev
pip install keystone-engine
```

### Issue: "No module named 'qiling'"
**Solution:** Install Qiling in editable mode:
```bash
source qiling_env/bin/activate
cd qiling
pip install -e .
```

### Issue: "Rootfs not found" errors
**Solution:** Either:
1. Download pre-built rootfs (Option 1 above)
2. Create minimal rootfs structure:
   ```bash
   mkdir -p rootfs/x8664_linux/{bin,lib,usr}
   ```

### Issue: Script hangs during execution
**Solution:** Increase timeout or reduce binary size:
```bash
# Edit verify_crypto.py
TIMEOUT = 60  # Increase from 30
MAX_INSTRUCTIONS = 100000  # Reduce if needed
```

## Post-Installation

### Update Qiling and Dependencies
```bash
./update.sh
```

### Add Custom Crypto Signatures
Edit `tests/crypto_constants.py` to add your own constants:
```python
MY_CUSTOM_CIPHER_SBOX = bytes([0x01, 0x02, 0x03, ...])
```

### Configure Detection Thresholds
Edit `tests/verify_crypto.py`:
```python
CONFIDENCE_THRESHOLDS = {
    'HIGH': 70,      # Adjust as needed
    'MEDIUM': 40,
    'LOW': 20
}
```

## What Gets Installed

### System Packages
- Build tools (gcc, g++, make, cmake)
- Python development headers
- Cryptographic libraries (openssl, libffi)
- Binary analysis tools (yara, binutils)

### Python Packages
- **Qiling Framework** - Binary emulation
- **Capstone** - Disassembly
- **Unicorn** - CPU emulation
- **Keystone** - Assembly
- **YARA** - Pattern matching
- **PyCryptodome** - Crypto implementations
- **Z3** - SMT solver (optional)
- **angr** - Symbolic execution (dev mode only)

### Directory Structure
```
.
├── qiling/              # Qiling source code
├── qiling_env/          # Python virtual environment
├── rootfs/              # Root filesystems for emulation
├── tests/               # Crypto detection scripts
├── setup.sh             # This installation script
├── activate.sh          # Quick activation
├── run_crypto_detector.sh # Quick run script
└── update.sh            # Update script
```

## Next Steps

1. **Test the installation:**
   ```bash
   ./run_crypto_detector.sh /bin/ls
   ```

2. **Read the documentation:**
   - `tests/QUICK_REFERENCE.md` - Quick start guide
   - `docs/USAGE.md` - Detailed usage

3. **Try examples:**
   ```bash
   source activate.sh
   python3 tests/verify_crypto.py examples/aes_sample
   ```

4. **Customize detection:**
   - Add custom constants in `tests/crypto_constants.py`
   - Adjust thresholds in `tests/verify_crypto.py`
   - Create custom analyzers

## Uninstallation

To remove the installation:
```bash
# Remove virtual environment
rm -rf qiling_env/

# Remove downloaded dependencies (optional)
rm -rf qiling/ rootfs/

# Remove helper scripts
rm -f activate.sh run_crypto_detector.sh update.sh
```

## Support

- **Documentation**: `docs/` directory
- **Issues**: Check `tests/NOTES.md` for known issues
- **Qiling Help**: https://github.com/qilingframework/qiling
- **Crypto Detection**: `tests/CRYPTO_DETECTOR_SUMMARY.md`

## License

This installation script is provided as-is for setting up the Qiling Crypto Detection Framework. Individual components have their own licenses:
- Qiling Framework: GPLv2
- Unicorn Engine: GPLv2
- Other dependencies: See respective licenses
