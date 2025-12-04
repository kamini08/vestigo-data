# Quick Setup Guide

Fast installation guide for the Qiling Crypto Detection Framework.

## Prerequisites

- Python 3.8+
- Git
- Linux or macOS

## Installation Steps

### 1. Create Virtual Environment

```bash
cd qiling_analysis
python3 -m venv qiling_env
source qiling_env/bin/activate
```

### 2. Install Core Dependencies

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

### 3. Install Analysis Tools

```bash
pip install 'yara-python' \
            'pycryptodome' \
            'z3-solver'
```

### 4. Install Development Tools (Optional)

```bash
pip install 'pytest' \
            'pytest-cov' \
            'black' \
            'flake8' \
            'mypy'
```

### 5. Install Qiling Framework

```bash
git clone https://github.com/qilingframework/qiling.git
pip install -e ./qiling
```

### 6. Setup Rootfs

```bash
git clone https://github.com/qilingframework/rootfs.git
```

## Verify Installation

```bash
source qiling_env/bin/activate
python3 -c "import qiling; print('Qiling installed successfully')"
ls rootfs/
```

## Usage

```bash
source qiling_env/bin/activate
python3 tests/verify_crypto.py /path/to/binary.elf
```

## Directory Structure

After installation, you should have:

```
qiling_analysis/
├── tests/
│   └── verify_crypto.py
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
