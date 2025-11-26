#!/bin/bash

TEMP_DIR="/tmp/firmware_tools_build"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)."
    exit 1
fi

dnf install -y epel-release 2>/dev/null
dnf install -y git make gcc gcc-c++ wget zlib-devel xz-devel lzo-devel libstdc++-devel binwalk binutils python3-pip

if [ $? -ne 0 ]; then
    echo "Dependency installation failed."
    exit 1
fi

pip3 install --upgrade binwalk

mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

if [ ! -d "sasquatch" ]; then
    git clone https://github.com/devttys0/sasquatch
fi

cd sasquatch
./build.sh

if [ $? -eq 0 ]; then
    echo "Sasquatch installed successfully."
else
    echo "Sasquatch build failed."
fi

rm -rf "$TEMP_DIR"
echo "Setup complete."
