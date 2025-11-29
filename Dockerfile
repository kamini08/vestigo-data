# Use Ubuntu 20.04 (GCC 9) to avoid GCC 15 compilation errors
FROM docker.io/library/ubuntu:20.04

# Avoid timezone prompts
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    liblzma-dev \
    liblzo2-dev \
    zlib1g-dev \
    git \
    wget \
    patch \
    && rm -rf /var/lib/apt/lists/*

# 2. Clone Sasquatch
WORKDIR /opt
RUN git clone https://github.com/devttys0/sasquatch.git

# 3. Build Sasquatch
WORKDIR /opt/sasquatch
RUN ./build.sh

# 4. Find the binary and install it (FIXED STEP)
# The binary is buried in squashfs4.3/squashfs-tools/, so we use 'find' to grab it
RUN find . -type f -name "sasquatch" -exec cp {} /usr/local/bin/ \;

# 5. Set up working directory
WORKDIR /work

# 6. Entrypoint
ENTRYPOINT ["sasquatch"]
