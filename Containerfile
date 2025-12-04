FROM ubuntu:20.04

# Set environment variables for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install system dependencies
RUN apt-get update && apt-get install -y \
    binwalk \
    python3 \
    python3-pip \
    git \
    build-essential \
    liblzma-dev \
    liblzo2-dev \
    zlib1g-dev \
    mtd-utils \
    squashfs-tools \
    wget \
    curl \
    patch \
    && rm -rf /var/lib/apt/lists/*

# Build sasquatch from source (using older Ubuntu for compatibility)
WORKDIR /opt
RUN git clone https://github.com/devttys0/sasquatch.git
WORKDIR /opt/sasquatch
RUN ./build.sh
# The binary is buried in squashfs4.3/squashfs-tools/, so we use 'find' to grab it
RUN find . -type f -name "sasquatch" -exec cp {} /usr/local/bin/ \;

# Install Python-based firmware extraction tools (only working ones)
RUN pip3 install jefferson || echo "Jefferson installation failed"

# Install UBI tools from source
WORKDIR /opt
RUN git clone https://github.com/jrspruitt/ubi_reader.git && \
    cd ubi_reader && \
    python3 setup.py install && \
    cd .. && \
    rm -rf ubi_reader || echo "ubi_reader installation failed"

# Install cramfs tools separately (build from source since package doesn't exist)
WORKDIR /opt
RUN git clone https://github.com/npitre/cramfs-tools.git && \
    cd cramfs-tools && \
    make && \
    cp cramfsck mkcramfs /usr/local/bin/ && \
    cd .. && \
    rm -rf cramfs-tools || echo "cramfs-tools installation failed"

# Create working directory
WORKDIR /work

# Set default command
CMD ["bash"]