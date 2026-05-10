# Use official PHP 7.4 CLI image as base
FROM php:7.4-cli

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libsodium-dev \
    pkg-config \
    file \
    libssl-dev \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire project to /app
COPY . /app

# Build the C extension
WORKDIR /app/c_extension
RUN rm -rf build && mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

# Install and enable the extension
RUN cp build/kage.so $(php-config --extension-dir)/kage.so && \
    docker-php-ext-enable kage

# Set working directory back to root
WORKDIR /app

# Default command: run all relevant tests to verify protection
CMD echo "--- 🛠️  Building Kage... ---" ; \
    echo "--- 🧪 Running Extension Base Tests ---" ; \
    php c_extension/test_extension.php ; \
    echo "" ; \
    echo "--- 🔐 Running Bytecode Encryption Tests ---" ; \
    php tests/test_bytecode_encryption.php ; \
    echo "" ; \
    echo "--- 🔄 Running Integration Tests ---" ; \
    php tests/test_integration.php
