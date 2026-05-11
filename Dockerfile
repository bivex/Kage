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
CMD export KAGE_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef" ; \
    echo "--- 🛡️ Kage Security Verification Suite ---" ; \
    echo "" ; \
    echo "--- Phase 1 & 2: Hooking & Loading ---" ; \
    php tests/test_phase2_hook.php ; \
    echo "" ; \
    echo "--- Phase 3: Bytecode Obfuscation (CFF & Literals) ---" ; \
    php -r " \
        \$key = '0123456789abcdef0123456789abcdef'; \
        \$code = '<?php echo \"SUCCESS: Obfuscated output correct\\n\"; for(\$i=0;\$i<2;\$i++) echo \"Loop \$i\\n\"; ?>'; \
        \$enc = kage_encrypt_c(\$code, \$key); \
        file_put_contents('docker_test.kage', 'KAGE' . base64_decode(\$enc)); \
        include 'docker_test.kage'; \
        unlink('docker_test.kage'); \
    " ; \
    echo "" ; \
    echo "--- Phase 4: Machine Binding (HWID Lock) ---" ; \
    php -r " \
        \$key = '0123456789abcdef0123456789abcdef'; \
        \$my_id = kage_get_machine_id(); \
        echo 'Current HWID: ' . \$my_id . PHP_EOL; \
        \$code = '<?php echo \"Authorized Execution\\n\"; ?>'; \
        \$enc = kage_encrypt_c(\$code, \$key, 'wrong-id-123'); \
        file_put_contents('locked.kage', 'KAGE' . base64_decode(\$enc)); \
        echo 'Attempting to run locked file...' . PHP_EOL; \
        try { include 'locked.kage'; } catch (Throwable \$e) { echo 'Caught: ' . \$e->getMessage() . PHP_EOL; } \
        unlink('locked.kage'); \
    " 2>&1 | grep -v "PHP Warning" ; \
    echo "" ; \
    echo "--- 🏁 Verification Complete ---"
