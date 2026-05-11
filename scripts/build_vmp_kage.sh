#!/usr/bin/env bash
# build_vmp_kage.sh — Protect Kage Extension using VMPacker (Strategy A)

set -euo pipefail

# 1. Build Kage extension in Docker (Linux x86_64)
echo "[*] Building Kage extension ELF in Docker..."
docker build -t kage-build-temp .

# 2. Extract the built .so to host
echo "[*] Extracting kage.so..."
container_id=$(docker create kage-build-temp)
docker cp "${container_id}:/usr/local/lib/php/extensions/no-debug-non-zts-20190902/kage.so" ./kage_linux_raw.so
docker rm "${container_id}"

# 3. Use vmpacker to protect critical functions
echo "[*] Virtualizing critical functions..."
# Note: we use the Go-built packer on the host
./packer/VMPacker/build/vmpacker \
    -func "kage_raw_decrypt,kage_get_machine_id,kage_global_user_handler" \
    -v \
    -o kage_protected.so \
    kage_linux_raw.so

echo "[+] Success! Protected extension created: kage_protected.so"

# 4. Verify the protected .so in Docker
echo "[*] Verifying protected extension..."
cat > Dockerfile.verify << 'EOF'
FROM php:7.4-cli
WORKDIR /app
COPY kage_protected.so /usr/local/lib/php/extensions/no-debug-non-zts-20190902/kage.so
RUN docker-php-ext-enable kage
COPY . /app
CMD export KAGE_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef" ; \
    php -r " \
        \$key = '0123456789abcdef0123456789abcdef'; \
        \$code = '<?php echo \"[VMP] Protected function execution SUCCESS\\n\"; ?>'; \
        \$enc = kage_encrypt_c(\$code, \$key); \
        file_put_contents('test.kage', base64_decode(\$enc)); \
        include 'test.kage'; \
    "
EOF
docker build -t kage-verify-vmp -f Dockerfile.verify .
docker run --rm kage-verify-vmp
rm Dockerfile.verify
