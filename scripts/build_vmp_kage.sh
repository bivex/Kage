#!/usr/bin/env bash
# build_vmp_kage.sh — Legacy wrapper redirecting to ASGARD-5877 protection workflow

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[!] Note: VMPacker has been upgraded to ASGARD-5877."
echo "[*] Invoking scripts/build_asgard_kage.sh..."
exec "${SCRIPT_DIR}/build_asgard_kage.sh" "$@"

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
