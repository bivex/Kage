#!/usr/bin/env bash
# build_asgard_kage.sh — Complete ASGARD-5877 Virtualization Pipeline for Kage ARM64

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ASGARD_BIN="${ROOT_DIR}/packer/asgard/_build/default/bin/main.exe"
ASGARD_CONFIG="${ROOT_DIR}/c_extension/asgard_config.json"
OUT_DIR="/tmp/asgard_kage_build"
EXPORT_DIR="${ROOT_DIR}/output-arm64"

echo "========================================================="
echo "   KAGE + ASGARD-5877 AOT VIRTUALIZATION PIPELINE        "
echo "========================================================="

# 1. Build ASGARD toolchain if not already built
if [[ ! -f "${ASGARD_BIN}" ]]; then
    echo "[*] Building ASGARD toolchain via dune..."
    (cd "${ROOT_DIR}/packer/asgard" && eval "$(/opt/homebrew/bin/opam env 2>/dev/null || opam env 2>/dev/null || true)" && dune build bin/main.exe)
fi

echo "[+] ASGARD toolchain ready: ${ASGARD_BIN}"

# 2. Virtualize C crypto sources into ASGARD Polymorphic Bytecode & VM Runtime
echo "[*] Virtualizing cryptographic routines via ASGARD protect-arm64..."
PHP_INC=$(php-config --includes 2>/dev/null | sed 's/-I//g' | tr ' ' ':' || echo "")
LIBSODIUM_INC=$(brew --prefix libsodium 2>/dev/null || echo "/opt/homebrew/opt/libsodium")/include
export CPATH="${PHP_INC}:${LIBSODIUM_INC}:${ROOT_DIR}/c_extension:${ROOT_DIR}/c_extension/src/core:${ROOT_DIR}/c_extension/src/crypto:${ROOT_DIR}/c_extension/src/vm"

rm -rf "${OUT_DIR}"
"${ASGARD_BIN}" protect-arm64 \
    -i "${ROOT_DIR}/c_extension/src/crypto/crypto.c" \
    -o "${OUT_DIR}" \
    -c "${ASGARD_CONFIG}" \
    --compile=false

# 3. Synchronize generated VM runtime and virtualized sources into c_extension
echo "[*] Synchronizing ASGARD VM runtime headers and bytecode into c_extension..."
cp "${OUT_DIR}/app_virtualized.cpp" "${ROOT_DIR}/c_extension/src/crypto/crypto_virtualized.cpp"
cp "${OUT_DIR}/threaded_vm.hpp" "${ROOT_DIR}/c_extension/src/crypto/threaded_vm.hpp"
cp "${OUT_DIR}"/asg_tech_*.hpp "${ROOT_DIR}/c_extension/src/crypto/"

# 4. Build hardened Linux ARM64 Docker image
echo "[*] Compiling protected kage.so in Linux ARM64 container..."
docker build -f "${ROOT_DIR}/Dockerfile.arm64" -t kage-arm64:protected "${ROOT_DIR}"

# 5. Export protected artifact
echo "[*] Exporting protected kage.so artifact..."
mkdir -p "${EXPORT_DIR}"
docker run --rm --entrypoint cat kage-arm64:protected /usr/local/lib/php/extensions/no-debug-non-zts-20190902/kage.so > "${EXPORT_DIR}/kage.so"
chmod 755 "${EXPORT_DIR}/kage.so"
echo "[+] Exported protected binary: ${EXPORT_DIR}/kage.so ($(ls -lh "${EXPORT_DIR}/kage.so" | awk '{print $5}'))"

# 6. Verify with end-to-end demo execution
echo "[*] Running end-to-end verification in Docker..."
docker run --rm -v "${ROOT_DIR}/examples:/examples" kage-arm64:protected php /examples/demo_asgard_kage.php

echo "========================================================="
echo "   ASGARD PROTECTION PIPELINE COMPLETED SUCCESSFULLY!    "
echo "========================================================="
