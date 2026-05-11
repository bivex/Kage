#!/usr/bin/env bash
# =============================================================
# build-arm64.sh — Build & test Kage ARM64 with VMPacker
# =============================================================
# Usage:
#   ./build-arm64.sh              # Full build
#   ./build-arm64.sh --export     # Build + extract kage.so
#   ./build-arm64.sh --test       # Build + run verification
#   ./build-arm64.sh --clean      # Remove all images
# =============================================================
set -euo pipefail

IMAGE="kage-arm64:protected"
EXPORT_IMAGE="kage-arm64:export"
PLATFORM="linux/arm64"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; exit 1; }

# Detect platform
ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    info "Native ARM64 detected — using docker build"
    BUILD_CMD="docker build"
else
    info "x86_64 detected — using docker buildx for ARM64 emulation"
    BUILD_CMD="docker buildx build --platform $PLATFORM"
fi

case "${1:-build}" in
    --clean)
        info "Removing images..."
        docker rmi "$IMAGE" "$EXPORT_IMAGE" 2>/dev/null || true
        info "Done."
        exit 0
        ;;
    --export)
        info "Building exporter target..."
        $BUILD_CMD --platform $PLATFORM \
            -f Dockerfile.arm64 \
            --target exporter \
            -t "$EXPORT_IMAGE" \
            .
        info "Extracting protected kage.so..."
        CONTAINER=$(docker create --platform $PLATFORM "$EXPORT_IMAGE")
        docker cp "$CONTAINER:/output" ./output-arm64
        docker rm "$CONTAINER" > /dev/null
        info "Artifacts saved to ./output-arm64/"
        ls -la ./output-arm64/
        exit 0
        ;;
    --test)
        info "Building runtime image..."
        $BUILD_CMD --platform $PLATFORM \
            -f Dockerfile.arm64 \
            --target runtime \
            -t "$IMAGE" \
            .
        info "Running verification..."
        docker run --rm --platform $PLATFORM "$IMAGE"
        exit 0
        ;;
    build|"")
        info "Full build: VMPacker → Kage → Protect → Runtime"
        $BUILD_CMD --platform $PLATFORM \
            -f Dockerfile.arm64 \
            -t "$IMAGE" \
            .
        info "Build complete: $IMAGE"
        info "Run tests:    ./build-arm64.sh --test"
        info "Extract .so:  ./build-arm64.sh --export"
        exit 0
        ;;
    *)
        echo "Usage: $0 [--export|--test|--clean]"
        exit 1
        ;;
esac
