#!/usr/bin/env bash
set -e

VERSIONS=("8.1" "8.2" "8.3" "8.4")

echo "=========================================="
echo "🛡️  Kage Multi-PHP Version Verification Suite"
echo "=========================================="

for ver in "${VERSIONS[@]}"; do
    echo ""
    echo "------------------------------------------"
    echo "🐳 Building & Testing PHP ${ver}..."
    echo "------------------------------------------"
    docker build -f "Dockerfile.php${ver//./}" -t "kage-test-php${ver//./}" .
    docker run --rm "kage-test-php${ver//./}"
    echo "✅ PHP ${ver} Verification Passed!"
done

echo ""
echo "🎉 ALL TARGET PHP VERSIONS (8.1 - 8.4) PASSED FULL VERIFICATION!"
