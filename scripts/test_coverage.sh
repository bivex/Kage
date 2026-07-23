#!/usr/bin/env bash
set -e

echo "=========================================="
echo "📊 Kage Code Coverage Suite (gcov / lcov)"
echo "=========================================="

docker build -f Dockerfile.coverage -t kage-coverage .
docker run --rm kage-coverage
