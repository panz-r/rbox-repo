#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build-asan"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "=== Building rbox-protocol with AddressSanitizer ==="
cmake -DENABLE_ASAN=ON "$SCRIPT_DIR"
make -j$(nproc)

echo ""
echo "=== ASAN build complete ==="
echo "Run tests with: cd $BUILD_DIR && ctest"
