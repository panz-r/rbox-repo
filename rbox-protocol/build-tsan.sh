#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build-tsan"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "=== Building rbox-protocol with ThreadSanitizer ==="
cmake -DENABLE_TSAN=ON "$SCRIPT_DIR"
make -j$(nproc)

echo ""
echo "=== TSAN build complete ==="
echo "Run tests with: cd $BUILD_DIR && ctest"
echo "Or manually: TSAN_OPTIONS='history_size=7:halt_on_error=1' ./test_*"
