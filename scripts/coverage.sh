#!/bin/bash
# Coverage script for shellgate
set -e

BUILD_DIR="$1"
if [ -z "$BUILD_DIR" ]; then
    BUILD_DIR="/w/rbox-repo/shellgate/build"
fi

cd "$BUILD_DIR"

# Clean previous coverage data
lcov --zerocounters --directory . 2>/dev/null || true

# Build with coverage flags
CFLAGS="-fprofile-arcs -ftest-coverage" make clean 2>/dev/null || true
CFLAGS="-fprofile-arcs -ftest-coverage" make -j4 2>/dev/null || make -j4

# Run tests
./test_shellgate

# Capture coverage
lcov --capture --directory . --output-file coverage.info --charset UTF-8

# Generate HTML
mkdir -p coverage_html
genhtml coverage.info --output-directory coverage_html --charset UTF-8

echo ""
echo "Coverage report generated in: $BUILD_DIR/coverage_html/index.html"
echo "Coverage info saved to: $BUILD_DIR/coverage.info"