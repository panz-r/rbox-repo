#!/bin/bash
#
# run-tests.sh - Run all tests from a build directory
#
# Usage: ./run-tests.sh <build_dir>
#

set -e

BUILD_DIR="${1:-.}"
cd "$BUILD_DIR"

# Set library path to use local library
export LD_LIBRARY_PATH="$BUILD_DIR:$LD_LIBRARY_PATH"

# TSAN options (if running under TSAN)
if [[ "$LD_LIBRARY_PATH" == *"build-tsan"* ]] || [ -n "$TSAN_OPTIONS" ]; then
    export TSAN_OPTIONS="${TSAN_OPTIONS:-history_size=7:halt_on_error=1:verbosity=1}"
    echo "TSAN options: $TSAN_OPTIONS"
fi

# ASAN options (if running under ASAN)
if [[ "$LD_LIBRARY_PATH" == *"build-asan"* ]] || [ -n "$ASAN_OPTIONS" ]; then
    export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1}"
    echo "ASAN options: $ASAN_OPTIONS"
fi

# List of tests to run
TESTS=(
    "./test_protocol"
    "./test_protocol_encoding"
    "./test_protocol_decoding"
    "./test_log"
    "./test_timer_heap"
    "./test_protocol_full"
    "./test_integration"
    "./test_blocking_server"
    "./test_persistent"
    "./test_env_decisions"
    "./test_stress"
    "./test_cache"
    "./test_versioning"
)

FAILED=0
PASSED=0

echo ""
echo "=== Running all tests ==="
echo "Build directory: $BUILD_DIR"
echo "Library path: $LD_LIBRARY_PATH"
echo ""

for test in "${TESTS[@]}"; do
    if [ -x "$test" ]; then
        echo "--- Running $test ---"
        if timeout 60 "$test" > "${test##*/}.log" 2>&1; then
            echo "PASS: $test"
            ((PASSED++))
        else
            ec=$?
            echo "FAIL: $test (exit code: $ec)"
            echo "=== Log tail ==="
            tail -20 "${test##*/}.log"
            ((FAILED++))
        fi
    else
        echo "SKIP: $test (not found or not executable)"
    fi
done

echo ""
echo "=== Results ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
