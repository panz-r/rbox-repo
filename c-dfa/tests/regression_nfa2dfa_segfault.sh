#!/bin/bash
# regression_nfa2dfa_segfault.sh - NFA to DFA segfault regression
# Tests various pattern constructs for proper lifecycle handling

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/.."

# Use temp directory for this test run - ensures parallel safety
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

BUILD="$TEST_DIR"
mkdir -p "$BUILD"

# Tools - use absolute paths
CDFATOOL="$SRC_DIR/build/tools/cdfatool"

echo "cdfatool compile Segfault Bug Test"
echo "==================================="

# Create pattern file
echo 'ACCEPTANCE_MAPPING [safe] -> 0
[safe] ls( (abc )?)' > "$BUILD/bug_nfa2dfa.txt"

echo "Compiling pattern ls( (abc )?)..."
if "$CDFATOOL" compile "$BUILD/bug_nfa2dfa.txt" -o "$BUILD/bug_nfa2dfa.dfa" 2>&1; then
    echo "[PASS] cdfatool compile completed without crash"
    echo ""
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    echo "<testsuite name=\"regression_nfa2dfa_segfault\" tests=\"1\" failures=\"0\" pending=\"0\">"
    echo "<testcase name=\"nfa2dfa_segfault\" passed=\"1\" failed=\"0\" tests=\"1\"/>"
    echo "</testsuite>"
    echo ""
    echo "SUMMARY: 1/1 passed"
    exit 0
else
    echo "[FAIL] cdfatool compile crashed or failed"
    echo ""
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    echo "<testsuite name=\"regression_nfa2dfa_segfault\" tests=\"1\" failures=\"1\" pending=\"0\">"
    echo "<testcase name=\"nfa2dfa_segfault\" passed=\"0\" failed=\"1\" tests=\"1\"/>"
    echo "</testsuite>"
    echo ""
    echo "SUMMARY: 0/1 passed"
    exit 1
fi
