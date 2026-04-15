#!/bin/bash
# ============================================================================
# Regression test for cdfatool compile segfault bug
# ============================================================================
# Bug: cdfatool compile crashes (segfault) when processing an optional group
# containing 3+ characters followed by a space.
#
# Minimal reproduction: ls( (abc )?)
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/.."

# BUILD_DIR can be passed from Python runner, otherwise auto-detect
if [ -n "$BUILD_DIR" ]; then
    TOOLS_DIR="$BUILD_DIR/tools"
    WORK_DIR="$BUILD_DIR"
else
    TOOLS_DIR="$SRC_DIR/build/tools"
    WORK_DIR="$SRC_DIR/build_test"
fi

echo "cdfatool compile Segfault Bug Test"
echo "==================================="

# Create pattern file
echo 'ACCEPTANCE_MAPPING [safe] -> 0
[safe] ls( (abc )?)' > "$WORK_DIR/bug_nfa2dfa.txt"

echo "Compiling pattern ls( (abc )?)..."
if "$TOOLS_DIR/cdfatool" compile "$WORK_DIR/bug_nfa2dfa.txt" -o "$WORK_DIR/bug_nfa2dfa.dfa" 2>&1; then
    echo "[PASS] cdfatool compile completed without crash"
else
    echo "[FAIL] cdfatool compile crashed or failed"
    exit 1
fi