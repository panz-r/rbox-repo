#!/bin/bash
# ============================================================================
# Regression test for nfa2dfa_advanced segfault bug
# ============================================================================
# Bug: nfa2dfa_advanced crashes (segfault) when processing an optional group
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

echo "nfa2dfa_advanced Segfault Bug Test"
echo "=================================="

# Create pattern file
echo 'ACCEPTANCE_MAPPING [safe] -> 0
[safe] ls( (abc )?)' > "$WORK_DIR/bug_nfa2dfa.txt"

echo "Building NFA for ls( (abc )?)..."
"$TOOLS_DIR/nfa_builder" "$WORK_DIR/bug_nfa2dfa.txt" "$WORK_DIR/bug_nfa2dfa.nfa" 2>&1
echo "NFA States: $(grep '^States:' '$WORK_DIR/bug_nfa2dfa.nfa' | awk '{print $2}')"

echo "Running nfa2dfa_advanced on the NFA..."
if "$TOOLS_DIR/nfa2dfa_advanced" "$WORK_DIR/bug_nfa2dfa.nfa" "$WORK_DIR/bug_nfa2dfa.dfa" 2>&1; then
    echo "[PASS] nfa2dfa_advanced completed without crash"
    echo "DFA states: $(grep '^States:' '$WORK_DIR/bug_nfa2dfa.dfa' | awk '{print $2}')"
else
    echo "[FAIL] nfa2dfa_advanced crashed or failed"
    exit 1
fi
