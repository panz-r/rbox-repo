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
TOOLS_DIR="$SCRIPT_DIR/../tools"
BUILD_DIR="$SCRIPT_DIR/../build_test"

echo "nfa2dfa_advanced Segfault Bug Test"
echo "=================================="

# Create pattern file
echo 'ACCEPTANCE_MAPPING [safe] -> 0
[safe] ls( (abc )?)' > "$BUILD_DIR/bug_nfa2dfa.txt"

echo "Building NFA for ls( (abc )?)..."
"$TOOLS_DIR/nfa_builder" "$BUILD_DIR/bug_nfa2dfa.txt" "$BUILD_DIR/bug_nfa2dfa.nfa" 2>&1
echo "NFA States: $(grep '^States:' '$BUILD_DIR/bug_nfa2dfa.nfa' | awk '{print $2}')"

echo "Running nfa2dfa_advanced on the NFA..."
if "$TOOLS_DIR/nfa2dfa_advanced" "$BUILD_DIR/bug_nfa2dfa.nfa" "$BUILD_DIR/bug_nfa2dfa.dfa" 2>&1; then
    echo "[PASS] nfa2dfa_advanced completed without crash"
    echo "DFA states: $(grep '^States:' '$BUILD_DIR/bug_nfa2dfa.dfa' | awk '{print $2}')"
else
    echo "[FAIL] nfa2dfa_advanced crashed or failed"
    exit 1
fi
