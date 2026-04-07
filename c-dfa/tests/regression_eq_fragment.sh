#!/bin/bash
# ============================================================================
# Regression test for bug: = followed by fragment reference in optional group
# ============================================================================
# Bug: When '=' immediately precedes a fragment reference '((FRAG))' inside
# an optional group, the parser produces a degenerate NFA with only 1 state.
#
# This test verifies the bug is fixed by checking NFA state counts.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/../tools"
BUILD_DIR="$SCRIPT_DIR/../build_test"

TESTS_PASSED=0
TESTS_FAILED=0

pass() { 
    echo "  [PASS] $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() { 
    echo "  [FAIL] $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Helper: build NFA and return state count
get_nfa_states() {
    local patterns="$1"
    local nfa_file="$2"
    "$TOOLS_DIR/nfa_builder" "$patterns" "$nfa_file" 2>/dev/null || return 1
    grep "^States:" "$nfa_file" | awk '{print $2}'
}

# Helper: build DFA and return state count  
get_dfa_states() {
    local nfa_file="$1"
    local dfa_file="$2"
    "$TOOLS_DIR/nfa2dfa_advanced" "$nfa_file" "$dfa_file" 2>/dev/null || return 1
    grep "^States:" "$dfa_file" | awk '{print $2}'
}

echo "Bug EQ Fragment Regression Tests"
echo "================================"
echo ""

# Test 1: Working pattern - ls(z)((safe::x)) should have > 1 states
echo "[TEST 1] Working pattern ls(z)((safe::x))"
cat > "$BUILD_DIR/regression_work.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[fragment:safe::x] a|b|c
[safe] ls(z)((safe::x))
EOF
states=$(get_nfa_states "$BUILD_DIR/regression_work.txt" "$BUILD_DIR/regression_work.nfa")
if [ "$states" -gt 1 ]; then
    pass "ls(z)((safe::x)) has $states states (expected > 1)"
else
    fail "ls(z)((safe::x)) has $states states (expected > 1)"
fi

# Test 2: Bug pattern - ls( =)((safe::x)) should have > 1 states (BUG: currently 1)
echo "[TEST 2] Bug pattern ls( =)((safe::x))"
cat > "$BUILD_DIR/regression_bug1.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[fragment:safe::x] a|b|c
[safe] ls( =)((safe::x))
EOF
states=$(get_nfa_states "$BUILD_DIR/regression_bug1.txt" "$BUILD_DIR/regression_bug1.nfa")
if [ "$states" -gt 1 ]; then
    pass "ls( =)((safe::x)) has $states states (expected > 1) - BUG FIXED!"
else
    fail "ls( =)((safe::x)) has $states states (expected > 1) - BUG STILL PRESENT"
fi

# Test 3: Bug pattern - ls(=)?((safe::x)) should have > 1 states (BUG: currently 1)
echo "[TEST 3] Bug pattern ls(=)?((safe::x))"
cat > "$BUILD_DIR/regression_bug2.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[fragment:safe::x] a|b|c
[safe] ls(=)?((safe::x))
EOF
states=$(get_nfa_states "$BUILD_DIR/regression_bug2.txt" "$BUILD_DIR/regression_bug2.nfa")
if [ "$states" -gt 1 ]; then
    pass "ls(=)?((safe::x)) has $states states (expected > 1) - BUG FIXED!"
else
    fail "ls(=)?((safe::x)) has $states states (expected > 1) - BUG STILL PRESENT"
fi

# Test 4: Character 'a' before fragment works - control
echo "[TEST 4] Control pattern ls(a)((safe::x))"
cat > "$BUILD_DIR/regression_ctrl.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[fragment:safe::x] a|b|c
[safe] ls(a)((safe::x))
EOF
states=$(get_nfa_states "$BUILD_DIR/regression_ctrl.txt" "$BUILD_DIR/regression_ctrl.nfa")
if [ "$states" -gt 1 ]; then
    pass "ls(a)((safe::x)) has $states states (expected > 1)"
else
    fail "ls(a)((safe::x)) has $states states (expected > 1)"
fi

# Test 5: ls x= (equals at end) should work
echo "[TEST 5] Pattern ls x= (equals at end)"
cat > "$BUILD_DIR/regression_end.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[safe] ls x=
EOF
states=$(get_nfa_states "$BUILD_DIR/regression_end.txt" "$BUILD_DIR/regression_end.nfa")
if [ "$states" -gt 1 ]; then
    pass "ls x= has $states states (expected > 1)"
else
    fail "ls x= has $states states (expected > 1)"
fi

# Cleanup
rm -f "$BUILD_DIR/regression_*.txt" "$BUILD_DIR/regression_*.nfa" "$BUILD_DIR/regression_*.dfa"

echo ""
echo "================================"
echo "SUMMARY: $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "================================"

if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
