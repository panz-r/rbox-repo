#!/bin/bash
# ============================================================================
# Regression test for bug: = followed by fragment reference in optional group
# ============================================================================
# Bug: When '=' immediately precedes a fragment reference '((FRAG))' inside
# an optional group, the parser produces a degenerate NFA (crashes or wrong DFA).
#
# This test verifies the bug is fixed by:
# 1. Compiling pattern to DFA (no crash)
# 2. Verifying the compiled DFA accepts expected inputs
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/.."

# BUILD_DIR can be passed from Python runner, otherwise auto-detect
if [ -n "$WORK_DIR" ]; then
    TOOLS_DIR="$WORK_DIR/tools"
    WORK_DIR="$WORK_DIR"
else
    TOOLS_DIR="$SRC_DIR/build/tools"
    WORK_DIR="$SRC_DIR/build_test"
fi

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

# Helper: compile pattern to DFA (returns 0 on success)
compile_pattern() {
    local patterns="$1"
    local dfa_file="$2"
    "$TOOLS_DIR/cdfatool" compile "$patterns" -o "$dfa_file" 2>/dev/null
}

# Helper: eval DFA on input and check if it matches (returns 0 on match)
eval_match() {
    local dfa_file="$1"
    local input="$2"
    local expect_match="$3"  # 0 or 1
    local result
    result=$("$TOOLS_DIR/cdfatool" eval "$dfa_file" <<< "$input" 2>/dev/null | grep -o 'matched=[01]')
    if [ "$result" = "matched=$expect_match" ]; then
        return 0
    else
        return 1
    fi
}

echo "Bug EQ Fragment Regression Tests"
echo "================================"
echo ""

# Test 1: Bug pattern - ls( =)((safe::x)) - originally crashed
# The bug was that '=' followed by fragment in optional group caused segfault
# We test that it now compiles without crashing
echo "[TEST 1] Bug pattern ls( =)((safe::x))"
cat > "$WORK_DIR/regression_bug1.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[fragment:safe::x] a|b|c
[safe] ls( =)((safe::x))
EOF
if compile_pattern "$WORK_DIR/regression_bug1.txt" "$WORK_DIR/regression_bug1.dfa"; then
    # Also verify it produces a working DFA that accepts expected inputs
    # Pattern: ls + optional(space + =) + fragment
    # So "ls=a" and "ls =a" should match
    if eval_match "$WORK_DIR/regression_bug1.dfa" "ls=a" "1" ||
       eval_match "$WORK_DIR/regression_bug1.dfa" "ls =a" "1"; then
        pass "ls( =)((safe::x)) - compiles and works - BUG FIXED!"
    else
        fail "ls( =)((safe::x)) - compiles but DFA doesn't work correctly"
    fi
else
    fail "ls( =)((safe::x)) - failed to compile - BUG STILL PRESENT"
fi

# Test 2: Bug pattern - ls(=)?((safe::x)) - variant with explicit optional marker
echo "[TEST 2] Bug pattern ls(=)?((safe::x))"
cat > "$WORK_DIR/regression_bug2.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[fragment:safe::x] a|b|c
[safe] ls(=)?((safe::x))
EOF
if compile_pattern "$WORK_DIR/regression_bug2.txt" "$WORK_DIR/regression_bug2.dfa"; then
    if eval_match "$WORK_DIR/regression_bug2.dfa" "ls=a" "1"; then
        pass "ls(=)?((safe::x)) - compiles and matches 'ls=a' - BUG FIXED!"
    else
        fail "ls(=)?((safe::x)) - compiles but DFA doesn't match"
    fi
else
    fail "ls(=)?((safe::x)) - failed to compile - BUG STILL PRESENT"
fi

# Test 3: Pattern without the problematic '= ' sequence
echo "[TEST 3] Normal pattern ls x= (equals at end)"
cat > "$WORK_DIR/regression_end.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[safe] ls x=
EOF
if compile_pattern "$WORK_DIR/regression_end.txt" "$WORK_DIR/regression_end.dfa"; then
    if eval_match "$WORK_DIR/regression_end.dfa" "ls x=" "1"; then
        pass "ls x= - compiles and matches 'ls x='"
    else
        fail "ls x= - compiles but DFA doesn't match"
    fi
else
    fail "ls x= - failed to compile"
fi

# Cleanup
rm -f "$WORK_DIR/regression_*.txt" "$WORK_DIR/regression_*.dfa"

echo ""
echo "================================"
echo "SUMMARY: $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "================================"

if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
fi
exit 0