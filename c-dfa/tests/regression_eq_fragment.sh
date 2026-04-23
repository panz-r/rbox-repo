#!/bin/bash
# regression_eq_fragment.sh - Bug #6 regression test
# Tests = followed by fragment reference in optional group

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/.."

# Use temp directory for this test run - ensures parallel safety
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

BUILD="$TEST_DIR"
mkdir -p "$BUILD"

# Tools - use absolute paths
CDFATOOL="$SRC_DIR/build/tools/cdfatool"

TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    echo "  <PASS>$1</PASS>"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo "  <FAIL>$1</FAIL>"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Helper: compile pattern to DFA (returns 0 on success)
compile_pattern() {
    local patterns="$1"
    local dfa_file="$2"
    "$CDFATOOL" compile "$patterns" -o "$dfa_file" 2>/dev/null
}

# Helper: eval DFA on input and check if it matches (returns 0 on match)
eval_match() {
    local dfa_file="$1"
    local input="$2"
    local expect_match="$3"
    local result
    result=$("$CDFATOOL" eval "$dfa_file" <<< "$input" 2>/dev/null | grep -o 'matched=[01]')
    if [ "$result" = "matched=$expect_match" ]; then
        return 0
    else
        return 1
    fi
}

# Test 1: Bug pattern - ls( =)[[safe::x]] - originally crashed
echo "[TEST 1] Bug pattern ls( =)[[safe::x]]"
cat > "$BUILD/regression_bug1.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[fragment:safe::x] a|b|c
[safe] ls( =)[[safe::x]]
EOF
if compile_pattern "$BUILD/regression_bug1.txt" "$BUILD/regression_bug1.dfa"; then
    if eval_match "$BUILD/regression_bug1.dfa" "ls=a" "1" ||
       eval_match "$BUILD/regression_bug1.dfa" "ls =a" "1"; then
        pass "ls( =)[[safe::x]] - compiles and works - BUG FIXED!"
    else
        fail "ls( =)[[safe::x]] - compiles but DFA doesn't work correctly"
    fi
else
    fail "ls( =)[[safe::x]] - failed to compile - BUG STILL PRESENT"
fi

# Test 2: Bug pattern - ls(=)?[[safe::x]] - variant with explicit optional marker
echo "[TEST 2] Bug pattern ls(=)?[[safe::x]]"
cat > "$BUILD/regression_bug2.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[fragment:safe::x] a|b|c
[safe] ls(=)?[[safe::x]]
EOF
if compile_pattern "$BUILD/regression_bug2.txt" "$BUILD/regression_bug2.dfa"; then
    if eval_match "$BUILD/regression_bug2.dfa" "ls=a" "1"; then
        pass "ls(=)?[[safe::x]] - compiles and matches 'ls=a' - BUG FIXED!"
    else
        fail "ls(=)?[[safe::x]] - compiles but DFA doesn't match"
    fi
else
    fail "ls(=)?[[safe::x]] - failed to compile - BUG STILL PRESENT"
fi

# Test 3: Pattern without the problematic '= ' sequence
echo "[TEST 3] Normal pattern ls x= (equals at end)"
cat > "$BUILD/regression_end.txt" << 'EOF'
ACCEPTANCE_MAPPING [safe] -> 0
[safe] ls x=
EOF
if compile_pattern "$BUILD/regression_end.txt" "$BUILD/regression_end.dfa"; then
    if eval_match "$BUILD/regression_end.dfa" "ls x=" "1"; then
        pass "ls x= - compiles and matches 'ls x='"
    else
        fail "ls x= - compiles but DFA doesn't match"
    fi
else
    fail "ls x= - failed to compile"
fi

# Output JUnit XML format for aggregator
TESTS_RUN=$((TESTS_PASSED + TESTS_FAILED))
echo ""
echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
echo "<testsuite name=\"regression_eq_fragment\" tests=\"$TESTS_RUN\" failures=\"$TESTS_FAILED\" pending=\"0\">"
echo "<testcase name=\"eq_fragment_regression\" passed=\"$TESTS_PASSED\" failed=\"$TESTS_FAILED\" tests=\"$TESTS_RUN\"/>"
echo "</testsuite>"
echo ""
echo "SUMMARY: $TESTS_PASSED passed, $TESTS_FAILED failed"

[ "$TESTS_FAILED" -gt 0 ] && exit 1 || exit 0
