#!/bin/bash
# test_dfa2c_array.sh - DFA to C array conversion tests
# Tests C array generation from compiled DFA

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/.."

# BUILD_DIR can be passed from Python runner, otherwise auto-detect
if [ -n "$BUILD_DIR" ]; then
    TOOLS_DIR="$BUILD_DIR/tools"
else
    TOOLS_DIR="$SRC_DIR/build/tools"
fi
CDFATOOL="$TOOLS_DIR/cdfatool"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

TESTS_RUN=0
TESTS_PASSED=0

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; }

run_test() {
    local name="$1"; shift
    TESTS_RUN=$((TESTS_RUN + 1))
    if "$@" > "$TMPDIR/${name}.log" 2>&1; then
        pass "$name"
    else
        fail "$name (exit $?, log: $TMPDIR/${name}.log)"
    fi
}

# Create a real pattern file
cat > "$TMPDIR/patterns.txt" << 'EOF'
[CATEGORIES]
0: safe
[safe] cat
EOF

echo "cdfatool embedd Tests"
echo "======================"
echo ""

# Build DFA from pattern
$CDFATOOL compile "$TMPDIR/patterns.txt" -o "$TMPDIR/test.dfa"

# --- Basic usage ---
run_test "basic_usage" bash -c "
    $CDFATOOL embedd $TMPDIR/test.dfa -o $TMPDIR/basic.c 2>/dev/null &&
    grep -q 'const uint8_t basic\[\]' $TMPDIR/basic.c &&
    grep -q 'const size_t basic_size' $TMPDIR/basic.c
"

# --- Verify generated C compiles ---
run_test "compiles_default" bash -c "
    $CDFATOOL embedd $TMPDIR/test.dfa -o $TMPDIR/comp_default.c 2>/dev/null &&
    gcc -c -o $TMPDIR/comp_default.o $TMPDIR/comp_default.c -Wall -Werror
"

# --- Test with real DFA (if available) ---
if [ -f "$SRC_DIR/build/test_accept.dfa" ]; then
    run_test "real_dfa_embedding" bash -c "
        $CDFATOOL embedd $SRC_DIR/build/test_accept.dfa -o $TMPDIR/real.c 2>/dev/null &&
        grep -q 'const uint8_t real\[\]' $TMPDIR/real.c &&
        gcc -c -o $TMPDIR/real.o $TMPDIR/real.c -Wall -Werror
    "
fi

# --- error: nonexistent input ---
run_test "error_nonexistent_input" bash -c "
    ! $CDFATOOL embedd /no/such/file.dfa -o $TMPDIR/err.c 2>/dev/null
"

echo ""
echo "Summary: $TESTS_PASSED/$TESTS_RUN tests passed"
echo "SUMMARY: $TESTS_PASSED/$TESTS_RUN passed"

if [ "$TESTS_PASSED" -eq "$TESTS_RUN" ]; then
    exit 0
else
    exit 1
fi