#!/bin/bash
# test_dfa2c_array.sh - Tests for the dfa2c_array tool
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/.."

# BUILD_DIR can be passed from Python runner, otherwise auto-detect
if [ -n "$BUILD_DIR" ]; then
    TOOLS_DIR="$BUILD_DIR/tools"
else
    TOOLS_DIR="$SRC_DIR/build/tools"
fi
DFA2C="$TOOLS_DIR/dfa2c_array"
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

# Create a small test binary (64 bytes of known data)
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(64)))" > "$TMPDIR/test.dfa"

echo "dfa2c_array Tool Tests"
echo "======================"
echo ""

# --- Basic usage ---
run_test "basic_usage" bash -c "
    $DFA2C $TMPDIR/test.dfa $TMPDIR/basic.c test_data &&
    grep -q 'const uint8_t test_data\[64\]' $TMPDIR/basic.c &&
    grep -q 'const size_t test_data_size = 64;' $TMPDIR/basic.c
"

# --- Verify generated C compiles ---
run_test "compiles_default" bash -c "
    $DFA2C $TMPDIR/test.dfa $TMPDIR/comp_default.c test_data &&
    gcc -c -o $TMPDIR/comp_default.o $TMPDIR/comp_default.c -Wall -Werror
"

# --- --type unsigned char ---
run_test "type_unsigned_char" bash -c "
    $DFA2C --type 'unsigned char' $TMPDIR/test.dfa $TMPDIR/uc.c test_data &&
    grep -q 'unsigned char test_data\[64\]' $TMPDIR/uc.c &&
    gcc -c -o $TMPDIR/uc.o $TMPDIR/uc.c -Wall -Werror
"

# --- --type uint8_t (explicit) ---
run_test "type_uint8_t" bash -c "
    $DFA2C --type uint8_t $TMPDIR/test.dfa $TMPDIR/u8.c test_data &&
    grep -q 'uint8_t test_data\[64\]' $TMPDIR/u8.c &&
    gcc -c -o $TMPDIR/u8.o $TMPDIR/u8.c -Wall -Werror
"

# --- --no-const ---
run_test "no_const" bash -c "
    $DFA2C --no-const $TMPDIR/test.dfa $TMPDIR/nc.c test_data &&
    grep -q 'uint8_t test_data\[64\]' $TMPDIR/nc.c &&
    ! grep -q 'const' $TMPDIR/nc.c &&
    gcc -c -o $TMPDIR/nc.o $TMPDIR/nc.c -Wall -Werror
"

# --- --static ---
run_test "static_linkage" bash -c "
    $DFA2C --static $TMPDIR/test.dfa $TMPDIR/st.c test_data &&
    grep -q 'static const size_t test_data_size' $TMPDIR/st.c &&
    grep -q 'static const uint8_t test_data' $TMPDIR/st.c &&
    gcc -c -o $TMPDIR/st.o $TMPDIR/st.c -Wall -Wno-unused-const-variable
"

# --- --array-only ---
run_test "array_only" bash -c "
    $DFA2C --array-only $TMPDIR/test.dfa $TMPDIR/ao.c test_data &&
    grep -q 'uint8_t test_data\[64\]' $TMPDIR/ao.c &&
    ! grep -q 'test_data_size' $TMPDIR/ao.c &&
    gcc -c -o $TMPDIR/ao.o $TMPDIR/ao.c -Wall -Werror
"

# --- --size-only ---
run_test "size_only" bash -c "
    $DFA2C --size-only $TMPDIR/test.dfa $TMPDIR/so.c test_data &&
    grep -q 'test_data_size = 64' $TMPDIR/so.c &&
    ! grep -q 'test_data\[64\]' $TMPDIR/so.c &&
    gcc -c -o $TMPDIR/so.o $TMPDIR/so.c -Wall -Werror
"

# --- --header ---
run_test "header_generation" bash -c "
    $DFA2C --header $TMPDIR/test_data.h $TMPDIR/test.dfa $TMPDIR/hdr.c test_data &&
    grep -q '#ifndef TEST_DATA_H' $TMPDIR/test_data.h &&
    grep -q 'extern const uint8_t test_data\[\]' $TMPDIR/test_data.h &&
    grep -q 'extern const size_t test_data_size' $TMPDIR/test_data.h &&
    grep -q '#endif' $TMPDIR/test_data.h &&
    gcc -c -o $TMPDIR/hdr.o $TMPDIR/hdr.c -Wall -Werror
"

# --- --header with --guard ---
run_test "header_custom_guard" bash -c "
    $DFA2C --header $TMPDIR/guarded.h --guard MY_GUARD_H $TMPDIR/test.dfa $TMPDIR/guarded.c test_data &&
    grep -q '#ifndef MY_GUARD_H' $TMPDIR/guarded.h &&
    grep -q '#define MY_GUARD_H' $TMPDIR/guarded.h
"

# --- --header with --array-only ---
run_test "header_array_only" bash -c "
    $DFA2C --header $TMPDIR/ao_hdr.h --array-only $TMPDIR/test.dfa $TMPDIR/ao_hdr.c test_data &&
    grep -q 'extern const uint8_t test_data\[\]' $TMPDIR/ao_hdr.h &&
    ! grep -q 'test_data_size' $TMPDIR/ao_hdr.h
"

# --- --header with --size-only ---
run_test "header_size_only" bash -c "
    $DFA2C --header $TMPDIR/so_hdr.h --size-only $TMPDIR/test.dfa $TMPDIR/so_hdr.c test_data &&
    grep -q 'extern const size_t test_data_size' $TMPDIR/so_hdr.h &&
    ! grep -q 'test_data\[\]' $TMPDIR/so_hdr.h
"

# --- --include ---
run_test "extra_include" bash -c "
    $DFA2C --include 'my_types.h' $TMPDIR/test.dfa $TMPDIR/inc.c test_data &&
    grep -q '#include \"my_types.h\"' $TMPDIR/inc.c
"

# --- combined flags (matching current rbox-client usage) ---
run_test "combined_unsigned_char_no_const" bash -c "
    $DFA2C --type 'unsigned char' --no-const $TMPDIR/test.dfa $TMPDIR/combined.c test_data &&
    grep -q 'unsigned char test_data\[64\]' $TMPDIR/combined.c &&
    ! grep -q 'const unsigned char' $TMPDIR/combined.c &&
    gcc -c -o $TMPDIR/combined.o $TMPDIR/combined.c -Wall -Werror
"

# --- combined static + header ---
run_test "combined_static_header" bash -c "
    $DFA2C --static --header $TMPDIR/sh.h $TMPDIR/test.dfa $TMPDIR/sh.c test_data &&
    grep -q 'static const uint8_t test_data' $TMPDIR/sh.c &&
    grep -q 'extern const uint8_t test_data\[\]' $TMPDIR/sh.h
"

# --- error: array-only + size-only ---
run_test "error_array_and_size_only" bash -c "
    ! $DFA2C --array-only --size-only $TMPDIR/test.dfa $TMPDIR/err.c test_data 2>/dev/null
"

# --- error: missing args ---
run_test "error_missing_args" bash -c "
    ! $DFA2C $TMPDIR/test.dfa 2>/dev/null
"

# --- error: unknown flag ---
run_test "error_unknown_flag" bash -c "
    ! $DFA2C --bogus $TMPDIR/test.dfa $TMPDIR/err.c test_data 2>/dev/null
"

# --- error: nonexistent input ---
run_test "error_nonexistent_input" bash -c "
    ! $DFA2C /no/such/file.dfa $TMPDIR/err.c test_data 2>/dev/null
"

# --- --help ---
run_test "help_flag" bash -c "
    $DFA2C --help 2>/dev/null
"

echo ""
echo "======================"
echo "SUMMARY: $TESTS_PASSED/$TESTS_RUN passed"
echo "======================"

[ "$TESTS_PASSED" -eq "$TESTS_RUN" ] && exit 0 || exit 1
