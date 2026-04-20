#!/bin/bash
# test_captures.sh - Capture group tests
# Tests various capture scenarios using the dfa_eval API

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/.."

# Use temp directory for this test run - ensures parallel safety
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

BUILD="$TEST_DIR"
mkdir -p "$BUILD"

# Libraries - use absolute paths from source tree
readonlybox_lib="$SRC_DIR/build/lib/libreadonlybox_dfa.a"
readonlybox_eval_lib="$SRC_DIR/build/lib_eval/libreadonlybox_dfa_eval.a"
cadical_lib="$SRC_DIR/vendor/cadical/build/libcadical.a"
STATIC_LIBS="$readonlybox_lib $readonlybox_eval_lib $cadical_lib -lm -lstdc++"

# Tools - use absolute paths
CDFATOOL="$SRC_DIR/build/tools/cdfatool"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  <PASS>$1</PASS>"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  <FAIL>$1</FAIL>"
}

# Helper: build DFA from pattern file
build_dfa() {
    local patterns_file="$1" dfa_file="$2"
    "$CDFATOOL" compile "$patterns_file" -o "$dfa_file" 2>/dev/null || return 1
}

# Helper: test eval with DFA file
test_eval_file() {
    local dfa_file="$1" input="$2" expect_match="$3"
    cat > "$BUILD/test_cap.c" << CEEOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"
#include "dfa_internal.h"
int main(void) {
    size_t sz;
    void* d = load_dfa_from_file("$dfa_file", &sz);
    if (!d) { printf("LOAD_FAIL\\n"); return 1; }
    dfa_result_t r;
    memset(&r, 0, sizeof(r));
    dfa_eval(d, sz, "$input", strlen("$input"), &r);
    printf("%d\\n", r.matched);
    free(d);
    return 0;
}
CEEOF
    gcc -I"$SRC_DIR/include" -o "$BUILD/test_cap_bin" "$BUILD/test_cap.c" $STATIC_LIBS 2>/dev/null || return 1
    local result=$("$BUILD/test_cap_bin" 2>/dev/null)
    [ "$result" = "$expect_match" ]
}

# ========== Test 1: Basic single capture ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap1.txt" << 'EOF'
[CATEGORIES]
0: safe
[safe:capture:src] cat <path>test.txt</path>
EOF
if build_dfa "$BUILD/cap1.txt" "$BUILD/cap1.dfa" && test_eval_file "$BUILD/cap1.dfa" "cat test.txt" "1"; then
    pass "basic_single_capture"
else
    fail "basic_single_capture"
fi

# ========== Test 2: Multiple patterns with captures ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap2.txt" << 'EOF'
[CATEGORIES]
0: safe
[safe:capture:get] GET /api/<res>users</res> HTTP/1.1
[safe:capture:post] POST /api/<res>data</res> HTTP/1.1
EOF
if build_dfa "$BUILD/cap2.txt" "$BUILD/cap2.dfa" && \
   test_eval_file "$BUILD/cap2.dfa" "GET /api/users HTTP/1.1" "1" && \
   test_eval_file "$BUILD/cap2.dfa" "POST /api/data HTTP/1.1" "1" && \
   test_eval_file "$BUILD/cap2.dfa" "GET /api/other HTTP/1.1" "0"; then
    pass "multi_pattern_captures"
else
    fail "multi_pattern_captures"
fi

# ========== Test 3: Nested captures ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap3.txt" << 'EOF'
[CATEGORIES]
0: safe
[safe:capture:outer] GET /api/<outer><inner>users</inner></outer> HTTP/1.1
EOF
if build_dfa "$BUILD/cap3.txt" "$BUILD/cap3.dfa" && test_eval_file "$BUILD/cap3.dfa" "GET /api/users HTTP/1.1" "1"; then
    pass "nested_captures"
else
    fail "nested_captures"
fi

# ========== Test 4: Capture at pattern boundary ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap4.txt" << 'EOF'
[CATEGORIES]
0: safe
[safe:capture:all] <data>everything</data>
EOF
if build_dfa "$BUILD/cap4.txt" "$BUILD/cap4.dfa" && test_eval_file "$BUILD/cap4.dfa" "everything" "1"; then
    pass "capture_at_boundary"
else
    fail "capture_at_boundary"
fi

# ========== Test 5: Multiple captures in one pattern ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap5.txt" << 'EOF'
[CATEGORIES]
0: safe
[safe:capture:both] <first>hello</first> <second>world</second>
EOF
if build_dfa "$BUILD/cap5.txt" "$BUILD/cap5.dfa" && test_eval_file "$BUILD/cap5.dfa" "hello world" "1"; then
    pass "multiple_captures_single_pattern"
else
    fail "multiple_captures_single_pattern"
fi

# ========== Test 6: Capture with quantifier ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap6.txt" << 'EOF'
[CATEGORIES]
0: safe
[fragment:safe::lower] a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z
[safe:capture:word] word <w>((safe::lower))+</w> done
EOF
if build_dfa "$BUILD/cap6.txt" "$BUILD/cap6.dfa" && test_eval_file "$BUILD/cap6.dfa" "word hello done" "1"; then
    pass "capture_with_quantifier"
else
    fail "capture_with_quantifier"
fi

# ========== Test 7: Capture in alternation ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap7.txt" << 'EOF'
[CATEGORIES]
0: safe
[fragment:safe::cmd] cat|ls|grep
[safe:capture:cmd] ((safe::cmd)) <file>test.txt</file>
EOF
if build_dfa "$BUILD/cap7.txt" "$BUILD/cap7.dfa" && \
   test_eval_file "$BUILD/cap7.dfa" "cat test.txt" "1" && \
   test_eval_file "$BUILD/cap7.dfa" "ls test.txt" "1" && \
   test_eval_file "$BUILD/cap7.dfa" "dog test.txt" "0"; then
    pass "capture_in_alternation"
else
    fail "capture_in_alternation"
fi

# ========== Test 8: Capture non-matching ==========
TESTS_RUN=$((TESTS_RUN + 1))
if test_eval_file "$BUILD/cap1.dfa" "dog test.txt" "0"; then
    pass "capture_non_matching"
else
    fail "capture_non_matching"
fi

# ========== Test 9: Capture with special chars ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap9.txt" << 'EOF'
[CATEGORIES]
0: safe
[safe:capture:file] cat <name>my-file_v2.txt</name>
EOF
if build_dfa "$BUILD/cap9.txt" "$BUILD/cap9.dfa" && test_eval_file "$BUILD/cap9.dfa" "cat my-file_v2.txt" "1"; then
    pass "capture_special_chars"
else
    fail "capture_special_chars"
fi

# ========== Test 10: Capture overlap patterns ==========
TESTS_RUN=$((TESTS_RUN + 1))
cat > "$BUILD/cap10.txt" << 'EOF'
[CATEGORIES]
0: safe
[safe:capture:src] GET <url>/api/users</url> HTTP/1.1
[safe:capture:src] GET <url>/api/data</url> HTTP/1.1
EOF
if build_dfa "$BUILD/cap10.txt" "$BUILD/cap10.dfa" && \
   test_eval_file "$BUILD/cap10.dfa" "GET /api/users HTTP/1.1" "1" && \
   test_eval_file "$BUILD/cap10.dfa" "GET /api/data HTTP/1.1" "1" && \
   test_eval_file "$BUILD/cap10.dfa" "GET /api/other HTTP/1.1" "0"; then
    pass "capture_overlap_patterns"
else
    fail "capture_overlap_patterns"
fi

# Output JUnit XML format for aggregator
echo ""
echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
echo "<testsuite name=\"test_captures\" tests=\"$TESTS_RUN\" failures=\"$TESTS_FAILED\" pending=\"0\">"
echo "<testcase name=\"capture_tests\" passed=\"$TESTS_PASSED\" failed=\"$TESTS_FAILED\" tests=\"$TESTS_RUN\"/>"
echo "</testsuite>"
echo ""
echo "SUMMARY: $TESTS_PASSED/$TESTS_RUN passed"

[ "$TESTS_PASSED" -eq "$TESTS_RUN" ] && exit 0 || exit 1
