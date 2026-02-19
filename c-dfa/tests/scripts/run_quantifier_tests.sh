#!/bin/bash
# ============================================================================
# Quantifier Test Runner
# Tests quantifier patterns using their dedicated DFAs
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/test_patterns"
DFA_TEST="$SCRIPT_DIR/dfa_test"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================================"
echo "Quantifier Pattern Test Runner"
echo "================================================"
echo ""

run_test() {
    local dfa_file="$1"
    local test_input="$2"
    local should_match="$3"
    local test_name="$4"
    
    if [ ! -f "$dfa_file" ]; then
        echo -e "${RED}ERROR: DFA file not found: $dfa_file${NC}"
        return 1
    fi
    
    # Copy DFA to current directory for dfa_test
    cp "$dfa_file" ./test_runner.dfa
    
    # Run test
    local result=$("$DFA_TEST" 2>&1 | grep -A1 "$test_input" | tail -1)
    
    # Actually use dfa_eval directly
    local match_result
    match_result=$(echo "$test_input" | ./tools/dfa_eval 2>/dev/null || echo "NO MATCH")
    
    local matched=false
    if [ "$match_result" != "NO MATCH" ]; then
        matched=true
    fi
    
    if [ "$should_match" = "true" ] && [ "$matched" = "true" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $test_name"
        return 0
    elif [ "$should_match" = "false" ] && [ "$matched" = "false" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $test_name"
        return 0
    else
        echo -e "  ${RED}[FAIL]${NC} $test_name (expected match=$should_match, got match=$matched)"
        return 1
    fi
}

# Alternative: use check_dfa to test
run_check_test() {
    local dfa_file="$1"
    local test_input="$2"
    local should_match="$3"
    local test_name="$4"
    
    if [ ! -f "$dfa_file" ]; then
        echo -e "${RED}ERROR: DFA file not found: $dfa_file${NC}"
        return 1
    fi
    
    # Use check_dfa tool
    local result
    result=$(./tools/check_dfa "$dfa_file" "$test_input" 2>&1)
    
    local matched=false
    if echo "$result" | grep -q "MATCH"; then
        matched=true
    fi
    
    if [ "$should_match" = "true" ] && [ "$matched" = "true" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $test_name"
        return 0
    elif [ "$should_match" = "false" ] && [ "$matched" = "false" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $test_name"
        return 0
    else
        echo -e "  ${RED}[FAIL]${NC} $test_name (expected match=$should_match, got match=$matched)"
        echo "    Output: $result"
        return 1
    fi
}

# Test Group 1: a+
echo "================================================"
echo "Group 1: Plus Quantifier (a+)"
echo "================================================"
run_check_test "$BUILD_DIR/01_plus_literal.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/01_plus_literal.dfa" "aa" true "'aa' matches"
run_check_test "$BUILD_DIR/01_plus_literal.dfa" "aaa" true "'aaa' matches"
run_check_test "$BUILD_DIR/01_plus_literal.dfa" "" false "empty should NOT match"
run_check_test "$BUILD_DIR/01_plus_literal.dfa" "b" false "'b' should NOT match"
echo ""

# Test Group 2: a*
echo "================================================"
echo "Group 2: Star Quantifier (a*)"
echo "================================================"
run_check_test "$BUILD_DIR/02_star_literal.dfa" "" true "empty matches"
run_check_test "$BUILD_DIR/02_star_literal.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/02_star_literal.dfa" "aa" true "'aa' matches"
run_check_test "$BUILD_DIR/02_star_literal.dfa" "b" true "'b' matches (zero a's)"
echo ""

# Test Group 3: a?
echo "================================================"
echo "Group 3: Question Mark Quantifier (a?)"
echo "================================================"
run_check_test "$BUILD_DIR/03_question_literal.dfa" "" true "empty matches"
run_check_test "$BUILD_DIR/03_question_literal.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/03_question_literal.dfa" "aa" false "'aa' should NOT match"
echo ""

# Test Group 4: ((a))+
echo "================================================"
echo "Group 4: Fragment Plus Quantifier (((a))+)"
echo "================================================"
run_check_test "$BUILD_DIR/04_plus_fragment.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/04_plus_fragment.dfa" "aa" true "'aa' matches"
run_check_test "$BUILD_DIR/04_plus_fragment.dfa" "aaa" true "'aaa' matches"
run_check_test "$BUILD_DIR/04_plus_fragment.dfa" "" false "empty should NOT match"
echo ""

# Test Group 5: ((ab))+
echo "================================================"
echo "Group 5: Multi-char Fragment Plus (((ab))+)"
echo "================================================"
run_check_test "$BUILD_DIR/05_plus_multichar.dfa" "ab" true "'ab' matches"
run_check_test "$BUILD_DIR/05_plus_multichar.dfa" "abab" true "'abab' matches"
run_check_test "$BUILD_DIR/05_plus_multichar.dfa" "ababab" true "'ababab' matches"
run_check_test "$BUILD_DIR/05_plus_multichar.dfa" "a" false "'a' should NOT match"
run_check_test "$BUILD_DIR/05_plus_multichar.dfa" "aba" false "'aba' should NOT match"
echo ""

# Test Group 6: (a|b)+
echo "================================================"
echo "Group 6: Alternation Plus ((a|b)+)"
echo "================================================"
run_check_test "$BUILD_DIR/06_alternation_plus.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/06_alternation_plus.dfa" "b" true "'b' matches"
run_check_test "$BUILD_DIR/06_alternation_plus.dfa" "ab" true "'ab' matches"
run_check_test "$BUILD_DIR/06_alternation_plus.dfa" "ba" true "'ba' matches"
run_check_test "$BUILD_DIR/06_alternation_plus.dfa" "ababa" true "'ababa' matches"
run_check_test "$BUILD_DIR/06_alternation_plus.dfa" "" false "empty should NOT match"
run_check_test "$BUILD_DIR/06_alternation_plus.dfa" "c" false "'c' should NOT match"
echo ""

# Test Group 7: (a|b)*
echo "================================================"
echo "Group 7: Alternation Star ((a|b)*)"
echo "================================================"
run_check_test "$BUILD_DIR/07_alternation_star.dfa" "" true "empty matches"
run_check_test "$BUILD_DIR/07_alternation_star.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/07_alternation_star.dfa" "ab" true "'ab' matches"
run_check_test "$BUILD_DIR/07_alternation_star.dfa" "abba" true "'abba' matches"
echo ""

# Test Group 8: (a|b)?
echo "================================================"
echo "Group 8: Alternation Question ((a|b)?)"
echo "================================================"
run_check_test "$BUILD_DIR/08_alternation_question.dfa" "" true "empty matches"
run_check_test "$BUILD_DIR/08_alternation_question.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/08_alternation_question.dfa" "b" true "'b' matches"
echo ""

# Test Group 9: ((a))+
echo "================================================"
echo "Group 9: Nested Quantifier (((a))+)"
echo "================================================"
run_check_test "$BUILD_DIR/09_nested_plus.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/09_nested_plus.dfa" "aa" true "'aa' matches"
run_check_test "$BUILD_DIR/09_nested_plus.dfa" "aaa" true "'aaa' matches"
run_check_test "$BUILD_DIR/09_nested_plus.dfa" "" false "empty should NOT match"
echo ""

# Test Group 10: a+b+
echo "================================================"
echo "Group 10: Multiple Quantifiers (a+b+)"
echo "================================================"
run_check_test "$BUILD_DIR/10_multiple_quantifiers.dfa" "ab" true "'ab' matches"
run_check_test "$BUILD_DIR/10_multiple_quantifiers.dfa" "aab" true "'aab' matches"
run_check_test "$BUILD_DIR/10_multiple_quantifiers.dfa" "abb" true "'abb' matches"
run_check_test "$BUILD_DIR/10_multiple_quantifiers.dfa" "aabb" true "'aabb' matches"
run_check_test "$BUILD_DIR/10_multiple_quantifiers.dfa" "ba" false "'ba' should NOT match"
run_check_test "$BUILD_DIR/10_multiple_quantifiers.dfa" "" false "empty should NOT match"
echo ""

# Test Group 11: (a|b)*c
echo "================================================"
echo "Group 11: Combined Quantifiers ((a|b)*c)"
echo "================================================"
run_check_test "$BUILD_DIR/11_combined_quantifiers.dfa" "c" true "'c' matches"
run_check_test "$BUILD_DIR/11_combined_quantifiers.dfa" "ac" true "'ac' matches"
run_check_test "$BUILD_DIR/11_combined_quantifiers.dfa" "bc" true "'bc' matches"
run_check_test "$BUILD_DIR/11_combined_quantifiers.dfa" "abc" true "'abc' matches"
run_check_test "$BUILD_DIR/11_combined_quantifiers.dfa" "abbc" true "'abbc' matches"
echo ""

# Test Group 12: a?b?c?
echo "================================================"
echo "Group 12: All Optional Quantifiers (a?b?c?)"
echo "================================================"
run_check_test "$BUILD_DIR/12_all_optional.dfa" "" true "empty matches"
run_check_test "$BUILD_DIR/12_all_optional.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/12_all_optional.dfa" "ab" true "'ab' matches"
run_check_test "$BUILD_DIR/12_all_optional.dfa" "abc" true "'abc' matches"
run_check_test "$BUILD_DIR/12_all_optional.dfa" "b" true "'b' matches"
run_check_test "$BUILD_DIR/12_all_optional.dfa" "c" true "'c' matches"
run_check_test "$BUILD_DIR/12_all_optional.dfa" "d" false "'d' should NOT match"
echo ""

# Test Group 13: [abc]+
echo "================================================"
echo "Group 13: Character Class Plus ([abc]+)"
echo "================================================"
run_check_test "$BUILD_DIR/13_char_class_plus.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/13_char_class_plus.dfa" "b" true "'b' matches"
run_check_test "$BUILD_DIR/13_char_class_plus.dfa" "c" true "'c' matches"
run_check_test "$BUILD_DIR/13_char_class_plus.dfa" "abc" true "'abc' matches"
run_check_test "$BUILD_DIR/13_char_class_plus.dfa" "ababc" true "'ababc' matches"
run_check_test "$BUILD_DIR/13_char_class_plus.dfa" "d" false "'d' should NOT match"
run_check_test "$BUILD_DIR/13_char_class_plus.dfa" "" false "empty should NOT match"
echo ""

# Test Group 14: .*
echo "================================================"
echo "Group 14: Wildcard (.*)"
echo "================================================"
run_check_test "$BUILD_DIR/14_wildcard.dfa" "" true "empty matches"
run_check_test "$BUILD_DIR/14_wildcard.dfa" "a" true "'a' matches"
run_check_test "$BUILD_DIR/14_wildcard.dfa" "abc" true "'abc' matches"
run_check_test "$BUILD_DIR/14_wildcard.dfa" "anything" true "'anything' matches"
echo ""

# Test Group 15: [[:alpha:]]+
echo "================================================"
echo "Group 15: POSIX Alpha ([[:alpha:]]+)"
echo "================================================"
run_check_test "$BUILD_DIR/15_posix_alpha.dfa" "abc" true "'abc' matches"
run_check_test "$BUILD_DIR/15_posix_alpha.dfa" "ABCXYZ" true "'ABCXYZ' matches"
run_check_test "$BUILD_DIR/15_posix_alpha.dfa" "abc123" true "'abc123' matches"
run_check_test "$BUILD_DIR/15_posix_alpha.dfa" "123" false "'123' should NOT match"
echo ""

echo "================================================"
echo "Test run complete!"
echo "================================================"
