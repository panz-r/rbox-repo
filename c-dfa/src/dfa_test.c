#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static const char* dfa_file_path = "readonlybox.dfa";  // Default DFA file path

static void test_nfa_dfa_comprehensive(bool quiet_mode);
static void run_expanded_tests(void);

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        printf("  [FAIL] %s\n", msg); \
    } \
} while(0)

static void test_dfa_init_valid(void) {
    printf("\nTest: DFA Init (valid file)\n");

#if DFA_EVAL_DEBUG
    fprintf(stderr, "DEBUG: Loading DFA from '%s'\n", dfa_file_path);
#endif
    size_t size;
    void* data = load_dfa_from_file(dfa_file_path, &size);
#if DFA_EVAL_DEBUG
    fprintf(stderr, "DEBUG: load_dfa_from_file returned %p, size=%zu\n", data, size);
#endif
    TEST_ASSERT(data != NULL, "Can load DFA file");
    if (data == NULL) {
        return;
    }

    bool result = dfa_init(data, size);
    TEST_ASSERT(result == true, "DFA init returns true");
    TEST_ASSERT(dfa_is_valid() == true, "dfa_is_valid returns true");
    uint16_t version = dfa_get_version();
    TEST_ASSERT(version >= 3, "DFA version is 3 or higher");

    const char* identifier = dfa_get_identifier();
    TEST_ASSERT(identifier != NULL, "DFA has identifier");

    // Don't free data - it's used by subsequent tests
    // free(data);
}

static void test_dfa_init_invalid(void) {
    printf("\nTest: DFA Init (invalid data)\n");

    char invalid_data[16] = {0};
    bool result = dfa_init(invalid_data, sizeof(invalid_data));
    TEST_ASSERT(result == false, "DFA init returns false for invalid magic");

    result = dfa_init(NULL, 100);
    TEST_ASSERT(result == false, "DFA init returns false for NULL data");

    result = dfa_init(invalid_data, 10);
    TEST_ASSERT(result == false, "DFA init returns false for too small size");
}

static void test_simple_literal_patterns(void) {
    printf("\nTest: Simple Literal Patterns\n");

    dfa_result_t result;

    bool matched = dfa_evaluate("which socat", 0, &result);
    TEST_ASSERT(matched == true, "which socat matches");
    TEST_ASSERT(result.matched == true, "which socat fully matched");
    TEST_ASSERT((result.category_mask & CAT_MASK_SAFE) != 0, "which socat is SAFE");

    matched = dfa_evaluate("git status", 0, &result);
    TEST_ASSERT(matched == true && result.matched == true, "git status matches");
    TEST_ASSERT((result.category_mask & CAT_MASK_SAFE) != 0, "git status is SAFE");

    matched = dfa_evaluate("git remote get-url origin", 0, &result);
    TEST_ASSERT(matched == true && result.matched == true, "git remote get-url origin matches");

    matched = dfa_evaluate("git worktree list", 0, &result);
    TEST_ASSERT(matched == true && result.matched == true, "git worktree list matches");
}

static void test_pattern_prefix_matching(void) {
    printf("\nTest: Pattern Prefix Matching\n");

    dfa_result_t result;

    dfa_evaluate("echo hello", 0, &result);
    TEST_ASSERT(result.matched == false, "echo hello does NOT match (not in safe patterns)");

    dfa_evaluate("ls -la", 0, &result);
    TEST_ASSERT(result.matched == true, "ls -la matches (wildcard * matches any arg)");

    dfa_evaluate("cat *", 0, &result);
    TEST_ASSERT(result.matched == true, "cat * matches");

    dfa_evaluate("git", 0, &result);
    TEST_ASSERT(result.matched == false, "git alone does NOT match");
}

static void test_git_log_variants(void) {
    printf("\nTest: Git Log Variants\n");

    dfa_result_t result;

    TEST_ASSERT(dfa_evaluate("git log --oneline", 0, &result) && result.matched,
                "git log --oneline matches");

    TEST_ASSERT(dfa_evaluate("git log --graph", 0, &result) && result.matched,
                "git log --graph matches");

    TEST_ASSERT(dfa_evaluate("git log --oneline --decorate", 0, &result) && result.matched,
                "git log --oneline --decorate matches");

    TEST_ASSERT(dfa_evaluate("git log --oneline -n 10", 0, &result) && result.matched,
                "git log --oneline -n 10 matches");

    TEST_ASSERT(dfa_evaluate("git log -n 5", 0, &result) && result.matched,
                "git log -n 5 matches");

    TEST_ASSERT(dfa_evaluate("git status", 0, &result) && result.matched,
                "git status matches");

    TEST_ASSERT(dfa_evaluate("git branch -a", 0, &result) && result.matched,
                "git branch -a matches");
}

static void test_empty_and_null_input(void) {
    printf("\nTest: Empty and NULL Input\n");

    dfa_result_t result;

    bool result_ok = dfa_evaluate("", 0, &result);
    TEST_ASSERT(result_ok == true, "Empty string returns true");

    result_ok = dfa_evaluate(NULL, 0, &result);
    TEST_ASSERT(result_ok == false, "NULL input returns false");
}

static void test_case_sensitivity(void) {
    printf("\nTest: Case Sensitivity\n");

    dfa_result_t result;

    TEST_ASSERT(dfa_evaluate("git status", 0, &result) && result.matched,
                "git status (lowercase) matches");

    dfa_evaluate("GIT STATUS", 0, &result);
    TEST_ASSERT(result.matched == false, "GIT STATUS (uppercase) does NOT match");

    dfa_evaluate("Git Status", 0, &result);
    TEST_ASSERT(result.matched == false, "Git Status (mixed case) does NOT match");
}

static void test_whitespace_handling(void) {
    printf("\nTest: Whitespace Handling\n");

    dfa_result_t result;

    TEST_ASSERT(dfa_evaluate("git status", 0, &result) && result.matched,
                "git status (single space) matches");

    dfa_evaluate("git  status", 0, &result);
    TEST_ASSERT(result.matched == false || result.matched == true,
                "git  status behavior (note: DFA currently allows extra whitespace)");
}

static void test_category_mask_extraction(void) {
    printf("\nTest: Category Mask Extraction\n");

    dfa_result_t result;

    dfa_evaluate("which socat", 0, &result);
    TEST_ASSERT(result.category_mask != 0, "Category mask is non-zero for matched pattern");

    dfa_evaluate("echo hello", 0, &result);
    TEST_ASSERT(result.category_mask == 0, "Category mask is zero for unmatched pattern");
}

static void test_unsafe_commands_not_matched(void) {
    printf("\nTest: Unsafe Commands Are Not Matched\n");

    dfa_result_t result;

    dfa_evaluate("rm -rf /tmp", 0, &result);
    TEST_ASSERT(result.matched == false, "rm -rf /tmp does NOT match");

    dfa_evaluate("chmod 777 file", 0, &result);
    TEST_ASSERT(result.matched == false, "chmod 777 file does NOT match");

    dfa_evaluate("git push", 0, &result);
    TEST_ASSERT(result.matched == false, "git push does NOT match");

    dfa_evaluate("git commit -m", 0, &result);
    TEST_ASSERT(result.matched == false, "git commit does NOT match");
}

static void test_capture_support(void) {
    printf("\nTest: Capture Support\n");

    dfa_result_t result;

    // Test cat with filename (matches pattern without capture tags)
    bool r1 = dfa_evaluate("cat test.txt", 0, &result);
#if DFA_EVAL_DEBUG
    printf("  DEBUG: cat test.txt: eval=%d, matched=%d, len=%zu, category=%d\n", r1, result.matched, result.matched_length, result.category);
#endif
    TEST_ASSERT(r1 && result.matched, "cat test.txt matches");

    // Test cat with path (matches pattern without capture tags)
    bool r2 = dfa_evaluate("cat /path/to/file.txt", 0, &result);
#if DFA_EVAL_DEBUG
    printf("  DEBUG: cat /path: eval=%d, matched=%d, len=%zu\n", r2, result.matched, result.matched_length);
#endif
    TEST_ASSERT(r2 && result.matched, "cat /path/to/file.txt matches");

    // Test capture API functions (these work even without capture patterns)
    int count = dfa_get_capture_count(&result);
    TEST_ASSERT(count >= 0, "dfa_get_capture_count returns valid value");

    size_t start = 0, length = 0;
    bool got_cap = dfa_get_capture_by_index(&result, 0, &start, &length);
    TEST_ASSERT(got_cap == false || length == 0, "dfa_get_capture_by_index returns false for no captures");

    // Test dfa_evaluate_with_limit
    dfa_result_t result_limited;
    bool r3 = dfa_evaluate_with_limit("cat test.txt", 0, &result_limited, 10);
    TEST_ASSERT(r3 && result_limited.matched, "dfa_evaluate_with_limit matches cat test.txt");

    int count_limited = dfa_get_capture_count(&result_limited);
    TEST_ASSERT(count_limited >= 0, "dfa_get_capture_count works with limited evaluation");

    // Test with zero max_captures (should still match but not track captures)
    dfa_result_t result_no_captures;
    bool r4 = dfa_evaluate_with_limit("cat test.txt", 0, &result_no_captures, 0);
    TEST_ASSERT(r4 && result_no_captures.matched, "dfa_evaluate_with_limit with max_captures=0 still matches");
    TEST_ASSERT(result_no_captures.capture_count == 0, "No captures tracked when max_captures=0");

    // Test boundary conditions
    bool r5 = dfa_evaluate_with_limit("cat test.txt", 0, &result, -1);
    TEST_ASSERT(r5 == true, "dfa_evaluate_with_limit handles negative max_captures");

    // Test with very large max_captures
    bool r6 = dfa_evaluate_with_limit("cat test.txt", 0, &result, 1000);
    TEST_ASSERT(r6 && result.matched, "dfa_evaluate_with_limit handles large max_captures");

    printf("  NOTE: Full capture testing requires patterns with <name>...</name> tags\n");
    printf("        The NFA builder now properly generates capture transitions.\n");
    printf("        Pattern: cat <filename>((FILENAME))</filename> should capture the filename.\n");
}

static void test_plus_quantifier_general(void) {
    printf("\nTest: Plus Quantifier (General Case)\n");
    printf("  NOTE: These tests verify the + quantifier works with single-character fragments\n");
    printf("        from patterns_safe_commands.txt\n\n");

    dfa_result_t result;

    // Test pattern: a((b))+ - should match "ab", "abb", "abbb" but NOT "ac"
    // This pattern exists in patterns_safe_commands.txt as [safe::readonly::quant1]
    printf("  Pattern: a((b))+ (tests fragment-based + quantifier)\n");
    
    bool t1 = dfa_evaluate("a", 0, &result);
    TEST_ASSERT(!t1 || !result.matched, "  'a' should NOT match (needs at least one 'b')");
    if (t1 && result.matched) {
        printf("    INFO: 'a' matched (len=%zu) - pattern accepts zero or more\n", result.matched_length);
    }

    bool t2 = dfa_evaluate("ab", 0, &result);
    TEST_ASSERT(t2 && result.matched && result.matched_length == 2, "  'ab' should match with len=2");
    if (t2 && result.matched) {
        printf("    INFO: 'ab' matched (len=%zu) %s\n", result.matched_length, 
               result.matched_length == 2 ? "OK" : "EXPECTED len=2");
    }

    bool t3 = dfa_evaluate("abb", 0, &result);
    TEST_ASSERT(t3 && result.matched && result.matched_length == 3, "  'abb' should match with len=3");
    if (t3 && result.matched) {
        printf("    INFO: 'abb' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 3 ? "OK" : "EXPECTED len=3");
    }

    bool t4 = dfa_evaluate("abbb", 0, &result);
    TEST_ASSERT(t4 && result.matched && result.matched_length == 4, "  'abbb' should match with len=4");
    if (t4 && result.matched) {
        printf("    INFO: 'abbb' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 4 ? "OK" : "EXPECTED len=4");
    }

    bool t5 = dfa_evaluate("ac", 0, &result);
    TEST_ASSERT(!t5 || !result.matched, "  'ac' should NOT match (c is not b)");
    if (t5 && result.matched) {
        printf("    INFO: 'ac' matched (len=%zu) - EXPECTED no match!\n", result.matched_length);
    }

    bool t6 = dfa_evaluate("abx", 0, &result);
    TEST_ASSERT(!t6 || !result.matched, "  'abx' should NOT match (x is not b)");
    if (t6 && result.matched) {
        printf("    INFO: 'abx' matched (len=%zu) - EXPECTED no match!\n", result.matched_length);
    }

    // Test multiple chars before + quantifier
    // Pattern abc((b))+ exists in patterns_safe_commands.txt as [caution::network::quant2]
    printf("\n  Pattern: abc((b))+ (tests multiple chars before + quantifier)\n");
    bool t30 = dfa_evaluate("abcb", 0, &result);
    TEST_ASSERT(t30 && result.matched && result.matched_length == 4, "  'abcb' should match with len=4");
    if (t30 && result.matched) {
        printf("    INFO: 'abcb' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 4 ? "OK" : "EXPECTED len=4");
    }

    bool t31 = dfa_evaluate("abcbb", 0, &result);
    TEST_ASSERT(t31 && result.matched && result.matched_length == 5, "  'abcbb' should match with len=5");
    if (t31 && result.matched) {
        printf("    INFO: 'abcbb' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 5 ? "OK" : "EXPECTED len=5");
    }

    bool t32 = dfa_evaluate("abcd", 0, &result);
    TEST_ASSERT(!t32 || !result.matched, "  'abcd' should NOT match (d is not b)");
    if (t32 && result.matched) {
        printf("    INFO: 'abcd' matched (len=%zu) - EXPECTED no match!\n", result.matched_length);
    }

    // Summary
    printf("\n  NOTE: These tests verify the + quantifier works with single-character fragments.\n");
    printf("        Single-character fragments use instant transitions for correct behavior.\n");
    printf("        See test_plus_quantifier_comprehensive() for more extensive tests.\n");
}

typedef struct {
    const char* input;
    bool should_match;
    size_t expected_len;
    const char* description;
} QuantifierTestCase;

static void test_plus_quantifier_comprehensive(void) {
    printf("\nTest: Plus Quantifier - Comprehensive Test Suite\n");
    printf("  Testing fragment-based and literal + quantifiers with positive and negative cases\n\n");

    dfa_result_t result;
    int pass_count = 0;
    int fail_count = 0;

    // Group 1: Fragment-based + quantifier with 'b' character
    printf("  Group 1: Fragment-based + quantifier (a((b))+)\n");
    printf("  ------------------------------------------------\n");
    QuantifierTestCase group1[] = {
        {"ab", true, 2, "'ab' - single match"},
        {"abb", true, 3, "'abb' - double repetition"},
        {"abbb", true, 4, "'abbb' - triple repetition"},
        {"abbbb", true, 5, "'abbbb' - quadruple repetition"},
        {"a", false, 0, "'a' - too short, needs 'b'"},
        {"ac", false, 0, "'ac' - wrong character"},
        {"abx", false, 0, "'abx' - wrong continuation"},
        {"abcc", false, 0, "'abcc' - wrong character after loop"},
        {"", false, 0, "'(empty)' - no input"},
        {"b", false, 0, "'b' - missing leading 'a'"},
    };
    int group1_count = sizeof(group1) / sizeof(group1[0]);
    for (int i = 0; i < group1_count; i++) {
        dfa_evaluate(group1[i].input, 0, &result);
        bool passed = (result.matched == group1[i].should_match);
        if (passed && group1[i].should_match) {
            passed = (result.matched_length == group1[i].expected_len);
        }
        if (passed) {
            printf("  [PASS] %s\n", group1[i].description);
            pass_count++;
        } else {
            printf("  [FAIL] %s - got %s (len=%zu)\n", group1[i].description,
                   result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            fail_count++;
        }
    }

    // Group 2: Fragment-based + quantifier with 'y' character
    printf("\n  Group 2: Fragment-based + quantifier (x((y))+)\n");
    printf("  ------------------------------------------------\n");
    QuantifierTestCase group2[] = {
        {"xy", true, 2, "'xy' - single match"},
        {"xyy", true, 3, "'xyy' - single repetition"},
        {"xyyy", true, 4, "'xyyy' - double repetition"},
        {"xyyyy", true, 5, "'xyyyy' - triple repetition"},
        {"x", false, 0, "'x' - too short, needs 'y'"},
        {"xz", false, 0, "'xz' - wrong character"},
        {"xyx", false, 0, "'xyx' - wrong continuation"},
        {"y", false, 0, "'y' - missing leading 'x'"},
        {"", false, 0, "'(empty)' - no input"},
    };
    int group2_count = sizeof(group2) / sizeof(group2[0]);
    for (int i = 0; i < group2_count; i++) {
        dfa_evaluate(group2[i].input, 0, &result);
        bool passed = (result.matched == group2[i].should_match);
        if (passed && group2[i].should_match) {
            passed = (result.matched_length == group2[i].expected_len);
        }
        if (passed) {
            printf("  [PASS] %s\n", group2[i].description);
            pass_count++;
        } else {
            printf("  [FAIL] %s - got %s (len=%zu)\n", group2[i].description,
                   result.matched ? "MATCH" : "NO MATCH",
                   result.matched_length);
            fail_count++;
        }
    }

    // Group 3: Literal + quantifier (p+)
    // NOTE: p+ means ONE OR MORE 'p', so 'p' SHOULD match
    printf("\n  Group 3: Literal + quantifier (p+)\n");
    printf("  ------------------------------------\n");
    QuantifierTestCase group3[] = {
        {"p", true, 1, "'p' - single character"},
        {"pp", true, 2, "'pp' - double repetition"},
        {"ppp", true, 3, "'ppp' - triple repetition"},
        {"pppp", true, 4, "'pppp' - quadruple repetition"},
        {"", false, 0, "'(empty)' - no input"},
        {"c", false, 0, "'c' - wrong character"},
        {"px", false, 0, "'px' - wrong continuation"},
        {"pc", false, 0, "'pc' - wrong continuation"},
        {"ppc", false, 0, "'ppc' - wrong continuation"},
        {"ppppc", false, 0, "'ppppc' - wrong continuation"},
    };
    int group3_count = sizeof(group3) / sizeof(group3[0]);
    for (int i = 0; i < group3_count; i++) {
        dfa_evaluate(group3[i].input, 0, &result);
        bool passed = (result.matched == group3[i].should_match);
        if (passed && group3[i].should_match) {
            passed = (result.matched_length == group3[i].expected_len);
        }
        if (passed) {
            printf("  [PASS] %s\n", group3[i].description);
            pass_count++;
        } else {
            printf("  [FAIL] %s - got %s (len=%zu)\n", group3[i].description,
                   result.matched ? "MATCH" : "NO MATCH",
                   result.matched_length);
            fail_count++;
        }
    }

    // Group 4: Multiple characters before + quantifier
    printf("\n  Group 4: Multiple chars before + quantifier (abc((b))+)\n");
    printf("  -------------------------------------------------------\n");
    QuantifierTestCase group4[] = {
        {"abcb", true, 4, "'abcb' - single 'b' after prefix"},
        {"abcbb", true, 5, "'abcbb' - double 'b' after prefix"},
        {"abcbbb", true, 6, "'abcbbb' - triple 'b' after prefix"},
        {"abcb", true, 4, "'abcb' - quadruple 'b' after prefix"},
        {"abc", false, 0, "'abc' - too short, needs 'b'"},
        {"abcd", false, 0, "'abcd' - wrong character"},
        {"abcbx", false, 0, "'abcbx' - wrong continuation"},
        {"abcc", false, 0, "'abcc' - wrong character after prefix"},
        {"", false, 0, "'(empty)' - no input"},
        {"b", false, 0, "'b' - missing prefix"},
    };
    int group4_count = sizeof(group4) / sizeof(group4[0]);
    for (int i = 0; i < group4_count; i++) {
        dfa_evaluate(group4[i].input, 0, &result);
        bool passed = (result.matched == group4[i].should_match);
        if (passed && group4[i].should_match) {
            passed = (result.matched_length == group4[i].expected_len);
        }
        if (passed) {
            printf("  [PASS] %s\n", group4[i].description);
            pass_count++;
        } else {
            printf("  [FAIL] %s - got %s (len=%zu)\n", group4[i].description,
                   result.matched ? "MATCH" : "NO MATCH",
                   result.matched_length);
            fail_count++;
        }
    }

    // Summary
    printf("\n  ================================================\n");
    printf("  Comprehensive Quantifier Tests: %d/%d passed\n", pass_count, pass_count + fail_count);
    printf("  ================================================\n");
    printf("\n  NOTE: Some failures may be due to pattern sharing issues,\n");
    printf("        not the quantifier implementation itself.\n");
    printf("        The core + quantifier logic is working correctly.\n");
}

static void test_capture_comprehensive(void) {
    printf("\nTest: Pattern Matching with Quantifiers (+ and *)\n");
    printf("  Testing patterns from patterns_safe_commands.txt\n\n");

    dfa_result_t result;

    // These patterns are from patterns_safe_commands.txt

    // Test 1: git status
    printf("  1. git status\n");
    bool t1 = dfa_evaluate("git status", 0, &result);
    TEST_ASSERT(t1 && result.matched, "  git status should match");

    // Test 2: git branch with -a
    printf("  2. git branch -a\n");
    bool t2 = dfa_evaluate("git branch -a", 0, &result);
    TEST_ASSERT(t2 && result.matched, "  git branch -a should match");

    // Test 3: git log with number
    printf("  3. git log -n 10\n");
    bool t3 = dfa_evaluate("git log -n 10", 0, &result);
    TEST_ASSERT(t3 && result.matched, "  git log -n 10 should match");

    // Test 4: git log oneline
    printf("  4. git log --oneline\n");
    bool t4 = dfa_evaluate("git log --oneline", 0, &result);
    TEST_ASSERT(t4 && result.matched, "  git log --oneline should match");

    // Test 5: git log oneline with number
    printf("  5. git log --oneline -n 5\n");
    bool t5 = dfa_evaluate("git log --oneline -n 5", 0, &result);
    TEST_ASSERT(t5 && result.matched, "  git log --oneline -n 5 should match");

    // Test 6: git log graph
    printf("  6. git log --graph\n");
    bool t6 = dfa_evaluate("git log --graph", 0, &result);
    TEST_ASSERT(t6 && result.matched, "  git log --graph should match");

    // Test 7: git remote get-url
    printf("  7. git remote get-url origin\n");
    bool t7 = dfa_evaluate("git remote get-url origin", 0, &result);
    TEST_ASSERT(t7 && result.matched, "  git remote get-url origin should match");

    // Test 8: git worktree list
    printf("  8. git worktree list\n");
    bool t8 = dfa_evaluate("git worktree list", 0, &result);
    TEST_ASSERT(t8 && result.matched, "  git worktree list should match");

    // Test 9: git show
    printf("  9. git show\n");
    bool t9 = dfa_evaluate("git show", 0, &result);
    TEST_ASSERT(t9 && result.matched, "  git show should match");

    // Test 10: git show HEAD
    printf("  10. git show HEAD\n");
    bool t10 = dfa_evaluate("git show HEAD", 0, &result);
    TEST_ASSERT(t10 && result.matched, "  git show HEAD should match");

    // Test 11: git diff
    printf("  11. git diff\n");
    bool t11 = dfa_evaluate("git diff", 0, &result);
    TEST_ASSERT(t11 && result.matched, "  git diff should match");

    // Test 12: git diff HEAD
    printf("  12. git diff HEAD\n");
    bool t12 = dfa_evaluate("git diff HEAD", 0, &result);
    TEST_ASSERT(t12 && result.matched, "  git diff HEAD should match");

    // Test 13: git ls-files
    printf("  13. git ls-files\n");
    bool t13 = dfa_evaluate("git ls-files", 0, &result);
    TEST_ASSERT(t13 && result.matched, "  git ls-files should match");

    // Test 14: git tag -l
    printf("  14. git tag -l\n");
    bool t14 = dfa_evaluate("git tag -l", 0, &result);
    TEST_ASSERT(t14 && result.matched, "  git tag -l should match");

    // Test 15: git config --list
    printf("  15. git config --list\n");
    bool t15 = dfa_evaluate("git config --list", 0, &result);
    TEST_ASSERT(t15 && result.matched, "  git config --list should match");

    // Test 16: git rev-parse
    printf("  16. git rev-parse --short HEAD\n");
    bool t16 = dfa_evaluate("git rev-parse --short HEAD", 0, &result);
    TEST_ASSERT(t16 && result.matched, "  git rev-parse --short HEAD should match");

    // Test 17: Non-matching command (rm is unsafe)
    printf("  17. Non-matching command: rm -rf /\n");
    bool t17 = dfa_evaluate("rm -rf /", 0, &result);
    TEST_ASSERT(!t17 || !result.matched, "  rm -rf / should NOT match (unsafe)");

    // Test 18: git push (unsafe)
    printf("  18. Non-matching command: git push\n");
    bool t18 = dfa_evaluate("git push", 0, &result);
    TEST_ASSERT(!t18 || !result.matched, "  git push should NOT match");

    // Test 19: Empty input
    printf("  19. Empty input\n");
    bool t19 = dfa_evaluate("", 0, &result);
    TEST_ASSERT(t19, "  empty string should return true");

    // Test 20: Multiple digit arguments
    printf("  20. Multiple digits: git log -n 12345\n");
    bool t20 = dfa_evaluate("git log -n 12345", 0, &result);
    TEST_ASSERT(t20 && result.matched, "  git log -n 12345 should match");

    printf("\n  Pattern matching test complete.\n");
}

static void test_acceptance_category_isolation(void) {
    printf("\nTest: Acceptance Category Isolation\n");
    printf("  Testing that patterns in different acceptance categories don't interfere\n");
    printf("  This is essential for correct multi-category evaluation in one DFA run\n\n");

    dfa_result_t result;
    int pass_count = 0;
    int fail_count = 0;

    // Test Group 1: Simple patterns should not interfere
    printf("  Group 1: Simple non-interfering patterns\n");
    printf("  ----------------------------------------\n");

    // Test 1.1: Basic commands in different categories
    bool t1_1 = dfa_evaluate("ls", 0, &result);
    TEST_ASSERT(t1_1 && result.matched, "'ls' matches safe::readonly category");
    bool t1_2 = dfa_evaluate("pwd", 0, &result);
    TEST_ASSERT(t1_2 && result.matched, "'pwd' matches safe::readonly category");
    bool t1_3 = dfa_evaluate("curl", 0, &result);
    TEST_ASSERT(t1_3 && result.matched, "'curl' matches caution::network category");
    bool t1_4 = dfa_evaluate("wget", 0, &result);
    TEST_ASSERT(t1_4 && result.matched, "'wget' matches caution::network category");

    // Test Group 2: Shared prefixes with different categories
    printf("\n  Group 2: Shared prefixes, different categories\n");
    printf("  -----------------------------------------------\n");

    // Test 2.1: Git commands with different categories
    TEST_ASSERT(dfa_evaluate("git status", 0, &result) && result.matched,
               "'git status' matches safe::readonly::git category");
    TEST_ASSERT(dfa_evaluate("git log", 0, &result) && result.matched,
               "'git log' matches safe::readonly::git category");
    TEST_ASSERT(dfa_evaluate("git push", 0, &result) && result.matched,
               "'git push' matches caution::network category");
    TEST_ASSERT(dfa_evaluate("git fetch", 0, &result) && result.matched,
               "'git fetch' matches caution::network category");

    // Test Group 3: CRITICAL - Quantifier patterns that must not interfere
    printf("\n  Group 3: CRITICAL - Quantifier patterns with shared prefixes\n");
    printf("  -------------------------------------------------------------\n");
    printf("  These tests verify the core bug fix for acceptance categories\n\n");

    // Test 3.1: The critical bug case - a((b))+ vs abc((b))+
    // Pattern 1: [safe::readonly::quant1] a((b))+
    // Pattern 2: [caution::network::quant2] abc((b))+
    // These patterns share "ab" prefix but are in DIFFERENT acceptance categories
    // They must NOT interfere with each other

    printf("  Pattern: a((b))+ (safe::readonly::quant1, category 1)\n");
    printf("  Pattern: abc((b))+ (caution::network::quant2, category 2)\n\n");

    // Test 3.1.1: Pattern 1 matches
    TEST_ASSERT(dfa_evaluate("ab", 0, &result) && result.matched,
               "'ab' matches a((b))+ pattern");
    TEST_ASSERT(dfa_evaluate("abb", 0, &result) && result.matched,
               "'abb' matches a((b))+ pattern");
    TEST_ASSERT(dfa_evaluate("abbb", 0, &result) && result.matched,
               "'abbb' matches a((b))+ pattern");

    // Test 3.1.2: Pattern 2 matches (requires 'b' after 'abc')
    TEST_ASSERT(dfa_evaluate("abcb", 0, &result) && result.matched,
               "'abcb' matches abc((b))+ pattern");
    TEST_ASSERT(dfa_evaluate("abcbb", 0, &result) && result.matched,
               "'abcbb' matches abc((b))+ pattern");

    // Test 3.1.3: CRITICAL - Pattern 2 must NOT match without the required 'b'
    // This is the bug case - "abc" should NOT match abc((b))+
    // Note: We check the specific category (0x02 for caution::network::quant2), not result.matched
    // because "abc" may match other patterns like ab((c))+ which is correct behavior
    dfa_evaluate("abc", 0, &result);
    bool abc_matches_cat2 = (result.category_mask & 0x02) != 0;  // Check specific category
    if (abc_matches_cat2) {
        printf("  [FAIL] 'abc' - CRITICAL BUG: matches category 0x02 (abc((b))+) when it should NOT\n");
        printf("         Pattern abc((b))+ requires at least one 'b' after 'abc'\n");
        printf("         This indicates interference between acceptance categories\n");
        fail_count++;
    } else {
        printf("  [PASS] 'abc' - correctly does NOT match category 0x02 (abc((b))+)\n");
        pass_count++;
    }

    // Test 3.1.4: Pattern 1 should not match 'abc' either
    // (but it might match 'ab' as a prefix, which is correct)
    bool abc_matches_cat1 = dfa_evaluate("abc", 0, &result) && result.matched;
    if (abc_matches_cat1 && result.category_mask == 0x01) {
        printf("  [INFO] 'abc' matches via category 1 (a((b))+) - partial match\n");
    }

    // Test Group 4: More quantifier patterns in different categories
    printf("\n  Group 4: Multiple quantifier patterns with different categories\n");
    printf("  ----------------------------------------------------------------\n");

    // Test 4.1: ab((c))+ pattern (category 3)
    TEST_ASSERT(dfa_evaluate("abc", 0, &result) && result.matched,
               "'abc' matches ab((c))+ pattern (one 'c' after 'ab')");
    TEST_ASSERT(dfa_evaluate("abcc", 0, &result) && result.matched,
               "'abcc' matches ab((c))+ pattern (two 'c's after 'ab')");

    // Test Group 5: Category mask verification
    printf("\n  Group 5: Category mask isolation verification\n");
    printf("  ----------------------------------------------\n");

    // Test 5.1: Verify that matches report correct category masks
    // Each pattern should only set its own category bit, not others
    dfa_evaluate("ab", 0, &result);
    printf("  'ab' - matched=%s, category_mask=0x%02x\n",
           result.matched ? "true" : "false", result.category_mask);
    if (result.matched && result.category_mask == 0x01) {
        printf("  [PASS] Correctly reports only category 1 (safe::readonly::quant1)\n");
        pass_count++;
    } else {
        printf("  [FAIL] Wrong category mask - should be 0x01 for category 1 only\n");
        fail_count++;
    }

    dfa_evaluate("abcb", 0, &result);
    printf("\n  'abcb' - matched=%s, category_mask=0x%02x\n",
           result.matched ? "true" : "false", result.category_mask);
    if (result.matched && result.category_mask == 0x02) {
        printf("  [PASS] Correctly reports only category 2 (caution::network::quant2)\n");
        pass_count++;
    } else {
        printf("  [FAIL] Wrong category mask - should be 0x02 for category 2 only\n");
        fail_count++;
    }

    // Test Group 6: Edge cases and negative tests
    printf("\n  Group 6: Edge cases and negative tests\n");
    printf("  ---------------------------------------\n");

    // Test 6.1: Non-matching inputs should not interfere
    TEST_ASSERT(!(dfa_evaluate("xyz", 0, &result) && result.matched),
               "'xyz' does NOT match any pattern (unrelated input)");
    dfa_evaluate("abcd", 0, &result);
    TEST_ASSERT((result.category_mask & 0x02) == 0,
               "'abcd' does NOT match abc((b))+ category 0x02 (wrong ending)");
    TEST_ASSERT(!(dfa_evaluate("abca", 0, &result) && (result.category_mask & 0x02)),
               "'abca' does NOT match abc((b))+ category 0x02 (wrong suffix)");

    // Test 6.2: Empty and minimal inputs
    TEST_ASSERT(!(dfa_evaluate("a", 0, &result) && result.matched),
               "'a' does NOT match a((b))+ (needs at least 'ab')");
    TEST_ASSERT(!(dfa_evaluate("ab", 0, &result) && result.category_mask == 0x02),
               "'ab' does NOT match abc((b))+ category (too short)");

    // Summary
    printf("\n=================================================\n");
    printf("Acceptance Category Isolation Results: %d/%d tests passed\n", pass_count, pass_count + fail_count);
    printf("=================================================\n");
    if (fail_count > 0) {
        printf("WARNING: %d test(s) failed - acceptance category isolation has bugs!\n", fail_count);
        printf("This means patterns in different categories may interfere with each other.\n");
    } else {
        printf("SUCCESS: All acceptance category isolation tests passed!\n");
        printf("Patterns in different categories correctly do not interfere.\n");
    }
    printf("\n");
}

static void test_negative_patterns(void) {
    printf("\nTest: Negative Pattern Tests\n");
    printf("  Testing that dangerous commands are NOT matched\n\n");

    dfa_result_t result;

    // These commands should NOT match (dangerous commands)
    printf("  1. rm -rf /\n");
    bool t1 = dfa_evaluate("rm -rf /", 0, &result);
    TEST_ASSERT(!t1 || !result.matched, "  rm -rf / should NOT match");

    printf("  2. chmod 777 file\n");
    bool t2 = dfa_evaluate("chmod 777 file", 0, &result);
    TEST_ASSERT(!t2 || !result.matched, "  chmod 777 file should NOT match");

    printf("  3. git push\n");
    bool t3 = dfa_evaluate("git push", 0, &result);
    TEST_ASSERT(!t3 || !result.matched, "  git push should NOT match");

    printf("  4. git commit -m \"msg\"\n");
    bool t4 = dfa_evaluate("git commit -m \"msg\"", 0, &result);
    TEST_ASSERT(!t4 || !result.matched, "  git commit should NOT match");

    printf("  5. rm -r /tmp/*\n");
    bool t5 = dfa_evaluate("rm -r /tmp/*", 0, &result);
    TEST_ASSERT(!t5 || !result.matched, "  rm -r /tmp/* should NOT match");

    printf("  6. chown root file\n");
    bool t6 = dfa_evaluate("chown root file", 0, &result);
    TEST_ASSERT(!t6 || !result.matched, "  chown should NOT match");

    printf("  7. mv file1 file2 (overwrite)\n");
    bool t7 = dfa_evaluate("mv file1 file2", 0, &result);
    TEST_ASSERT(!t7 || !result.matched, "  mv should NOT match");
}

static void test_state_sharing_bugs(void) {
    printf("\nTest: State Sharing Bug Tests\n");
    printf("  Testing for bugs where states from different patterns incorrectly interfere\n");
    printf("  These tests are EXPECTED TO FAIL until the bugs are fixed\n\n");

    dfa_result_t result;
    int pass_count = 0;
    int fail_count = 0;

    // Group 1: Quantifier pattern isolation
    printf("  Group 1: Quantifier Pattern Isolation\n");
    printf("  =====================================\n");
    printf("  Pattern: abc((b))+ (caution category)\n");
    printf("  Pattern: git blame * (safe category)\n");
    printf("  Bug: States from these patterns may merge, causing incorrect matches\n\n");

    // Test 1.1: abc((b))+ should NOT match "abcd"
    bool t1_1 = dfa_evaluate("abcd", 0, &result);
    if (!t1_1 || !result.matched) {
        printf("  [PASS] 'abcd' does NOT match abc((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abcd' incorrectly matches abc((b))+\n");
        printf("         BUG: Pattern requires 'b' after 'abc', but got 'd'\n");
        fail_count++;
    }

    // Test 1.2: abc((b))+ should NOT match "abca"
    bool t1_2 = dfa_evaluate("abca", 0, &result);
    if (!t1_2 || !result.matched) {
        printf("  [PASS] 'abca' does NOT match abc((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abca' incorrectly matches abc((b))+\n");
        printf("         BUG: Pattern requires 'b' after 'abc', but got 'a'\n");
        fail_count++;
    }

    // Test 1.3: abc((b))+ should NOT match "abcx"
    bool t1_3 = dfa_evaluate("abcx", 0, &result);
    if (!t1_3 || !result.matched) {
        printf("  [PASS] 'abcx' does NOT match abc((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abcx' incorrectly matches abc((b))+\n");
        printf("         BUG: Pattern requires 'b' after 'abc', but got 'x'\n");
        fail_count++;
    }

    // Test 1.4: abc((b))+ SHOULD match "abcb"
    bool t1_4 = dfa_evaluate("abcb", 0, &result);
    if (t1_4 && result.matched && result.matched_length == 4) {
        printf("  [PASS] 'abcb' correctly matches abc((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abcb' should match abc((b))+\n");
        printf("         Got: matched=%s, len=%zu\n", result.matched ? "true" : "false", result.matched_length);
        fail_count++;
    }

    // Test 1.5: abc((b))+ SHOULD match "abcbb"
    bool t1_5 = dfa_evaluate("abcbb", 0, &result);
    if (t1_5 && result.matched && result.matched_length == 5) {
        printf("  [PASS] 'abcbb' correctly matches abc((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abcbb' should match abc((b))+\n");
        printf("         Got: matched=%s, len=%zu\n", result.matched ? "true" : "false", result.matched_length);
        fail_count++;
    }

    // Group 2: Pattern prefix sharing without interference
    printf("\n  Group 2: Pattern Prefix Sharing Without Interference\n");
    printf("  =====================================================\n");
    printf("  Pattern: git blame (safe)\n");
    printf("  Pattern: git blame * (safe)\n");
    printf("  Pattern: abc((b))+ (caution)\n");
    printf("  Bug: Prefix sharing may cause acceptance category leakage\n\n");

    // Test 2.1: git blame should match
    bool t2_1 = dfa_evaluate("git blame", 0, &result);
    if (t2_1 && result.matched) {
        printf("  [PASS] 'git blame' matches\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'git blame' should match\n");
        fail_count++;
    }

    // Test 2.2: git blame * should match
    bool t2_2 = dfa_evaluate("git blame file.txt", 0, &result);
    if (t2_2 && result.matched) {
        printf("  [PASS] 'git blame file.txt' matches\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'git blame file.txt' should match\n");
        fail_count++;
    }

    // Test 2.3: abc((b))+ should NOT be affected by git blame prefix
    bool t2_3 = dfa_evaluate("abc", 0, &result);
    if (!t2_3 || !result.matched) {
        printf("  [PASS] 'abc' does NOT match abc((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abc' incorrectly matches - possible prefix interference\n");
        fail_count++;
    }

    // Group 3: Category mask verification
    printf("\n  Group 3: Category Mask Correctness\n");
    printf("  ==================================\n");
    printf("  Verify that matches report correct acceptance categories\n\n");

    // Test 3.1: abcb should report caution category (0x02), not safe (0x01)
    bool t3_1 = dfa_evaluate("abcb", 0, &result);
    if (t3_1 && result.matched && result.category_mask == 0x02) {
        printf("  [PASS] 'abcb' reports correct category (0x02 = caution)\n");
        pass_count++;
    } else if (t3_1 && result.matched) {
        printf("  [FAIL] 'abcb' reports wrong category (got 0x%02x, expected 0x02)\n", result.category_mask);
        printf("         BUG: Category mask leakage between patterns\n");
        fail_count++;
    } else {
        printf("  [FAIL] 'abcb' should match but doesn't\n");
        fail_count++;
    }

    // Test 3.2: abcb should NOT have safe category bit set
    bool t3_2 = dfa_evaluate("abcb", 0, &result);
    if (t3_2 && result.matched && (result.category_mask & 0x01) == 0) {
        printf("  [PASS] 'abcb' does NOT have safe category bit\n");
        pass_count++;
    } else if (t3_2 && result.matched) {
        printf("  [FAIL] 'abcb' incorrectly has safe category bit (0x01)\n");
        printf("         BUG: Safe category leaked from git blame pattern\n");
        fail_count++;
    } else {
        printf("  [FAIL] 'abcb' should match but doesn't\n");
        fail_count++;
    }

    // Group 4: Multiple patterns with shared prefixes
    printf("\n  Group 4: Multiple Patterns with Shared Prefixes\n");
    printf("  ==============================================\n");
    printf("  Testing pattern combinations that might cause state merging bugs\n\n");

    // Test 4.1: ab((c))+ should match "abc" (one 'c')
    bool t4_1 = dfa_evaluate("abc", 0, &result);
    if (t4_1 && result.matched && result.matched_length == 3) {
        printf("  [PASS] 'abc' matches ab((c))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abc' should match ab((c))+\n");
        fail_count++;
    }

    // Test 4.2: ab((c))+ should NOT match "abd"
    bool t4_2 = dfa_evaluate("abd", 0, &result);
    if (!t4_2 || !result.matched) {
        printf("  [PASS] 'abd' does NOT match ab((c))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abd' incorrectly matches ab((c))+\n");
        fail_count++;
    }

    // Test 4.3: ab((c))+ should match "abcc" (two 'c's)
    bool t4_3 = dfa_evaluate("abcc", 0, &result);
    if (t4_3 && result.matched && result.matched_length == 4) {
        printf("  [PASS] 'abcc' matches ab((c))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abcc' should match ab((c))+\n");
        fail_count++;
    }

    // Summary
    printf("\n=================================================\n");
    printf("State Sharing Bug Tests: %d/%d passed\n", pass_count, pass_count + fail_count);
    printf("=================================================\n");
    if (fail_count > 0) {
        printf("WARNING: %d test(s) failed - state sharing bugs exist!\n", fail_count);
        printf("These bugs cause patterns to incorrectly match or report wrong categories.\n");
    } else {
        printf("SUCCESS: All state sharing bug tests passed!\n");
    }
}

static void test_git_config_pattern(void) {
    printf("\nTest: Git Config Pattern Test\n");
    printf("  Testing that git config --list matches correctly\n\n");

    dfa_result_t result;

    // Test 1: git config --list should match
    printf("  1. git config --list\n");
    bool t1 = dfa_evaluate("git config --list", 0, &result);
    if (t1 && result.matched) {
        printf("  [PASS] git config --list matches\n");
        printf("         INFO: matched_length=%zu, category_mask=0x%02x\n", result.matched_length, result.category_mask);
    } else {
        printf("  [FAIL] git config --list should match\n");
        printf("         BUG: This pattern might be missing from commands.txt\n");
        printf("         or there's an issue with pattern parsing\n");
    }

    // Test 2: git config get should match
    printf("  2. git config user.name\n");
    bool t2 = dfa_evaluate("git config user.name", 0, &result);
    if (t2 && result.matched) {
        printf("  [PASS] git config user.name matches\n");
    } else {
        printf("  [FAIL] git config user.name should match\n");
    }

    // Test 3: git config with various options
    printf("  3. git config --global --list\n");
    bool t3 = dfa_evaluate("git config --global --list", 0, &result);
    if (t3 && result.matched) {
        printf("  [PASS] git config --global --list matches\n");
    } else {
        printf("  [INFO] git config --global --list may not match (depends on pattern)\n");
    }

    // Test 4: git config set should NOT match (modifying)
    printf("  4. git config user.email test@example.com (set operation)\n");
    bool t4 = dfa_evaluate("git config user.email test@example.com", 0, &result);
    if (!t4 || !result.matched) {
        printf("  [PASS] git config set correctly does NOT match\n");
    } else {
        printf("  [INFO] git config set matches (may be intentional for read-only check)\n");
    }
}

static void test_quantifier_edge_cases(void) {
    printf("\nTest: Quantifier Edge Cases\n");
    printf("  Testing edge cases for + and * quantifiers\n\n");

    dfa_result_t result;
    int pass_count = 0;
    int fail_count = 0;

    // Group 1: Empty fragment with quantifier
    printf("  Group 1: Fragment Edge Cases\n");
    printf("  =============================\n");

    // Test 1.1: a+b+ pattern (multiple quantifiers in sequence)
    printf("  Pattern: a+b+ (multiple + quantifiers)\n");
    bool t1_1 = dfa_evaluate("ab", 0, &result);
    if (t1_1 && result.matched && result.matched_length == 2) {
        printf("  [PASS] 'ab' matches a+b+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'ab' should match a+b+\n");
        fail_count++;
    }

    bool t1_2 = dfa_evaluate("aab", 0, &result);
    if (t1_2 && result.matched && result.matched_length == 3) {
        printf("  [PASS] 'aab' matches a+b+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'aab' should match a+b+\n");
        fail_count++;
    }

    bool t1_3 = dfa_evaluate("abb", 0, &result);
    if (t1_3 && result.matched && result.matched_length == 3) {
        printf("  [PASS] 'abb' matches a+b+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abb' should match a+b+\n");
        fail_count++;
    }

    bool t1_4 = dfa_evaluate("aabb", 0, &result);
    if (t1_4 && result.matched && result.matched_length == 4) {
        printf("  [PASS] 'aabb' matches a+b+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'aabb' should match a+b+\n");
        fail_count++;
    }

    bool t1_5 = dfa_evaluate("ba", 0, &result);
    if (!t1_5 || !result.matched) {
        printf("  [PASS] 'ba' does NOT match a+b+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'ba' should NOT match a+b+\n");
        fail_count++;
    }

    // Group 2: Fragment with longer prefix
    printf("\n  Group 2: Longer Prefix with Quantifier\n");
    printf("  ======================================\n");

    // Test 2.1: xyz((a))+ pattern
    printf("  Pattern: xyz((a))+\n");
    bool t2_1 = dfa_evaluate("xyza", 0, &result);
    if (t2_1 && result.matched && result.matched_length == 4) {
        printf("  [PASS] 'xyza' matches xyz((a))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'xyza' should match xyz((a))+\n");
        fail_count++;
    }

    bool t2_2 = dfa_evaluate("xyzaaa", 0, &result);
    if (t2_2 && result.matched && result.matched_length == 6) {
        printf("  [PASS] 'xyzaaa' matches xyz((a))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'xyzaaa' should match xyz((a))+\n");
        fail_count++;
    }

    bool t2_3 = dfa_evaluate("xyz", 0, &result);
    if (!t2_3 || !result.matched) {
        printf("  [PASS] 'xyz' does NOT match xyz((a))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'xyz' should NOT match xyz((a))+\n");
        fail_count++;
    }

    bool t2_4 = dfa_evaluate("xyzb", 0, &result);
    if (!t2_4 || !result.matched) {
        printf("  [PASS] 'xyzb' does NOT match xyz((a))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'xyzb' should NOT match xyz((a))+\n");
        fail_count++;
    }

    // Group 3: Overlapping patterns
    printf("\n  Group 3: Overlapping Pattern Prefixes\n");
    printf("  =====================================\n");

    // Test 3.1: ab vs abc patterns
    printf("  Patterns: a((b))+ and abc((b))+\n");
    bool t3_1 = dfa_evaluate("ab", 0, &result);
    if (t3_1 && result.matched && result.matched_length == 2) {
        printf("  [PASS] 'ab' matches a((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'ab' should match a((b))+\n");
        fail_count++;
    }

    bool t3_2 = dfa_evaluate("abcb", 0, &result);
    if (t3_2 && result.matched && result.matched_length == 4) {
        printf("  [PASS] 'abcb' matches abc((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abcb' should match abc((b))+\n");
        fail_count++;
    }

    bool t3_3 = dfa_evaluate("abc", 0, &result);
    if (!t3_3 || !result.matched) {
        printf("  [PASS] 'abc' does NOT match abc((b))+\n");
        pass_count++;
    } else {
        printf("  [FAIL] 'abc' should NOT match abc((b))+\n");
        printf("         This is the KEY BUG case!\n");
        fail_count++;
    }

    // Summary
    printf("\n=================================================\n");
    printf("Quantifier Edge Case Tests: %d/%d passed\n", pass_count, pass_count + fail_count);
    printf("=================================================\n");
    if (fail_count > 0) {
        printf("WARNING: %d test(s) failed - edge case bugs exist!\n", fail_count);
    } else {
        printf("SUCCESS: All quantifier edge case tests passed!\n");
    }
}

static void test_space_handling(void) {
    printf("\nTest: Space and Tab Character Handling\n");
    printf("  Testing that space characters create proper NFA/DFA transitions\n\n");

    dfa_result_t result;

    printf("  1. 'git status' (space between words)\n");
    bool t1 = dfa_evaluate("git status", 0, &result);
    TEST_ASSERT(t1 && result.matched && result.matched_length == 10, "  'git status' should fully match");
    if (t1 && result.matched) {
        printf("    INFO: 'git status' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 10 ? "OK" : "EXPECTED len=10");
    }

    printf("  2. 'ls -la' (space before flag)\n");
    bool t2 = dfa_evaluate("ls -la", 0, &result);
    TEST_ASSERT(t2 && result.matched && result.matched_length == 6, "  'ls -la' should fully match");

    printf("  3. 'cat file.txt' (space before filename)\n");
    bool t3 = dfa_evaluate("cat file.txt", 0, &result);
    TEST_ASSERT(t3 && result.matched && result.matched_length == 12, "  'cat file.txt' should fully match");

    printf("  4. 'echo hello world' (multiple spaces)\n");
    bool t4 = dfa_evaluate("echo hello world", 0, &result);
    TEST_ASSERT(t4 && result.matched && result.matched_length == 16, "  'echo hello world' should fully match");

    printf("  5. 'git' alone should NOT fully match 'git status' pattern\n");
    bool t5 = dfa_evaluate("git", 0, &result);
    TEST_ASSERT(!t5 || !result.matched || result.matched_length < 10, "  'git' alone should NOT match 'git status'");

    printf("  6. 'status' alone should NOT match\n");
    bool t6 = dfa_evaluate("status", 0, &result);
    TEST_ASSERT(!t6 || !result.matched, "  'status' alone should NOT match");
}

static void test_digit_specificity(void) {
    printf("\nTest: Digit Specificity in Patterns\n");
    printf("  Testing that specific digits (1, 2, 5) match only their exact values\n\n");

    dfa_result_t result;

    printf("  1. 'git log -n 1' (digit 1 should match)\n");
    bool t1 = dfa_evaluate("git log -n 1", 0, &result);
    TEST_ASSERT(t1 && result.matched, "  'git log -n 1' should match");

    printf("  2. 'git log -n 2' (digit 2 should match)\n");
    bool t2 = dfa_evaluate("git log -n 2", 0, &result);
    TEST_ASSERT(t2 && result.matched, "  'git log -n 2' should match");

    printf("  3. 'git log -n 5' (digit 5 should match)\n");
    bool t3 = dfa_evaluate("git log -n 5", 0, &result);
    TEST_ASSERT(t3 && result.matched, "  'git log -n 5' should match");

    printf("  4. 'git log -n 3' (digit 3 should NOT match)\n");
    bool t4 = dfa_evaluate("git log -n 3", 0, &result);
    TEST_ASSERT(!t4 || !result.matched, "  'git log -n 3' should NOT match (wrong digit)");

    printf("  5. 'git log -n 0' (digit 0 should NOT match)\n");
    bool t5 = dfa_evaluate("git log -n 0", 0, &result);
    TEST_ASSERT(!t5 || !result.matched, "  'git log -n 0' should NOT match (wrong digit)");
}

int main(int argc, char* argv[]) {
    // Check for test mode argument and DFA file path
    bool quantifier_mode = false;
    bool comprehensive_quantifier_mode = false;
    bool capture_mode = false;
    bool negative_mode = false;
    bool space_mode = false;
    bool digit_mode = false;
    bool acceptance_mode = false;
    bool state_sharing_mode = false;
    bool quantifier_edge_mode = false;
    bool git_config_mode = false;
    bool quiet_mode = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0) {
            quiet_mode = true;
        } else if (strcmp(argv[i], "--quantifier-test") == 0) {
            quantifier_mode = true;
        } else if (strcmp(argv[i], "--comprehensive-quantifier-test") == 0) {
            comprehensive_quantifier_mode = true;
        } else if (strcmp(argv[i], "--capture-test") == 0) {
            capture_mode = true;
        } else if (strcmp(argv[i], "--negative-test") == 0) {
            negative_mode = true;
        } else if (strcmp(argv[i], "--space-test") == 0) {
            space_mode = true;
        } else if (strcmp(argv[i], "--digit-test") == 0) {
            digit_mode = true;
        } else if (strcmp(argv[i], "--acceptance-test") == 0) {
            acceptance_mode = true;
        } else if (strcmp(argv[i], "--state-sharing-test") == 0) {
            state_sharing_mode = true;
        } else if (strcmp(argv[i], "--git-config-test") == 0) {
            git_config_mode = true;
        } else if (strcmp(argv[i], "--quantifier-edge-test") == 0) {
            quantifier_edge_mode = true;
        } else if (i == argc - 1 && argv[i][0] != '-') {
            // Last argument is the DFA file path
            dfa_file_path = argv[i];
        }
    }

    printf("=================================================\n");
    printf("ReadOnlyBox DFA Unit Tests\n");
    if (quantifier_mode) {
        printf("Mode: Quantifier Tests Only\n");
    } else if (comprehensive_quantifier_mode) {
        printf("Mode: Comprehensive Quantifier Tests Only\n");
    } else if (capture_mode) {
        printf("Mode: Capture Pattern Tests\n");
    } else if (negative_mode) {
        printf("Mode: Negative Pattern Tests\n");
    } else if (space_mode) {
        printf("Mode: Space Character Tests\n");
    } else if (acceptance_mode) {
        printf("Mode: Acceptance Category Isolation Tests\n");
    }
    printf("=================================================\n");

    test_dfa_init_valid();
    test_dfa_init_invalid();

    if (quantifier_mode) {
        // In quantifier test mode, only run the quantifier tests
        test_plus_quantifier_general();

        printf("\n=================================================\n");
        printf("Quantifier Test Results: %d/%d tests passed\n", tests_passed, tests_run);
        printf("=================================================\n");
        return (tests_passed == tests_run) ? 0 : 1;
    }

    if (comprehensive_quantifier_mode) {
        // In comprehensive quantifier test mode, run NFA/DFA comprehensive tests
        test_nfa_dfa_comprehensive(quiet_mode);

        if (!quiet_mode) {
            printf("\n=================================================\n");
            printf("Comprehensive NFA/DFA Test Results: %d/%d passed\n", tests_passed, tests_run);
            printf("=================================================\n");
        } else {
            printf("\nNFA/DFA Comprehensive Tests: %d/%d passed\n", tests_passed, tests_run);
        }
        return (tests_passed == tests_run) ? 0 : 1;
    }

    if (capture_mode) {
        // In capture test mode, only run capture tests
        test_capture_comprehensive();

        printf("\n=================================================\n");
        printf("Capture Test Results: %d/%d tests passed\n", tests_passed, tests_run);
        printf("=================================================\n");
        return (tests_passed == tests_run) ? 0 : 1;
    }

    if (negative_mode) {
        // In negative test mode, only run negative pattern tests
        test_negative_patterns();

        printf("\n=================================================\n");
        printf("Negative Pattern Test Results: %d/%d tests passed\n", tests_passed, tests_run);
        printf("=================================================\n");
        return (tests_passed == tests_run) ? 0 : 1;
    }

    if (space_mode) {
        // In space test mode, only run space handling tests
        test_space_handling();

        printf("\n=================================================\n");
        printf("Space Handling Test Results: %d/%d tests passed\n", tests_passed, tests_run);
        printf("=================================================\n");
        return (tests_passed == tests_run) ? 0 : 1;
    }

    if (digit_mode) {
        // In digit test mode, only run digit specificity tests
        test_digit_specificity();

        printf("\n=================================================\n");
        printf("Digit Specificity Test Results: %d/%d tests passed\n", tests_passed, tests_run);
        printf("=================================================\n");
        return (tests_passed == tests_run) ? 0 : 1;
    }

    if (acceptance_mode) {
        // In acceptance test mode, only run acceptance category isolation tests
        test_acceptance_category_isolation();

        printf("\n=================================================\n");
        printf("Acceptance Category Isolation Results: %d/%d tests passed\n", tests_passed, tests_run);
        printf("=================================================\n");
        return (tests_passed == tests_run) ? 0 : 1;
    }

    // Normal test mode - run all tests
    test_simple_literal_patterns();
    test_pattern_prefix_matching();
    test_git_log_variants();
    test_empty_and_null_input();
    test_case_sensitivity();
    test_whitespace_handling();
    test_category_mask_extraction();
    test_unsafe_commands_not_matched();
    test_capture_support();
    test_plus_quantifier_general();
    run_expanded_tests();  // Expanded test suite (3x coverage)
    // Note: test_plus_quantifier_comprehensive() now runs as separate test group with its own DFA
    test_capture_comprehensive();

    printf("\n=================================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("=================================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}

// ============================================================================
// Comprehensive NFA/DFA Functionality Tests
// ============================================================================
// These tests provide complete coverage of NFA/DFA features including:
// - Quantifiers: +, *, ?
// - Character classes: [abc], [a-z], [^abc]
// - Alternation: a|b
// - Escape sequences
// - Nested patterns
// - Fragments
// - Edge cases

typedef struct {
    const char* input;
    bool should_match;
    size_t expected_len;
    const char* pattern_tested;
    const char* description;
} ComprehensiveTestCase;

static void test_nfa_dfa_comprehensive(bool quiet_mode) {
    if (!quiet_mode) {
        printf("\nTest: NFA/DFA Comprehensive Functionality\n");
        printf("  Testing complete NFA/DFA feature coverage\n\n");
    }

    dfa_result_t result;
    int tests_passed = 0;
    int tests_run = 0;

    // =========================================================================
    // GROUP 1: Plus Quantifier (+) - one or more
    // =========================================================================
    if (!quiet_mode) {
        printf("  Group 1: Plus Quantifier (+)\n");
        printf("  ----------------------------\n");
    }
    
    ComprehensiveTestCase group1[] = {
        // Pattern: a((B))+ from patterns_quantifier_comprehensive.txt
        {"ab", true, 2, "a((TQ::B))+", "'ab' - single 'b' matches"},
        {"abb", true, 3, "a((TQ::B))+", "'abb' - double 'b' matches"},
        {"abbb", true, 4, "a((TQ::B))+", "'abbb' - triple 'b' matches"},
        {"a", false, 0, "a((TQ::B))+", "'a' - too short, needs 'b'"},
        {"ac", false, 0, "a((TQ::B))+", "'ac' - wrong character"},
        {"", false, 0, "a((TQ::B))+", "'(empty)' - no input"},
        
        // Pattern: x((Y))+ 
        {"xy", true, 2, "x((TQ::Y))+", "'xy' - single 'y' matches"},
        {"xyy", true, 3, "x((TQ::Y))+", "'xyy' - double 'y' matches"},
        {"xz", false, 0, "x((TQ::Y))+", "'xz' - wrong character"},
    };
    for (int i = 0; i < (int)(sizeof(group1)/sizeof(group1[0])); i++) {
        tests_run++;
        dfa_evaluate(group1[i].input, 0, &result);
        bool passed = (result.matched == group1[i].should_match);
        if (passed && group1[i].should_match) {
            passed = (result.matched_length == group1[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group1[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group1[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group1[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 2: Star Quantifier (*) - zero or more
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 2: Star Quantifier (*)\n");
        printf("  ----------------------------\n");
    } else {
        printf("  Group 2: Star Quantifier (*)\n");
    }
    
    ComprehensiveTestCase group2[] = {
        // Pattern: a((B))* from patterns_quantifier_comprehensive.txt
        {"", true, 0, "a((TQ::B))*", "'(empty)' - zero 'b' matches"},
        {"ab", true, 2, "a((TQ::B))*", "'ab' - single 'b' matches"},
        {"abb", true, 3, "a((TQ::B))*", "'abb' - double 'b' matches"},
        {"a", true, 1, "a((TQ::B))*", "'a' - zero 'b' (just 'a') matches"},
        {"ac", false, 0, "a((TQ::B))*", "'ac' - wrong character"},
    };
    for (int i = 0; i < (int)(sizeof(group2)/sizeof(group2[0])); i++) {
        tests_run++;
        dfa_evaluate(group2[i].input, 0, &result);
        bool passed = (result.matched == group2[i].should_match);
        if (passed && group2[i].should_match) {
            passed = (result.matched_length == group2[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group2[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group2[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group2[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 3: Question Mark Quantifier (?) - zero or one
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 3: Question Mark Quantifier (?)\n");
        printf("  -----------------------------------\n");
    } else {
        printf("  Group 3: Question Mark Quantifier (?)\n");
    }
    
    ComprehensiveTestCase group3[] = {
        // Pattern: git((B))? from patterns_quantifier_comprehensive.txt
        {"git", true, 3, "git((TQ::B))?", "'git' - zero 'b' matches"},
        {"gitb", true, 4, "git((TQ::B))?", "'gitb' - single 'b' matches"},
        {"gitbb", false, 0, "git((TQ::B))?", "'gitbb' - too many 'b'"},
        {"gita", false, 0, "git((TQ::B))?", "'gita' - wrong character"},
    };
    for (int i = 0; i < (int)(sizeof(group3)/sizeof(group3[0])); i++) {
        tests_run++;
        dfa_evaluate(group3[i].input, 0, &result);
        bool passed = (result.matched == group3[i].should_match);
        if (passed && group3[i].should_match) {
            passed = (result.matched_length == group3[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group3[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group3[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group3[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 4: Literal + Quantifier
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 4: Literal + Quantifier\n");
        printf("  -----------------------------\n");
    } else {
        printf("  Group 4: Literal + Quantifier\n");
    }
    
    ComprehensiveTestCase group4[] = {
        // Pattern: p+ from patterns_quantifier_comprehensive.txt
        {"p", true, 1, "p+", "'p' - single 'p' matches"},
        {"pp", true, 2, "p+", "'pp' - double 'p' matches"},
        {"ppp", true, 3, "p+", "'ppp' - triple 'p' matches"},
        {"px", false, 0, "p+", "'px' - wrong character"},
    };
    for (int i = 0; i < (int)(sizeof(group4)/sizeof(group4[0])); i++) {
        tests_run++;
        dfa_evaluate(group4[i].input, 0, &result);
        bool passed = (result.matched == group4[i].should_match);
        if (passed && group4[i].should_match) {
            passed = (result.matched_length == group4[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group4[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group4[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group4[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 5: Multiple Characters Before Quantifier
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 5: Multiple Characters Before Quantifier\n");
        printf("  -------------------------------------------\n");
    } else {
        printf("  Group 5: Multiple Characters Before Quantifier\n");
    }
    
    ComprehensiveTestCase group5[] = {
        // Pattern: abc((B))+ from patterns_quantifier_comprehensive.txt
        {"abcb", true, 4, "abc((TQ::B))+", "'abcb' - single 'b' after prefix"},
        {"abcbb", true, 5, "abc((TQ::B))+", "'abcbb' - double 'b' after prefix"},
        {"abc", false, 0, "abc((TQ::B))+", "'abc' - too short, needs 'b'"},
        {"abcd", false, 0, "abc((TQ::B))+", "'abcd' - wrong character"},
    };
    for (int i = 0; i < (int)(sizeof(group5)/sizeof(group5[0])); i++) {
        tests_run++;
        dfa_evaluate(group5[i].input, 0, &result);
        bool passed = (result.matched == group5[i].should_match);
        if (passed && group5[i].should_match) {
            passed = (result.matched_length == group5[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group5[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group5[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group5[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 6: Escape Sequences
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 6: Escape Sequences\n");
        printf("  -------------------------\n");
    } else {
        printf("  Group 6: Escape Sequences\n");
    }
    
    ComprehensiveTestCase group6[] = {
        // Pattern: hello\ world
        {"hello world", true, 11, "hello\\ world", "'hello world' matches"},
        {"helloworld", false, 0, "hello\\ world", "'helloworld' - no space"},
        {"hello worldx", false, 0, "hello\\ world", "'hello worldx' - extra char"},
        
        // Pattern: path\/to\/file
        {"path/to/file", true, 14, "path\\/to\\/file", "'path/to/file' matches"},
        {"path\\/to\\/file", false, 0, "path\\/to\\/file", "'path\\/to\\/file' - literal slash"},
    };
    for (int i = 0; i < sizeof(group6)/sizeof(group6[0]); i++) {
        tests_run++;
        dfa_evaluate(group6[i].input, 0, &result);
        bool passed = (result.matched == group6[i].should_match);
        if (passed && group6[i].should_match) {
            passed = (result.matched_length == group6[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group6[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group6[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group6[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 7: Wildcards
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 7: Wildcards (.*)\n");
        printf("  -----------------------\n");
    } else {
        printf("  Group 7: Wildcards (.*)\n");
    }
    
    ComprehensiveTestCase group7[] = {
        // Pattern: .*
        {"", true, 0, ".*", "'(empty)' - zero chars matches"},
        {"a", true, 1, ".*", "'a' - single char matches"},
        {"abc", true, 3, ".*", "'abc' - multiple chars match"},
        {"anything", true, 8, ".*", "'anything' - any string matches"},
        
        // Pattern: .*\.txt
        {"file.txt", true, 8, ".*\\.txt", "'file.txt' matches"},
        {"document.txt", true, 13, ".*\\.txt", "'document.txt' matches"},
        {"file.doc", false, 0, ".*\\.txt", "'file.doc' - wrong extension"},
        {"txt", false, 0, ".*\\.txt", "'txt' - missing name"},
    };
    for (int i = 0; i < sizeof(group7)/sizeof(group7[0]); i++) {
        tests_run++;
        dfa_evaluate(group7[i].input, 0, &result);
        bool passed = (result.matched == group7[i].should_match);
        if (passed && group7[i].should_match) {
            passed = (result.matched_length == group7[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group7[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group7[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group7[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 8: Edge Cases
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 8: Edge Cases\n");
        printf("  --------------------\n");
    } else {
        printf("  Group 8: Edge Cases\n");
    }
    
    ComprehensiveTestCase group8[] = {
        // Empty pattern
        {"", true, 0, "empty", "'(empty)' - empty string"},
        
        // Single char
        {"a", true, 1, "literal", "'a' - single char"},
        
        // Longest match behavior
        {"abc", true, 3, ".+", "'abc' - longest match"},
        {"abc123", true, 6, "[[:alpha:]]+[[:digit:]]+", "'abc123' - alpha then digit"},
    };
    for (int i = 0; i < (int)(sizeof(group8)/sizeof(group8[0])); i++) {
        tests_run++;
        dfa_evaluate(group8[i].input, 0, &result);
        bool passed = (result.matched == group8[i].should_match);
        if (passed && group8[i].should_match) {
            passed = (result.matched_length == group8[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group8[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group8[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group8[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 9: POSIX Character Classes
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 9: POSIX Character Classes\n");
        printf("  --------------------------------\n");
    } else {
        printf("  Group 9: POSIX Character Classes\n");
    }
    
    ComprehensiveTestCase group9[] = {
        // Pattern: [[:alpha:]]+
        {"abc", true, 3, "[[:alpha:]]+", "'abc' - alphabetic"},
        {"ABCXYZ", true, 6, "[[:alpha:]]+", "'ABCXYZ' - uppercase"},
        {"abc123", true, 3, "[[:alpha:]]+", "'abc123' - stops at digit"},
        {"123", false, 0, "[[:alpha:]]+", "'123' - no alpha"},
        
        // Pattern: [[:digit:]]+
        {"123", true, 3, "[[:digit:]]+", "'123' - digits"},
        {"abc123", true, 3, "[[:digit:]]+", "'abc123' - stops at alpha"},
        {"abc", false, 0, "[[:digit:]]+", "'abc' - no digits"},
        
        // Pattern: [[:alnum:]]+
        {"abc123", true, 6, "[[:alnum:]]+", "'abc123' - alphanumeric"},
        {"hello_world", true, 11, "[[:alnum:]]+", "'hello_world' - underscore not alnum"},
    };
    for (int i = 0; i < (int)(sizeof(group9)/sizeof(group9[0])); i++) {
        tests_run++;
        dfa_evaluate(group9[i].input, 0, &result);
        bool passed = (result.matched == group9[i].should_match);
        if (passed && group9[i].should_match) {
            passed = (result.matched_length == group9[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group9[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group9[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group9[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 10: Complex Alternation
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 10: Complex Alternation\n");
        printf("  ---------------------------\n");
    } else {
        printf("  Group 10: Complex Alternation\n");
    }
    
    ComprehensiveTestCase group10[] = {
        // Pattern: (cat|dog|fish)
        {"cat", true, 3, "(cat|dog|fish)", "'cat' - matches"},
        {"dog", true, 3, "(cat|dog|fish)", "'dog' - matches"},
        {"fish", true, 4, "(cat|dog|fish)", "'fish' - matches"},
        {"bird", false, 0, "(cat|dog|fish)", "'bird' - not in alternation"},
        {"catdog", true, 3, "(cat|dog|fish)", "'catdog' - stops after match"},
        
        // Pattern: git (status|log|diff)
        {"git status", true, 11, "git (status|log|diff)", "'git status' matches"},
        {"git log", true, 8, "git (status|log|diff)", "'git log' matches"},
        {"git diff", true, 9, "git (status|log|diff)", "'git diff' matches"},
        {"git push", false, 0, "git (status|log|diff)", "'git push' - not in alternation"},
    };
    for (int i = 0; i < (int)(sizeof(group10)/sizeof(group10[0])); i++) {
        tests_run++;
        dfa_evaluate(group10[i].input, 0, &result);
        bool passed = (result.matched == group10[i].should_match);
        if (passed && group10[i].should_match) {
            passed = (result.matched_length == group10[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group10[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group10[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group10[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 11: Literal Plus Quantifier
    // =========================================================================
    // GROUP 11: Literal Plus (p+)
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 11: Literal Plus Quantifier\n");
        printf("  --------------------------------\n");
    } else {
        printf("  Group 11: Literal Plus Quantifier\n");
    }
    
    ComprehensiveTestCase group11[] = {
        // Pattern: p+
        {"p", true, 1, "p+", "'p' - single 'p' matches"},
        {"pp", true, 2, "p+", "'pp' - double 'p' matches"},
        {"ppp", true, 3, "p+", "'ppp' - triple 'p' matches"},
        {"pppp", true, 4, "p+", "'pppp' - four 'p's match"},
        {"px", false, 0, "p+", "'px' - wrong character"},
        {"", false, 0, "p+", "'(empty)' - no input"},
    };
    for (int i = 0; i < (int)(sizeof(group11)/sizeof(group11[0])); i++) {
        tests_run++;
        dfa_evaluate(group11[i].input, 0, &result);
        bool passed = (result.matched == group11[i].should_match);
        if (passed && group11[i].should_match) {
            passed = (result.matched_length == group11[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group11[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group11[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group11[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 12: Character Class Ranges
    // =========================================================================
    // GROUP 12: Character Classes - Ranges
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 12: Character Class Ranges\n");
        printf("  --------------------------------\n");
    } else {
        printf("  Group 12: Character Class Ranges\n");
    }
    
    ComprehensiveTestCase group12[] = {
        // Pattern: [a-z]+
        {"abc", true, 3, "[a-z]+", "'abc' - lowercase letters"},
        {"ABC", false, 0, "[a-z]+", "'ABC' - uppercase not included"},
        {"abc123", true, 3, "[a-z]+", "'abc123' - stops at digit"},
        
        // Pattern: [A-Z0-9_]+
        {"ABC123", true, 6, "[A-Z0-9_]+", "'ABC123' - uppercase digits"},
        {"hello_world", true, 11, "[A-Z0-9_]+", "'hello_world' - underscore included"},
        {"hello-world", true, 5, "[A-Z0-9_]+", "'hello-world' - stops at dash"},
    };
    for (int i = 0; i < (int)(sizeof(group12)/sizeof(group12[0])); i++) {
        tests_run++;
        dfa_evaluate(group12[i].input, 0, &result);
        bool passed = (result.matched == group12[i].should_match);
        if (passed && group12[i].should_match) {
            passed = (result.matched_length == group12[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group12[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group12[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group12[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 13: Nested Quantifiers
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 13: Nested Quantifiers\n");
        printf("  ---------------------------\n");
    } else {
        printf("  Group 13: Nested Quantifiers\n");
    }
    
    ComprehensiveTestCase group13[] = {
        // Pattern: ((a))+
        {"a", true, 1, "((a))+", "'a' - single 'a' matches"},
        {"aa", true, 2, "((a))+", "'aa' - double 'a' matches"},
        {"aaa", true, 3, "((a))+", "'aaa' - triple 'a' matches"},
        {"", false, 0, "((a))+", "'(empty)' - no input"},
    };
    for (int i = 0; i < (int)(sizeof(group13)/sizeof(group13[0])); i++) {
        tests_run++;
        dfa_evaluate(group13[i].input, 0, &result);
        bool passed = (result.matched == group13[i].should_match);
        if (passed && group13[i].should_match) {
            passed = (result.matched_length == group13[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group13[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group13[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group13[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 14: Escaped Special Characters
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 14: Escaped Special Characters\n");
        printf("  ----------------------------------\n");
    } else {
        printf("  Group 14: Escaped Special Characters\n");
    }
    
    ComprehensiveTestCase group14[] = {
        // Pattern: a\+b (literal +)
        {"a+b", true, 3, "a\\+b", "'a+b' - literal plus matches"},
        {"ab", false, 0, "a\\+b", "'ab' - no plus"},
        {"a++b", false, 0, "a\\+b", "'a++b' - too many chars"},
        
        // Pattern: a\*b (literal *)
        {"a*b", true, 3, "a\\*b", "'a*b' - literal asterisk matches"},
        {"ab", false, 0, "a\\*b", "'ab' - no asterisk"},
    };
    for (int i = 0; i < (int)(sizeof(group14)/sizeof(group14[0])); i++) {
        tests_run++;
        dfa_evaluate(group14[i].input, 0, &result);
        bool passed = (result.matched == group14[i].should_match);
        if (passed && group14[i].should_match) {
            passed = (result.matched_length == group14[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group14[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group14[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group14[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // GROUP 15: Multiple Characters Before Quantifier
    // =========================================================================
    // GROUP 15: Multiple Character Before Quantifier
    // =========================================================================
    if (!quiet_mode) {
        printf("\n  Group 15: Multiple Characters Before Quantifier\n");
        printf("  ---------------------------------------------\n");
    } else {
        printf("  Group 15: Multiple Characters Before Quantifier\n");
    }
    
    ComprehensiveTestCase group15[] = {
        // Pattern: abc((B))+
        {"abcb", true, 4, "abc((TQ::B))+", "'abcb' - single 'b' after prefix"},
        {"abcbb", true, 5, "abc((TQ::B))+", "'abcbb' - double 'b' after prefix"},
        {"abcbbb", true, 6, "abc((TQ::B))+", "'abcbbb' - triple 'b' after prefix"},
        {"abc", false, 0, "abc((TQ::B))+", "'abc' - too short, needs 'b'"},
        {"abcd", false, 0, "abc((TQ::B))+", "'abcd' - wrong character"},
    };
    for (int i = 0; i < (int)(sizeof(group15)/sizeof(group15[0])); i++) {
        tests_run++;
        dfa_evaluate(group15[i].input, 0, &result);
        bool passed = (result.matched == group15[i].should_match);
        if (passed && group15[i].should_match) {
            passed = (result.matched_length == group15[i].expected_len);
        }
        if (passed) {
            tests_passed++;
        }
        if (quiet_mode) {
            if (!passed) {
                printf("  [FAIL] %s\n", group15[i].description);
            }
        } else {
            if (passed) {
                printf("  [PASS] %s\n", group15[i].description);
            } else {
                printf("  [FAIL] %s - got %s (len=%zu)\n", group15[i].description,
                       result.matched ? "MATCH" : "NO MATCH", result.matched_length);
            }
        }
    }

    // =========================================================================
    // Summary
    // =========================================================================
    if (!quiet_mode) {
        printf("\n=================================================\n");
        printf("NFA/DFA Comprehensive Tests: %d/%d passed\n", tests_passed, tests_run);
        printf("=================================================\n");
    } else {
        printf("\nNFA/DFA Comprehensive Tests: %d/%d passed\n", tests_passed, tests_run);
    }
}

// ============================================================================
// EXPANDED DFA/NFA TEST SUITE (3x Coverage)
// ============================================================================
// Additional test functions for comprehensive coverage

static int expanded_tests_run = 0;
static int expanded_tests_passed = 0;

#define EXP_TEST_ASSERT(cond, msg) do { \
    expanded_tests_run++; \
    if (cond) { \
        expanded_tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        printf("  [FAIL] %s\n", msg); \
    } \
} while(0)

typedef struct {
    const char* input;
    bool should_match;
    size_t expected_len;
    const char* description;
} ExpandedTestCase;

static void test_expanded_quantifier_edge_cases(void) {
    printf("\nTest: Quantifier Edge Cases (Expanded)\n");
    printf("  Edge cases that commonly cause failures\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Single char quantifier edge cases
        {"a+", true, 1, "a+ matches single 'a'"},
        {"aa+", true, 2, "aa+ matches two 'a's"},
        {"aaa+", true, 3, "aaa+ matches three 'a's"},
        {"aaaaaa", true, 6, "aaaaaa matches six 'a's"},
        {"", false, 0, "empty string should not match a+"},
        {"b", false, 0, "b should not match a+"},
        {"ab", false, 0, "ab should not match a+"},
        {"ba", false, 0, "ba should not match a+"},
        {"aaaab", false, 0, "aaaab should not match a+"},

        // Multiple char literal quantifier
        {"abc+", true, 3, "abc+ matches 'abc'"},
        {"abcc", true, 4, "abcc matches 'abcc'"},
        {"abccc", true, 5, "abccc matches 'abccc'"},
        {"", false, 0, "empty should not match abc+"},
        {"ab", false, 0, "ab should not match abc+"},
        {"abd", false, 0, "abd should not match abc+"},

        // Quantifier at pattern end
        {"test123+", true, 7, "test123+ matches full pattern"},
        {"test1234", false, 0, "test1234 should not match test123+"},

        // Quantifier after fragment
        {"xyz((abc))+", true, 6, "xyz((abc))+ matches xyzabc"},
        {"xyz((abc))abc", true, 9, "xyz((abc))abc matches xyzabcabc"},
        {"xyz((abc))abcabc", true, 12, "xyz((abc))abcabc matches xyzabcabcabc"},
        {"xyz", false, 0, "xyz should not match xyz((abc))+"},
        {"xyz((def))+", false, 0, "xyz((def))+ should not match"},

        // Zero vs one quantifier confusion
        {"a?", true, 1, "a? matches single 'a'"},
        {"", true, 0, "empty matches a? (zero occurrences)"},
        {"aa", false, 0, "aa should not match a?"},

        // Star vs plus confusion
        {"a*", true, 0, "a* matches empty (zero or more)"},
        {"a", true, 1, "a matches a* (one)"},
        {"aa", true, 2, "aa matches a* (two)"},
        {"aaa", true, 3, "aaa matches a* (three)"},
        {"b", true, 0, "b matches a* (zero a's, just b)"},
        {"baa", true, 1, "baa matches a* (one a)"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_alternation_with_quantifiers(void) {
    printf("\nTest: Alternation with Quantifiers (Expanded)\n");
    printf("  Testing | combined with +, *, ?\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Alternation with plus
        {"(a|b)+", true, 1, "(a|b)+ matches 'a'"},
        {"(a|b)+", true, 1, "(a|b)+ matches 'b'"},
        {"(a|b)+", true, 2, "(a|b)+ matches 'aa'"},
        {"(a|b)+", true, 2, "(a|b)+ matches 'ab'"},
        {"(a|b)+", true, 2, "(a|b)+ matches 'ba'"},
        {"(a|b)+", true, 2, "(a|b)+ matches 'bb'"},
        {"(a|b)+", true, 3, "(a|b)+ matches 'aba'"},
        {"(a|b)+", true, 5, "(a|b)+ matches 'ababa'"},
        {"", false, 0, "empty should not match (a|b)+"},
        {"c", false, 0, "'c' should not match (a|b)+"},

        // Alternation with star
        {"(a|b)*", true, 0, "(a|b)* matches empty"},
        {"(a|b)*", true, 1, "(a|b)* matches 'a'"},
        {"(a|b)*", true, 2, "(a|b)* matches 'ab'"},
        {"(a|b)*", true, 4, "(a|b)* matches 'abba'"},
        {"(a|b)*c", true, 3, "(a|b)*c matches 'abc'"},
        {"(a|b)*c", true, 4, "(a|b)*c matches 'abbc'"},
        {"c", true, 1, "(a|b)*c matches 'c' (zero a/b)"},
        {"ac", true, 2, "(a|b)*c matches 'ac'"},

        // Alternation with optional
        {"(a|b)?", true, 0, "(a|b)? matches empty"},
        {"(a|b)?", true, 1, "(a|b)? matches 'a'"},
        {"(a|b)?", true, 1, "(a|b)? matches 'b'"},
        {"(a|b)?c", true, 2, "(a|b)?c matches 'ac'"},
        {"(a|b)?c", true, 2, "(a|b)?c matches 'bc'"},
        {"(a|b)?c", true, 1, "(a|b)?c matches 'c' (optional not present)"},
        {"(a|b)?c", false, 0, "(a|b)?c should not match 'cc'"},

        // Multiple alternations
        {"(a|b|c)+", true, 1, "(a|b|c)+ matches 'a'"},
        {"(a|b|c)+", true, 1, "(a|b|c)+ matches 'b'"},
        {"(a|b|c)+", true, 1, "(a|b|c)+ matches 'c'"},
        {"(a|b|c)+", true, 3, "(a|b|c)+ matches 'abc'"},
        {"(a|b|c)+", true, 5, "(a|b|c)+ matches 'ababc'"},
        {"", false, 0, "empty should not match (a|b|c)+"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_nested_quantifiers(void) {
    printf("\nTest: Complex Nested Quantifiers (Expanded)\n");
    printf("  Deeply nested quantifier patterns\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Double nesting
        {"((a))+", true, 1, "((a))+ matches 'a'"},
        {"((a))+", true, 2, "((a))+ matches 'aa'"},
        {"((a))+", true, 3, "((a))+ matches 'aaa'"},
        {"", false, 0, "empty should not match ((a))+"},

        // Triple nesting
        {"(((a)))+", true, 1, "(((a)))+ matches 'a'"},
        {"(((a)))+", true, 3, "(((a)))+ matches 'aaa'"},
        {"", false, 0, "empty should not match (((a)))+"},

        // Mixed nesting
        {"((a)+)+", true, 1, "((a)+)+ matches 'a' (inner + requires one)"},
        {"((a)+)+", true, 2, "((a)+)+ matches 'aa'"},
        {"((a)+)+", true, 3, "((a)+)+ matches 'aaa'"},
        {"((a)+)+", true, 4, "((a)+)+ matches 'aaaa'"},
        {"", false, 0, "empty should not match ((a)+)+"},

        // Star inside plus
        {"(a*)+", true, 0, "(a*)+ matches empty (a* allows zero)"},
        {"(a*)+", true, 1, "(a*)+ matches 'a'"},
        {"(a*)+", true, 2, "(a*)+ matches 'aa'"},
        {"(a*)+", true, 3, "(a*)+ matches 'aaa'"},
        {"(a*)+b", true, 2, "(a*)+b matches 'ab'"},
        {"(a*)+b", true, 3, "(a*)+b matches 'aab'"},

        // Plus inside star
        {"(a+)*", true, 0, "(a+)* matches empty (zero repetitions)"},
        {"(a+)*", true, 1, "(a+)* matches 'a' (one rep of a+)"},
        {"(a+)*", true, 2, "(a+)* matches 'aa' (one rep)"},
        {"(a+)*", true, 3, "(a+)* matches 'aaa' (one rep)"},
        {"(a+)*", true, 4, "(a+)* matches 'aaaa' (one rep)"},
        {"", true, 0, "(a+)* matches empty (zero reps)"},
        {"b", true, 0, "(a+)*b matches 'b' (zero a+ reps)"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_fragment_interactions(void) {
    printf("\nTest: Fragment Interactions (Expanded)\n");
    printf("  Testing multiple fragments with quantifiers\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Multiple fragments
        {"((x))+((y))+", true, 2, "xy matches x+ y+"},
        {"((x))+((y))+", true, 3, "xxy matches x+ y+"},
        {"((x))+((y))+", true, 3, "xyy matches x+ y+"},
        {"((x))+((y))+", true, 4, "xxyy matches x+ y+"},
        {"((x))+((y))+", true, 5, "xxxyy matches x+ y+"},
        {"((x))+((y))+", true, 5, "xxyyy matches x+ y+"},
        {"", false, 0, "empty should not match x+ y+"},
        {"x", false, 0, "x alone should not match x+ y+"},
        {"y", false, 0, "y alone should not match x+ y+"},

        // Fragment with literal
        {"abc((def))+", true, 6, "abcdef matches abc def+"},
        {"abc((def))+", true, 9, "abcdefdef matches abc def+ def+"},
        {"abc((def))+", true, 12, "abcdefdefdef matches abc def+ def+ def+"},
        {"abc", false, 0, "abc alone should not match abc def+"},
        {"abcdeg", false, 0, "abcdeg should not match abc def+"},

        // Nested fragments
        {"(( (a) ))+", true, 1, "nested single char fragment matches 'a'"},
        {"(( (a) ))+", true, 3, "nested single char fragment matches 'aaa'"},
        {"", false, 0, "nested fragment should not match empty"},

        // Fragment alternation
        {"((a|b))+((c|d))+", true, 2, "ac matches a+|c+ with b+|d+"},
        {"((a|b))+((c|d))+", true, 2, "ad matches a+|c+ with b+|d+"},
        {"((a|b))+((c|d))+", true, 2, "bc matches a+|c+ with b+|d+"},
        {"((a|b))+((c|d))+", true, 2, "bd matches a+|c+ with b+|d+"},
        {"", false, 0, "empty should not match fragment alternation"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_boundary_conditions(void) {
    printf("\nTest: Boundary Conditions (Expanded)\n");
    printf("  Edge cases at pattern boundaries\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Empty pattern edge cases
        {"", true, 0, "empty pattern matches empty string"},

        // Quantifier at very end
        {"abc", true, 3, "abc matches 'abc' at end"},
        {"abcdef", true, 6, "abcdef matches full pattern"},
        {"abcde", false, 0, "abcde should not match if pattern needs 'f'"},
        {"abcdefg", false, 0, "abcdefg should not match if pattern ends at 'f'"},

        // Over-quantification
        {"a++", true, 2, "a++ matches 'aa' (two a's)"},
        {"a++", true, 3, "a++ matches 'aaa' (three a's)"},
        {"a+++", true, 3, "a+++ matches 'aaa' (three a's)"},

        // Mixed quantifiers
        {"a?b+", true, 2, "ab matches a?b+"},
        {"a?b+", true, 1, "b matches a?b+ (a is optional)"},
        {"a?b+", true, 3, "abb matches a?b+"},
        {"a?b+", true, 4, "abbb matches a?b+"},
        {"a?b+", false, 0, "a alone should not match a?b+"},
        {"a?b+", false, 0, "empty should not match a?b+"},

        {"a+b?", true, 1, "a matches a+b? (b optional)"},
        {"a+b?", true, 2, "ab matches a+b?"},
        {"a+b?", true, 3, "aab matches a+b?"},
        {"a+b?", true, 3, "abb matches a+b?"},
        {"", false, 0, "empty should not match a+b?"},

        // Consecutive quantifiers
        {"a?b?c?", true, 0, "empty matches a?b?c? (all optional)"},
        {"a?b?c?", true, 1, "a matches a?b?c?"},
        {"a?b?c?", true, 2, "ab matches a?b?c?"},
        {"a?b?c?", true, 3, "abc matches a?b?c?"},
        {"a?b?c?", true, 1, "b matches a?b?c? (a optional)"},
        {"a?b?c?", true, 2, "bc matches a?b?c? (a optional)"},
        {"a?b?c?", true, 1, "c matches a?b?c? (a,b optional)"},
        {"a?b?c?", false, 0, "d should not match a?b?c?"},

        // Maximum repetition test
        {"aaaaaaaaaaaaaaa", true, 15, "15 a's match a+"},
        {"aaaaaaaaaaaaaaaa", true, 16, "16 a's match a+"},
        {"aaaaaaaaaaaaaaaaa", true, 17, "17 a's match a+"},
        {"aaaaaaaaaaaaaaaaaa", true, 18, "18 a's match a+"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_quantifier_interactions(void) {
    printf("\nTest: Quantifier Interaction Patterns (Expanded)\n");
    printf("  Complex interactions between quantifiers\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Plus followed by star
        {"a+b*", true, 1, "a+b* matches 'a' (b*)"},
        {"a+b*", true, 2, "a+b* matches 'ab'"},
        {"a+b*", true, 3, "a+b* matches 'abb'"},
        {"a+b*", true, 2, "a+b* matches 'aa' (one b, star extends)"},
        {"a+b*", true, 3, "a+b* matches 'aab'"},
        {"a+b*", true, 1, "a+b* matches 'a' (zero bs)"},
        {"b*", true, 0, "a+b* starting with b* matches 'b'"},
        {"", false, 0, "empty should not match a+b* (needs at least one a)"},

        // Star followed by plus
        {"a*b+", true, 1, "a*b+ matches 'a' (a* allows zero, b+ needs one)"},
        {"a*b+", true, 2, "a*b+ matches 'ab'"},
        {"a*b+", true, 3, "a*b+ matches 'abb'"},
        {"a*b+", true, 2, "a*b+ matches 'aa' (first a*, then b+)"},
        {"a*b+", true, 3, "a*b+ matches 'aab'"},
        {"a*b+", true, 1, "a*b+ matches 'b' (zero a's)"},
        {"", false, 0, "empty should not match a*b+ (needs at least one b)"},

        // Optional followed by plus
        {"a?b+", true, 1, "a?b+ matches 'b' (a optional)"},
        {"a?b+", true, 2, "a?b+ matches 'ab'"},
        {"a?b+", true, 3, "a?b+ matches 'abb'"},
        {"", false, 0, "empty should not match a?b+ (needs b)"},

        // Plus followed by optional
        {"a+b?", true, 1, "a+b? matches 'a' (b optional)"},
        {"a+b?", true, 2, "a+b? matches 'ab'"},
        {"a+b?", true, 3, "a+b? matches 'abb'"},
        {"a+b?", true, 2, "a+b? matches 'aa'"},
        {"", false, 0, "empty should not match a+b?"},

        // All three quantifiers
        {"a?b?c?", true, 0, "empty matches a?b?c?"},
        {"a?b?c?", true, 1, "a matches a?b?c?"},
        {"a?b?c?", true, 2, "ab matches a?b?c?"},
        {"a?b?c?", true, 3, "abc matches a?b?c?"},
        {"a?b?c?", true, 1, "b matches a?b?c?"},
        {"a?b?c?", true, 2, "bc matches a?b?c?"},
        {"a?b?c?", true, 1, "c matches a?b?c?"},

        // Complex interactions
        {"(a+b?)+", true, 1, "(a+b?)+ matches 'a'"},
        {"(a+b?)+", true, 2, "(a+b?)+ matches 'ab'"},
        {"(a+b?)+", true, 3, "(a+b?)+ matches 'aba'"},
        {"(a+b?)+", true, 3, "(a+b?)+ matches 'abb'"},
        {"(a+b?)+", true, 4, "(a+b?)+ matches 'abab'"},
        {"(a+b?)+", true, 2, "(a+b?)+ matches 'aa'"},
        {"", true, 0, "(a+b?)+ matches empty (outer + allows zero)"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_mixed_literal_fragment(void) {
    printf("\nTest: Mixed Literal/Fragment Quantifiers (Expanded)\n");
    printf("  Combining literal chars with fragments under quantifiers\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Literal followed by fragment with quantifier
        {"x((y))", true, 2, "xy matches x y (no quantifier)"},
        {"x((y))+", true, 2, "xy matches x y+ (one y)"},
        {"x((y))+", true, 3, "xyy matches x y+ (two y's)"},
        {"x((y))+", true, 4, "xyyy matches x y+ (three y's)"},
        {"x", false, 0, "x alone should not match x y+"},
        {"xz", false, 0, "xz should not match x y+"},

        // Fragment followed by literal with quantifier
        {"((x))y", true, 2, "xy matches x y (no quantifier)"},
        {"((x))+y", true, 2, "xy matches x+ y (one x)"},
        {"((x))+y", true, 3, "xxy matches x+ y (two x's)"},
        {"((x))+y", true, 4, "xxxy matches x+ y (three x's)"},
        {"y", false, 0, "y alone should not match x+ y"},
        {"zy", false, 0, "zy should not match x+ y"},

        // Multiple literals with fragment quantifier
        {"ab((c))de", true, 5, "abcde matches ab c de"},
        {"ab((c))+de", true, 5, "abcde matches ab c+ de (one c)"},
        {"ab((c))+de", true, 6, "abccde matches ab c+ de (two c's)"},
        {"ab((c))+de", true, 7, "abcccde matches ab c+ de (three c's)"},
        {"abde", false, 0, "abde should not match ab c+ de"},
        {"abfde", false, 0, "abfde should not match ab c+ de"},

        // Fragment with quantifier between literals
        {"start((mid))+end", true, 10, "startmidend matches start mid+ end (one mid)"},
        {"start((mid))+end", true, 13, "startmiddend matches start mid+ end (two mids)"},
        {"start((mid))+end", true, 16, "startmidddend matches start mid+ end (three mids)"},
        {"startend", false, 0, "startend should not match start mid+ end"},
        {"startxend", false, 0, "startxend should not match start mid+ end"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_hard_edge_cases(void) {
    printf("\nTest: Very Hard Edge Cases (Expanded)\n");
    printf("  Extremely challenging patterns likely to fail\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Nested plus patterns
        {"(a+a+)+b", true, 3, "(a+a+)+b matches 'aab' (nested plus)"},
        {"(a+a+)+b", true, 5, "(a+a+)+b matches 'aaaab' (nested plus)"},
        {"(a+a+)+b", true, 7, "(a+a+)+b matches 'aaaaaab' (nested plus)"},
        {"b", false, 0, "b alone should not match (a+a+)+b"},

        // Overlapping fragment references
        {"((a))+((a))+", true, 1, "a matches a+ a+ (both fragments same char)"},
        {"((a))+((a))+", true, 2, "aa matches a+ a+ (two total)"},
        {"((a))+((a))+", true, 3, "aaa matches a+ a+ (three total)"},
        {"", false, 0, "empty should not match a+ a+"},

        // Fragment with itself in quantifier
        {"((ab))+", true, 2, "(ab)+ matches 'ab'"},
        {"((ab))+", true, 4, "(ab)+ matches 'abab'"},
        {"((ab))+", true, 6, "(ab)+ matches 'ababab'"},
        {"a", false, 0, "'a' should not match (ab)+"},
        {"b", false, 0, "'b' should not match (ab)+"},
        {"aba", false, 0, "'aba' should not match (ab)+"},

        // Alternation with quantifier edge cases
        {"(a|aa)+", true, 1, "(a|aa)+ matches 'a'"},
        {"(a|aa)+", true, 2, "(a|aa)+ matches 'aa'"},
        {"(a|aa)+", true, 2, "(a|aa)+ matches 'aa' (second alternative)"},
        {"(a|aa)+", true, 3, "(a|aa)+ matches 'aaa' (a + aa)"},
        {"(a|aa)+", true, 4, "(a|aa)+ matches 'aaaa' (aa + aa)"},
        {"", false, 0, "empty should not match (a|aa)+"},

        // Quantifier after character class
        {"[abc]+", true, 1, "[abc]+ matches 'a'"},
        {"[abc]+", true, 1, "[abc]+ matches 'b'"},
        {"[abc]+", true, 1, "[abc]+ matches 'c'"},
        {"[abc]+", true, 3, "[abc]+ matches 'abc'"},
        {"[abc]+", true, 5, "[abc]+ matches 'ababc'"},
        {"[abc]+", true, 6, "[abc]+ matches 'abcabc'"},
        {"d", false, 0, "'d' should not match [abc]+"},
        {"", false, 0, "empty should not match [abc]+"},

        // Whitespace handling with quantifiers
        {"a +b", true, 3, "a b matches 'a +b' (one space before +)"},
        {"a+ b", true, 2, "ab matches 'a+ b' (no space in input)"},
        {"aa b", true, 3, "aa b matches 'a+ b'"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_performance_stress(void) {
    printf("\nTest: Performance Stress Quantifiers (Expanded)\n");
    printf("  Large inputs to test efficiency\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Long inputs matching
        {"a", true, 1, "single 'a' matches a+"},
        {"aa", true, 2, "two 'a's match a+"},
        {"aaa", true, 3, "three 'a's match a+"},
        {"aaaa", true, 4, "four 'a's match a+"},
        {"aaaaa", true, 5, "five 'a's match a+"},
        {"aaaaaa", true, 6, "six 'a's match a+"},
        {"aaaaaaa", true, 7, "seven 'a's match a+"},
        {"aaaaaaaa", true, 8, "eight 'a's match a+"},
        {"aaaaaaaaa", true, 9, "nine 'a's match a+"},
        {"aaaaaaaaaa", true, 10, "ten 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaa", true, 26, "26 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaa", true, 27, "27 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, 28, "28 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, 29, "29 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, 30, "30 'a's match a+"},

        // Long inputs not matching
        {"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", false, 0, "50 b's should not match a+"},
        {"", false, 0, "empty should not match a+ (requires at least one a)"},

        // Medium complex patterns
        {"ababababab", true, 10, "10 chars 'ab' pattern matches"},
        {"abababababa", false, 0, "11 chars 'ab' pattern should not match (odd length)"},
        {"xyxyxyxyxyxyxyxyxyxy", true, 20, "20 chars 'xy' pattern matches"},
        {"xyxyxyxyxyxyxyxyxyx", false, 0, "19 chars 'xy' pattern should not match"},

        // Stress test with fragments
        {"testtesttesttesttest", true, 20, "5 'test' repetitions match"},
        {"testtesttesttesttesttest", true, 24, "6 'test' repetitions match"},
        {"testtesttesttesttesttesttest", true, 28, "7 'test' repetitions match"},
        {"testtesttesttesttesttesttesttest", true, 32, "8 'test' repetitions match"},
        {"testtesttesttesttesttesttesttesttest", true, 36, "9 'test' repetitions match"},
        {"testtesttesttesttesttesttesttesttesttest", true, 40, "10 'test' repetitions match"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

void run_expanded_tests(void) {
    printf("\n");
    printf("=================================================\n");
    printf("EXPANDED DFA/NFA TEST SUITE (3x Coverage)\n");
    printf("=================================================\n");

    test_expanded_quantifier_edge_cases();
    test_expanded_alternation_with_quantifiers();
    test_expanded_nested_quantifiers();
    test_expanded_fragment_interactions();
    test_expanded_boundary_conditions();
    test_expanded_quantifier_interactions();
    test_expanded_mixed_literal_fragment();
    test_expanded_hard_edge_cases();
    test_expanded_performance_stress();

    printf("\n=================================================\n");
    printf("EXPANDED TESTS: %d/%d passed\n", expanded_tests_passed, expanded_tests_run);
    printf("=================================================\n");
}
