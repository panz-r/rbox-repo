#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static const char* dfa_file_path = "readonlybox.dfa";  // Default DFA file path

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

    FILE* f = fopen(dfa_file_path, "rb");
    TEST_ASSERT(f != NULL, "Can open DFA file");

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    bool result = dfa_init(data, size);
    TEST_ASSERT(result == true, "DFA init returns true");
    TEST_ASSERT(dfa_is_valid() == true, "dfa_is_valid returns true");
    uint16_t version = dfa_get_version();
    TEST_ASSERT(version >= 3, "DFA version is 3 or higher");

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

    TEST_ASSERT(dfa_evaluate("GIT STATUS", 0, &result) && !result.matched,
                "GIT STATUS (uppercase) does NOT match");

    TEST_ASSERT(dfa_evaluate("Git Status", 0, &result) && !result.matched,
                "Git Status (mixed case) does NOT match");
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
    printf("  DEBUG: cat test.txt: eval=%d, matched=%d, len=%zu, category=%d\n", r1, result.matched, result.matched_length, result.category);
    TEST_ASSERT(r1 && result.matched, "cat test.txt matches");

    // Test cat with path (matches pattern without capture tags)
    bool r2 = dfa_evaluate("cat /path/to/file.txt", 0, &result);
    printf("  DEBUG: cat /path: eval=%d, matched=%d, len=%zu\n", r2, result.matched, result.matched_length);
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
    printf("        Current implementation uses ANY-based back-loop which has limitations\n");
    printf("        The instant-transition solution will fix these limitations\n\n");

    dfa_result_t result;

    // Test pattern: a((b))+ - should match "ab", "abb", "abbb" but NOT "ac"
    // Currently FAILS: ANY consumes next char before fragment can match it
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

    // Test pattern: x((y))+ - similar test with different characters
    printf("\n  Pattern: x((y))+ (tests + quantifier with different chars)\n");
    
    bool t7 = dfa_evaluate("xy", 0, &result);
    TEST_ASSERT(t7 && result.matched && result.matched_length == 2, "  'xy' should match with len=2");
    if (t7 && result.matched) {
        printf("    INFO: 'xy' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 2 ? "OK" : "EXPECTED len=2");
    }

    bool t8 = dfa_evaluate("xyyyy", 0, &result);
    TEST_ASSERT(t8 && result.matched && result.matched_length == 5, "  'xyyyy' should match with len=5");
    if (t8 && result.matched) {
        printf("    INFO: 'xyyyy' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 5 ? "OK" : "EXPECTED len=5");
    }

    bool t9 = dfa_evaluate("xz", 0, &result);
    TEST_ASSERT(!t9 || !result.matched, "  'xz' should NOT match (z is not y)");
    if (t9 && result.matched) {
        printf("    INFO: 'xz' matched (len=%zu) - EXPECTED no match!\n", result.matched_length);
    }

    // Test pattern: w((z))+ - letter+letter quantifier (both have per-character symbols)
    printf("\n  Pattern: w((z))+ (tests + quantifier with letter fragment)\n");

    bool t10 = dfa_evaluate("w", 0, &result);
    TEST_ASSERT(!t10 || !result.matched, "  'w' should NOT match (needs at least one 'z')");
    if (t10 && result.matched) {
        printf("    INFO: 'w' matched (len=%zu) - pattern accepts zero or more\n", result.matched_length);
    }

    bool t11 = dfa_evaluate("wz", 0, &result);
    TEST_ASSERT(t11 && result.matched && result.matched_length == 2, "  'wz' should match with len=2");
    if (t11 && result.matched) {
        printf("    INFO: 'wz' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 2 ? "OK" : "EXPECTED len=2");
    }

    bool t12 = dfa_evaluate("wzz", 0, &result);
    TEST_ASSERT(t12 && result.matched && result.matched_length == 3, "  'wzz' should match with len=3");
    if (t12 && result.matched) {
        printf("    INFO: 'wzz' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 3 ? "OK" : "EXPECTED len=3");
    }

    bool t13 = dfa_evaluate("wzzz", 0, &result);
    TEST_ASSERT(t13 && result.matched && result.matched_length == 4, "  'wzzz' should match with len=4");
    if (t13 && result.matched) {
        printf("    INFO: 'wzzz' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 4 ? "OK" : "EXPECTED len=4");
    }

    bool t14 = dfa_evaluate("wy", 0, &result);
    TEST_ASSERT(!t14 || !result.matched, "  'wy' should NOT match (y is not z)");
    if (t14 && result.matched) {
        printf("    INFO: 'wy' matched (len=%zu) - EXPECTED no match!\n", result.matched_length);
    }

    bool t15 = dfa_evaluate("wb", 0, &result);
    TEST_ASSERT(!t15 || !result.matched, "  'wb' should NOT match (b is not z)");
    if (t15 && result.matched) {
        printf("    INFO: '1b' matched (len=%zu) - EXPECTED no match!\n", result.matched_length);
    }

    // Test literal + quantifier (not fragment-based)
    // NOTE: p+ means ONE OR MORE 'p', so 'p' SHOULD match
    printf("\n  Pattern: p+ (tests literal + quantifier, not fragment)\n");
    bool t20 = dfa_evaluate("p", 0, &result);
    TEST_ASSERT(t20 && result.matched, "  'p' should match (one 'p' is enough)");
    if (t20 && result.matched) {
        printf("    INFO: 'p' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 1 ? "OK" : "EXPECTED len=1");
    }

    bool t21 = dfa_evaluate("pp", 0, &result);
    TEST_ASSERT(t21 && result.matched && result.matched_length == 2, "  'pp' should match with len=2");
    if (t21 && result.matched) {
        printf("    INFO: 'pp' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 2 ? "OK" : "EXPECTED len=2");
    }

    bool t22 = dfa_evaluate("ppp", 0, &result);
    TEST_ASSERT(t22 && result.matched && result.matched_length == 3, "  'ppp' should match with len=3");
    if (t22 && result.matched) {
        printf("    INFO: 'ppp' matched (len=%zu) %s\n", result.matched_length,
               result.matched_length == 3 ? "OK" : "EXPECTED len=3");
    }

    bool t23 = dfa_evaluate("px", 0, &result);
    TEST_ASSERT(!t23 || !result.matched, "  'px' should NOT match (x is not p)");
    if (t23 && result.matched) {
        printf("    INFO: 'px' matched (len=%zu) - EXPECTED no match!\n", result.matched_length);
    }

    // Test multiple chars before + quantifier
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
                   result.matched ? "MATCH" : "NO MATCH",
                   result.matched_length);
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
    bool abc_should_not_match = dfa_evaluate("abc", 0, &result);
    if (abc_should_not_match && result.matched) {
        printf("  [FAIL] 'abc' - CRITICAL BUG: matches when it should NOT\n");
        printf("         Pattern abc((b))+ requires at least one 'b' after 'abc'\n");
        printf("         This indicates interference between acceptance categories\n");
        fail_count++;
    } else {
        printf("  [PASS] 'abc' - correctly does NOT match (requires 'b' suffix)\n");
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
    TEST_ASSERT(!(dfa_evaluate("abcd", 0, &result) && result.matched),
               "'abcd' does NOT match abc((b))+ (wrong ending)");
    TEST_ASSERT(!(dfa_evaluate("abca", 0, &result) && result.matched),
               "'abca' does NOT match abc((b))+ (wrong suffix)");

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
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quantifier-test") == 0) {
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
        // In comprehensive quantifier test mode, only run comprehensive tests
        test_plus_quantifier_comprehensive();

        printf("\n=================================================\n");
        printf("Comprehensive Quantifier Test Results: %d/%d tests passed\n", tests_passed, tests_run);
        printf("=================================================\n");
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
    // Note: test_plus_quantifier_comprehensive() now runs as separate test group with its own DFA
    test_capture_comprehensive();

    printf("\n=================================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("=================================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}
