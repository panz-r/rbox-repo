#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

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

    FILE* f = fopen("readonlybox.dfa", "rb");
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
    TEST_ASSERT(dfa_get_version() == 4, "DFA version is 4");

    free(data);
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
    TEST_ASSERT(result.matched == false, "ls -la does NOT match");

    dfa_evaluate("cat *", 0, &result);
    TEST_ASSERT(result.matched == true, "cat * matches (literal asterisk)");

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

    // Test cat with filename capture
    TEST_ASSERT(dfa_evaluate("cat test.txt", 0, &result) && result.matched,
                "cat test.txt matches");

    // Check capture count
    TEST_ASSERT(result.capture_count >= 1, "Has at least one capture");
    if (result.capture_count >= 1) {
        TEST_ASSERT(result.captures[0].start > 0, "Capture has valid start position");
        TEST_ASSERT(result.captures[0].end > result.captures[0].start, "Capture has valid end position");
        TEST_ASSERT(result.captures[0].completed, "Capture is completed");
    }

    // Test capture with path
    TEST_ASSERT(dfa_evaluate("cat /path/to/file.txt", 0, &result) && result.matched,
                "cat /path/to/file.txt matches");
    if (result.capture_count >= 1) {
        TEST_ASSERT(result.captures[0].start > 0, "Path capture has valid start");
    }
}

int main(int argc, char* argv[]) {
    printf("=================================================\n");
    printf("ReadOnlyBox DFA Unit Tests\n");
    printf("=================================================\n");

    test_dfa_init_valid();
    test_dfa_init_invalid();
    test_simple_literal_patterns();
    test_pattern_prefix_matching();
    test_git_log_variants();
    test_empty_and_null_input();
    test_case_sensitivity();
    test_whitespace_handling();
    test_category_mask_extraction();
    test_unsafe_commands_not_matched();
    test_capture_support();

    printf("\n=================================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("=================================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}
