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

static void init_dfa(void) {
    FILE* f = fopen("readonlybox.dfa", "rb");
    if (f == NULL) {
        printf("ERROR: Cannot open DFA file\n");
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    dfa_init(data, size);
}

static void test_quantifier_edge_cases(void) {
    printf("\n=== Quantifier Edge Cases ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("a**", 0, &result) && result.matched, "a** evaluates");
    TEST_ASSERT(dfa_evaluate("a*b*", 0, &result) && result.matched, "a*b* matches");
    TEST_ASSERT(dfa_evaluate("x*", 0, &result) && result.matched, "x* matches empty");
    TEST_ASSERT(dfa_evaluate("x+", 0, &result) && result.matched, "x+ matches single");
}

static void test_alternation_complex(void) {
    printf("\n=== Complex Alternation Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("alpha", 0, &result) && result.matched, "alpha matches");
    TEST_ASSERT(dfa_evaluate("bravo", 0, &result) && result.matched, "bravo matches");
    TEST_ASSERT(dfa_evaluate("charlie", 0, &result) && result.matched, "charlie matches");
    TEST_ASSERT(!(dfa_evaluate("zeta", 0, &result) && result.matched), "zeta doesnt match");
}

static void test_whitespace_variations(void) {
    printf("\n=== Whitespace Handling Variations ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("git status", 0, &result) && result.matched, "git status");
    TEST_ASSERT(!(dfa_evaluate(" git status", 0, &result) && result.matched), "leading space fails");
    TEST_ASSERT(!(dfa_evaluate("git status ", 0, &result) && result.matched), "trailing space fails");
}

static void test_wildcard_patterns(void) {
    printf("\n=== Wildcard Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("ls *", 0, &result) && result.matched, "ls * matches");
    TEST_ASSERT(dfa_evaluate("ls *.txt", 0, &result) && result.matched, "ls *.txt matches");
    TEST_ASSERT(!(dfa_evaluate("rm *", 0, &result) && result.matched), "rm * blocked");
    TEST_ASSERT(dfa_evaluate("cat *.*", 0, &result) && result.matched, "cat *.* matches");
}

static void test_negative_extended(void) {
    printf("\n=== Extended Negative Test Cases ===\n");
    dfa_result_t result;
    TEST_ASSERT(!(dfa_evaluate("rm -rf /", 0, &result) && result.matched), "rm -rf / blocked");
    TEST_ASSERT(!(dfa_evaluate("rm -rf /tmp", 0, &result) && result.matched), "rm -rf /tmp blocked");
    TEST_ASSERT(!(dfa_evaluate("chmod 777 file", 0, &result) && result.matched), "chmod 777 blocked");
    TEST_ASSERT(!(dfa_evaluate("git push origin main", 0, &result) && result.matched), "git push blocked");
    TEST_ASSERT(!(dfa_evaluate("git commit -m fix", 0, &result) && result.matched), "git commit blocked");
    TEST_ASSERT(!(dfa_evaluate("sudo rm -rf /", 0, &result) && result.matched), "sudo rm blocked");
}

static void test_case_extended(void) {
    printf("\n=== Extended Case Sensitivity ===\n");
    dfa_result_t result;
    TEST_ASSERT(!(dfa_evaluate("Git Status", 0, &result) && result.matched), "mixed case fails");
    TEST_ASSERT(!(dfa_evaluate("GIT STATUS", 0, &result) && result.matched), "uppercase fails");
    TEST_ASSERT(!(dfa_evaluate("gIt StAtUs", 0, &result) && result.matched), "random case fails");
}

static void test_path_variations(void) {
    printf("\n=== Path Pattern Variations ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("cat /etc/passwd", 0, &result) && result.matched, "absolute path");
    TEST_ASSERT(dfa_evaluate("cat /var/log/syslog", 0, &result) && result.matched, "log path");
    TEST_ASSERT(dfa_evaluate("cat /home/user/file.txt", 0, &result) && result.matched, "deep path");
    TEST_ASSERT(dfa_evaluate("cat ./file.txt", 0, &result) && result.matched, "relative ./path");
    TEST_ASSERT(dfa_evaluate("cat ../file.txt", 0, &result) && result.matched, "relative ../path");
}

static void test_git_subcommands(void) {
    printf("\n=== Git Subcommand Variations ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("git status", 0, &result) && result.matched, "status");
    TEST_ASSERT(dfa_evaluate("git log", 0, &result) && result.matched, "log");
    TEST_ASSERT(dfa_evaluate("git diff", 0, &result) && result.matched, "diff");
    TEST_ASSERT(dfa_evaluate("git show", 0, &result) && result.matched, "show");
    TEST_ASSERT(dfa_evaluate("git branch", 0, &result) && result.matched, "branch");
    TEST_ASSERT(dfa_evaluate("git tag", 0, &result) && result.matched, "tag");
    TEST_ASSERT(dfa_evaluate("git stash list", 0, &result) && result.matched, "stash list");
    TEST_ASSERT(dfa_evaluate("git remote -v", 0, &result) && result.matched, "remote -v");
    TEST_ASSERT(dfa_evaluate("git remote get-url origin", 0, &result) && result.matched, "remote get-url");
}

static void test_numeric_args(void) {
    printf("\n=== Numeric Argument Variations ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("git log -n 1", 0, &result) && result.matched, "-n 1");
    TEST_ASSERT(dfa_evaluate("git log -n 5", 0, &result) && result.matched, "-n 5");
    TEST_ASSERT(dfa_evaluate("git log -n 10", 0, &result) && result.matched, "-n 10");
    TEST_ASSERT(dfa_evaluate("git log -n 100", 0, &result) && result.matched, "-n 100");
    TEST_ASSERT(dfa_evaluate("git log -n 1000", 0, &result) && result.matched, "-n 1000");
    TEST_ASSERT(dfa_evaluate("git log -n 99999", 0, &result) && result.matched, "-n 99999");
}

static void test_which_command(void) {
    printf("\n=== Which Command Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("which socat", 0, &result) && result.matched, "which socat");
    TEST_ASSERT(dfa_evaluate("which python3", 0, &result) && result.matched, "which python3");
    TEST_ASSERT(dfa_evaluate("which gcc", 0, &result) && result.matched, "which gcc");
}

static void test_ls_patterns(void) {
    printf("\n=== LS Command Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("ls", 0, &result) && result.matched, "ls alone");
    TEST_ASSERT(dfa_evaluate("ls -l", 0, &result) && result.matched, "ls -l");
    TEST_ASSERT(dfa_evaluate("ls -la", 0, &result) && result.matched, "ls -la");
    TEST_ASSERT(dfa_evaluate("ls -lh", 0, &result) && result.matched, "ls -lh");
    TEST_ASSERT(dfa_evaluate("ls -R", 0, &result) && result.matched, "ls -R");
    TEST_ASSERT(dfa_evaluate("ls -a", 0, &result) && result.matched, "ls -a");
}

static void test_cat_patterns(void) {
    printf("\n=== CAT Command Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("cat file.txt", 0, &result) && result.matched, "cat file");
    TEST_ASSERT(dfa_evaluate("cat /etc/hosts", 0, &result) && result.matched, "cat /etc/hosts");
    TEST_ASSERT(dfa_evaluate("cat file1 file2", 0, &result) && result.matched, "cat multiple");
}

static void test_ps_patterns(void) {
    printf("\n=== PS Command Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("ps", 0, &result) && result.matched, "ps alone");
    TEST_ASSERT(dfa_evaluate("ps aux", 0, &result) && result.matched, "ps aux");
    TEST_ASSERT(dfa_evaluate("ps -ef", 0, &result) && result.matched, "ps -ef");
    TEST_ASSERT(dfa_evaluate("ps auxww", 0, &result) && result.matched, "ps auxww");
}

static void test_df_patterns(void) {
    printf("\n=== DF Command Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("df", 0, &result) && result.matched, "df alone");
    TEST_ASSERT(dfa_evaluate("df -h", 0, &result) && result.matched, "df -h");
    TEST_ASSERT(dfa_evaluate("df -T", 0, &result) && result.matched, "df -T");
    TEST_ASSERT(dfa_evaluate("df -hT", 0, &result) && result.matched, "df -hT");
}

static void test_du_patterns(void) {
    printf("\n=== DU Command Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("du", 0, &result) && result.matched, "du alone");
    TEST_ASSERT(dfa_evaluate("du -h", 0, &result) && result.matched, "du -h");
    TEST_ASSERT(dfa_evaluate("du -sh", 0, &result) && result.matched, "du -sh");
}

static void test_env_patterns(void) {
    printf("\n=== ENV Command Patterns ===\n");
    dfa_result_t result;
    TEST_ASSERT(dfa_evaluate("env", 0, &result) && result.matched, "env alone");
    TEST_ASSERT(dfa_evaluate("env -i", 0, &result) && result.matched, "env -i");
}

static void test_env_patterns(void);
static void run_all_extended_tests(void);

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    run_all_extended_tests();
    
    printf("\n=================================================\n");
    printf("Extended Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("=================================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}

// ============================================================================
// Capture Support Tests - These tests will fail until full capture 
// implementation is complete, but provide feedback on progress
// ============================================================================

static void test_capture_api_basic(void) {
    printf("\n=== Capture API Basic Tests ===\n");
    dfa_result_t result;
    
    // Test dfa_get_capture_count on a non-capture pattern
    bool eval_ok = dfa_evaluate("git status", 0, &result);
    if (eval_ok && result.matched) {
        int count = dfa_get_capture_count(&result);
        printf("  INFO: git status capture_count=%d (expected 0)\n", count);
        TEST_ASSERT(count == 0, "No captures for git status pattern");
    } else {
        printf("  INFO: git status didn't match, skipping capture test\n");
    }
    
    // Test dfa_get_capture_by_index on empty captures
    size_t start = 999, length = 999;
    bool got = dfa_get_capture_by_index(&result, 0, &start, &length);
    TEST_ASSERT(got == false, "dfa_get_capture_by_index returns false for empty");
    
    // Test with cat pattern (has FILENAME fragment but no capture tags)
    eval_ok = dfa_evaluate("cat test.txt", 0, &result);
    if (eval_ok && result.matched) {
        int count = dfa_get_capture_count(&result);
        printf("  INFO: cat test.txt capture_count=%d\n", count);
    }
}

static void test_capture_with_limit_zero(void) {
    printf("\n=== Capture Limit Zero Tests ===\n");
    dfa_result_t result;
    
    // Evaluate with max_captures=0
    bool eval_ok = dfa_evaluate_with_limit("git status", 0, &result, 0);
    TEST_ASSERT(eval_ok, "dfa_evaluate_with_limit returns true");
    TEST_ASSERT(result.matched, "Pattern matches even with max_captures=0");
    TEST_ASSERT(result.capture_count == 0, "No captures tracked when max_captures=0");
    
    int count = dfa_get_capture_count(&result);
    TEST_ASSERT(count == 0, "dfa_get_capture_count returns 0 for limit=0");
}

static void test_capture_with_limit_small(void) {
    printf("\n=== Capture Limit Small Values Tests ===\n");
    dfa_result_t result;
    
    // Test with very small limit
    bool eval_ok = dfa_evaluate_with_limit("git status", 0, &result, 1);
    TEST_ASSERT(eval_ok, "dfa_evaluate_with_limit(1) returns true");
    TEST_ASSERT(result.matched, "Pattern matches with max_captures=1");
    
    eval_ok = dfa_evaluate_with_limit("git status", 0, &result, 2);
    TEST_ASSERT(eval_ok, "dfa_evaluate_with_limit(2) returns true");
    
    eval_ok = dfa_evaluate_with_limit("git status", 0, &result, 5);
    TEST_ASSERT(eval_ok, "dfa_evaluate_with_limit(5) returns true");
}

static void test_capture_with_limit_large(void) {
    printf("\n=== Capture Limit Large Values Tests ===\n");
    dfa_result_t result;
    
    // Test with large limit
    bool eval_ok = dfa_evaluate_with_limit("git status", 0, &result, 100);
    TEST_ASSERT(eval_ok, "dfa_evaluate_with_limit(100) returns true");
    TEST_ASSERT(result.matched, "Pattern matches with max_captures=100");
    
    // Test with very large limit
    eval_ok = dfa_evaluate_with_limit("git status", 0, &result, 10000);
    TEST_ASSERT(eval_ok, "dfa_evaluate_with_limit(10000) returns true");
}

static void test_capture_with_limit_negative(void) {
    printf("\n=== Capture Limit Negative Values Tests ===\n");
    dfa_result_t result;
    
    // Test with negative limit (should behave like unlimited)
    bool eval_ok = dfa_evaluate_with_limit("git status", 0, &result, -1);
    TEST_ASSERT(eval_ok, "dfa_evaluate_with_limit(-1) returns true");
    TEST_ASSERT(result.matched, "Pattern matches with max_captures=-1");
    
    eval_ok = dfa_evaluate_with_limit("git status", 0, &result, -100);
    TEST_ASSERT(eval_ok, "dfa_evaluate_with_limit(-100) returns true");
}

static void test_capture_compare_apis(void) {
    printf("\n=== Compare Standard vs Limited API ===\n");
    dfa_result_t result_std, result_lim;
    
    bool ok_std = dfa_evaluate("git status", 0, &result_std);
    bool ok_lim = dfa_evaluate_with_limit("git status", 0, &result_lim, 10);
    
    TEST_ASSERT(ok_std == ok_lim, "Both APIs return same success");
    TEST_ASSERT(result_std.matched == result_lim.matched, "Both report same match");
    TEST_ASSERT(result_std.matched_length == result_lim.matched_length, "Both report same length");
    TEST_ASSERT(result_std.category == result_lim.category, "Both report same category");
}

static void test_capture_cat_filename(void) {
    printf("\n=== Capture CAT Filename Tests ===\n");
    dfa_result_t result;
    
    // Test cat with simple filename
    bool ok = dfa_evaluate("cat test.txt", 0, &result);
    if (ok && result.matched) {
        printf("  INFO: cat test.txt matched len=%zu caps=%d\n", 
               result.matched_length, result.capture_count);
    } else {
        printf("  INFO: cat test.txt did not match\n");
    }
    
    // Test cat with path
    ok = dfa_evaluate("cat /path/to/file.txt", 0, &result);
    if (ok && result.matched) {
        printf("  INFO: cat /path/to/file.txt matched len=%zu caps=%d\n",
               result.matched_length, result.capture_count);
    }
    
    // Test with limit
    dfa_result_t result_lim;
    ok = dfa_evaluate_with_limit("cat test.txt", 0, &result_lim, 5);
    if (ok && result_lim.matched) {
        printf("  INFO: with limit=5, caps=%d\n", result_lim.capture_count);
    }
}

static void test_capture_git_args(void) {
    printf("\n=== Capture GIT Argument Tests ===\n");
    dfa_result_t result;
    
    // Git log with count
    bool ok = dfa_evaluate("git log -n 10", 0, &result);
    if (ok && result.matched) {
        printf("  INFO: git log -n 10 matched caps=%d\n", result.capture_count);
    }
    
    // Git branch with all
    ok = dfa_evaluate("git branch -a", 0, &result);
    if (ok && result.matched) {
        printf("  INFO: git branch -a matched caps=%d\n", result.capture_count);
    }
    
    // Git remote get-url
    ok = dfa_evaluate("git remote get-url origin", 0, &result);
    if (ok && result.matched) {
        printf("  INFO: git remote get-url origin matched caps=%d\n", result.capture_count);
    }
}

static void test_capture_boundary_conditions(void) {
    printf("\n=== Capture Boundary Condition Tests ===\n");
    dfa_result_t result;
    
    // Empty input
    bool ok = dfa_evaluate("", 0, &result);
    int count = dfa_get_capture_count(&result);
    printf("  INFO: empty input capture_count=%d\n", count);
    
    // Single char
    ok = dfa_evaluate("a", 0, &result);
    if (ok) {
        int count = dfa_get_capture_count(&result);
        printf("  INFO: single 'a' capture_count=%d\n", count);
    }
    
    // Very long command (stress test)
    char long_cmd[256];
    memset(long_cmd, 'a', 200);
    strcpy(long_cmd + 200, " git status");
    ok = dfa_evaluate(long_cmd, 0, &result);
    printf("  INFO: long command matched=%s len=%zu\n", 
           result.matched ? "yes" : "no", result.matched_length);
}

static void test_capture_api_errors(void) {
    printf("\n=== Capture API Error Handling Tests ===\n");
    dfa_result_t result;
    size_t start, length;
    
    // Test get_capture_by_index with invalid index
    dfa_evaluate("git status", 0, &result);
    bool ok = dfa_get_capture_by_index(&result, -1, &start, &length);
    TEST_ASSERT(!ok, "Index -1 returns false");
    
    ok = dfa_get_capture_by_index(&result, 100, &start, &length);
    TEST_ASSERT(!ok, "Index beyond count returns false");
    
    // Test get_capture_count with NULL result
    int count = dfa_get_capture_count(NULL);
    TEST_ASSERT(count == -1, "NULL result returns -1");
}

// New test runner that includes capture tests
static void run_all_extended_tests(void) {
    printf("=================================================\n");
    printf("ReadOnlyBox DFA Extended Unit Tests (with Captures)\n");
    printf("=================================================\n");
    
    init_dfa();

    // Original extended tests
    test_quantifier_edge_cases();
    test_alternation_complex();
    test_whitespace_variations();
    test_wildcard_patterns();
    test_negative_extended();
    test_case_extended();
    test_path_variations();
    test_git_subcommands();
    test_numeric_args();
    test_which_command();
    test_ls_patterns();
    test_cat_patterns();
    test_ps_patterns();
    test_df_patterns();
    test_du_patterns();
    test_env_patterns();
    
    // NEW: Capture tests
    printf("\n--- CAPTURE TESTS (expect some failures) ---\n");
    test_capture_api_basic();
    test_capture_with_limit_zero();
    test_capture_with_limit_small();
    test_capture_with_limit_large();
    test_capture_with_limit_negative();
    test_capture_compare_apis();
    test_capture_cat_filename();
    test_capture_git_args();
    test_capture_boundary_conditions();
    test_capture_api_errors();
}
