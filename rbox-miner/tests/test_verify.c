/*
 * test_verify.c – Unit tests for the verify module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "rbox_policy_learner.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-40s ", #name); \
    if (name()) { \
        tests_passed++; \
        printf("PASS\n"); \
    } else { \
        tests_failed++; \
        printf("FAIL\n"); \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("  Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); return 0; } } while(0)
#define ASSERT_STR_EQ(a, b) do { if (strcmp((a), (b)) != 0) { printf("  String mismatch: '%s' != '%s' at %s:%d\n", (a), (b), __FILE__, __LINE__); return 0; } } while(0)

/* ============================================================
 * EXACT MATCH
 * ============================================================ */

static int test_verify_exact_match(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == CPL_OK);
    ASSERT(r.matches);
    ASSERT(r.matching_pattern != NULL);
    ASSERT_STR_EQ(r.matching_pattern, "git commit -m *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_no_match(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git push origin main", &r);
    ASSERT(err == CPL_ERR_INVALID);
    ASSERT(!r.matches);
    ASSERT(r.matching_pattern == NULL);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * WILDCARD SEMANTICS
 * ============================================================ */

static int test_verify_wildcard_single_token(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git commit -m", &r);
    ASSERT(err == CPL_ERR_INVALID);
    ASSERT(!r.matches);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_path(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "cat *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "cat /etc/passwd", &r);
    ASSERT(err == CPL_OK);
    ASSERT(r.matches);
    ASSERT(r.matching_pattern != NULL);
    ASSERT_STR_EQ(r.matching_pattern, "cat *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_number(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "head -n *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "head -n 42", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "head -n *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * EXACT LENGTH
 * ============================================================ */

static int test_verify_exact_length_shorter_command(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git commit", &r);
    ASSERT(err == CPL_ERR_INVALID);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_exact_length_longer_command(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == CPL_ERR_INVALID);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * PIPELINES
 * ============================================================ */

static int test_verify_pipeline(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "cat * | grep *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "cat /var/log/syslog | grep ERROR", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "cat * | grep *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_pipeline_no_match_wrong_cmd(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "cat * | grep *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "cat file | wc -l", &r);
    ASSERT(err == CPL_ERR_INVALID);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MULTIPLE PATTERNS
 * ============================================================ */

static int test_verify_multiple_patterns_first_match(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "ls -la *");
    cpl_policy_add(policy, "git commit -m *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "ls -la /tmp", &r);
    ASSERT(err == CPL_OK);
    ASSERT(r.matches);
    ASSERT_STR_EQ(r.matching_pattern, "ls -la *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_multiple_patterns_different_prefixes(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "docker run -it * *");
    cpl_policy_add(policy, "cat * | grep *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git commit -m fix", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "git commit -m *");

    err = cpl_policy_eval(policy, "docker run -it ubuntu bash", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "docker run -it * *");

    err = cpl_policy_eval(policy, "cat log.txt | grep error", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "cat * | grep *");

    err = cpl_policy_eval(policy, "rm -rf /", &r);
    ASSERT(err == CPL_ERR_INVALID);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * VERIFY_ALL
 * ============================================================ */

static int test_verify_all_matches(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "git commit -m fix");

    const char **matches = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_policy_verify_all(policy, "git commit -m hello", &matches, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count == 1);
    ASSERT_STR_EQ(matches[0], "git commit -m *");

    cpl_policy_free_matches(matches, count);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_all_no_match(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");

    const char **matches = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_policy_verify_all(policy, "rm -rf /", &matches, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count == 0);
    ASSERT(matches == NULL);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * EDGE CASES
 * ============================================================ */

static int test_verify_empty_policy(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git commit", &r);
    ASSERT(err == CPL_ERR_INVALID);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_redirection(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "ls > *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "ls > /tmp/out.txt", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "ls > *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_flag_value(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "gcc -o myprog main.c");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "gcc -o myprog main.c", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "gcc -o myprog main.c");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_command_with_quotes(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "echo *");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "echo \"hello world\"", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "echo *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_flag_value(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "gcc --output * main.c");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "gcc --output program main.c", &r);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(r.matching_pattern, "gcc --output * main.c");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_after_remove(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "git status");

    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git commit -m fix", &r);
    ASSERT(err == CPL_OK);

    cpl_policy_remove(policy, "git commit -m *");

    err = cpl_policy_eval(policy, "git commit -m fix", &r);
    ASSERT(err == CPL_ERR_INVALID);

    err = cpl_policy_eval(policy, "git status", &r);
    ASSERT(err == CPL_OK);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * FULL EVAL + SUGGEST + ACCEPT LOOP
 * ============================================================ */

static int test_eval_suggest_accept_loop(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git status");
    cpl_policy_add(policy, "ls -la *");

    /* 1. Verify a matching command */
    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "git status", &r);
    ASSERT(err == CPL_OK);
    ASSERT(r.matches);
    ASSERT_STR_EQ(r.matching_pattern, "git status");

    /* 2. Verify a non-matching command — should produce suggestions */
    err = cpl_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == CPL_ERR_INVALID);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);
    ASSERT(strstr(r.suggestions[0].pattern, "git") != NULL);
    ASSERT(strstr(r.suggestions[1].pattern, "git") != NULL);

    /* 3. Accept suggestion A (exact) and add to policy */
    err = cpl_policy_add(policy, r.suggestions[0].pattern);
    ASSERT(err == CPL_OK);
    ASSERT(cpl_policy_count(policy) == 3);

    /* 4. Now the same command should match */
    err = cpl_policy_eval(policy, "git commit -m hello", &r);
    ASSERT(err == CPL_OK);
    ASSERT(r.matches);

    /* 5. A completely different command should still not match */
    err = cpl_policy_eval(policy, "rm -rf /", &r);
    ASSERT(err == CPL_ERR_INVALID);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_eval_suggest_variants_loop(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git status");
    cpl_policy_add(policy, "ls -la *");

    /* Get suggestions for a new command */
    cpl_eval_result_t r;
    cpl_error_t err = cpl_policy_eval(policy, "docker run -it ubuntu bash", &r);
    ASSERT(err == CPL_ERR_INVALID);
    ASSERT(!r.matches);
    ASSERT(r.suggestion_count == 2);

    /* Tokenize the chosen suggestion for Step 2 */
    cpl_token_array_t chosen;
    cpl_normalize_typed(r.suggestions[0].pattern, &chosen);

    /* Get variants — variant 0 is always all-literals */
    cpl_expand_suggestion_t variants[3];
    size_t nv = cpl_policy_suggest_variants(policy, chosen.tokens, chosen.count, variants);
    ASSERT(nv >= 1);

    /* Variant 0 should be all-literals */
    ASSERT(strstr(variants[0].pattern, "docker") != NULL);

    /* Accept the literal variant and add to policy */
    err = cpl_policy_add(policy, variants[0].pattern);
    ASSERT(err == CPL_OK);

    /* Now the command should match */
    err = cpl_policy_eval(policy, "docker run -it ubuntu bash", &r);
    ASSERT(err == CPL_OK);
    ASSERT(r.matches);

    cpl_free_token_array(&chosen);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running verify unit tests...\n\n");

    printf("Exact match:\n");
    TEST(test_verify_exact_match);
    TEST(test_verify_no_match);

    printf("\nWildcard semantics:\n");
    TEST(test_verify_wildcard_single_token);
    TEST(test_verify_wildcard_matches_path);
    TEST(test_verify_wildcard_matches_number);

    printf("\nExact length:\n");
    TEST(test_verify_exact_length_shorter_command);
    TEST(test_verify_exact_length_longer_command);

    printf("\nPipelines:\n");
    TEST(test_verify_pipeline);
    TEST(test_verify_pipeline_no_match_wrong_cmd);

    printf("\nMultiple patterns:\n");
    TEST(test_verify_multiple_patterns_first_match);
    TEST(test_verify_multiple_patterns_different_prefixes);

    printf("\nVerify all:\n");
    TEST(test_verify_all_matches);
    TEST(test_verify_all_no_match);

    printf("\nEdge cases:\n");
    TEST(test_verify_empty_policy);
    TEST(test_verify_redirection);
    TEST(test_verify_flag_value);
    TEST(test_verify_command_with_quotes);
    TEST(test_verify_wildcard_matches_flag_value);
    TEST(test_verify_after_remove);

    printf("\nEval + suggest + accept loop:\n");
    TEST(test_eval_suggest_accept_loop);
    TEST(test_eval_suggest_variants_loop);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
