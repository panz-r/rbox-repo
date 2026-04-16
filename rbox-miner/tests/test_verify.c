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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "git commit -m hello", &matched);
    ASSERT(err == CPL_OK);
    ASSERT(matched != NULL);
    ASSERT_STR_EQ(matched, "git commit -m *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_no_match(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "git push origin main", &matched);
    ASSERT(err == CPL_ERR_INVALID);
    ASSERT(matched == NULL);

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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "git commit -m", &matched);
    ASSERT(err == CPL_ERR_INVALID);
    ASSERT(matched == NULL);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_path(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "cat *");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "cat /etc/passwd", &matched);
    ASSERT(err == CPL_OK);
    ASSERT(matched != NULL);
    ASSERT_STR_EQ(matched, "cat *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_number(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "head -n *");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "head -n 42", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "head -n *");

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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "git commit", &matched);
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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "git commit -m hello", &matched);
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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "cat /var/log/syslog | grep ERROR", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "cat * | grep *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_pipeline_no_match_wrong_cmd(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "cat * | grep *");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "cat file | wc -l", &matched);
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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "ls -la /tmp", &matched);
    ASSERT(err == CPL_OK);
    ASSERT(matched != NULL);
    ASSERT_STR_EQ(matched, "ls -la *");

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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "git commit -m fix", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "git commit -m *");

    matched = NULL;
    err = cpl_policy_verify(policy, "docker run -it ubuntu bash", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "docker run -it * *");

    matched = NULL;
    err = cpl_policy_verify(policy, "cat log.txt | grep error", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "cat * | grep *");

    matched = NULL;
    err = cpl_policy_verify(policy, "rm -rf /", &matched);
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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "git commit", &matched);
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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "ls > /tmp/out.txt", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "ls > *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_flag_value(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "gcc -o myprog main.c");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "gcc -o myprog main.c", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "gcc -o myprog main.c");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_command_with_quotes(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "echo *");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "echo \"hello world\"", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "echo *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_matches_flag_value(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "gcc --output * main.c");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "gcc --output program main.c", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "gcc --output * main.c");

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

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "git commit -m fix", &matched);
    ASSERT(err == CPL_OK);

    cpl_policy_remove(policy, "git commit -m *");

    matched = NULL;
    err = cpl_policy_verify(policy, "git commit -m fix", &matched);
    ASSERT(err == CPL_ERR_INVALID);

    matched = NULL;
    err = cpl_policy_verify(policy, "git status", &matched);
    ASSERT(err == CPL_OK);

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

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
