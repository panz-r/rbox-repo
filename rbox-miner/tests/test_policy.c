/*
 * test_policy.c – Unit tests for the policy module.
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
 * LIFECYCLE
 * ============================================================ */

static int test_policy_create_free(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    ASSERT(policy != NULL);
    ASSERT(cpl_policy_count(policy) == 0);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_free_null(void)
{
    cpl_policy_free(NULL);
    return 1;
}

/* ============================================================
 * ADD
 * ============================================================ */

static int test_policy_add_single(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_error_t err = cpl_policy_add(policy, "git commit -m *");
    ASSERT(err == CPL_OK);
    ASSERT(cpl_policy_count(policy) == 1);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_duplicate(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "git commit -m *");
    ASSERT(cpl_policy_count(policy) == 1);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_multiple(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "ls -l *");
    cpl_policy_add(policy, "cat * | grep *");
    ASSERT(cpl_policy_count(policy) == 3);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_empty(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_error_t err = cpl_policy_add(policy, "");
    ASSERT(err == CPL_ERR_INVALID);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_null(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_error_t err = cpl_policy_add(policy, NULL);
    ASSERT(err == CPL_ERR_INVALID);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_add_prefix_patterns(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git");
    cpl_policy_add(policy, "git commit");
    cpl_policy_add(policy, "git commit -m *");
    ASSERT(cpl_policy_count(policy) == 3);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * REMOVE
 * ============================================================ */

static int test_policy_remove(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "ls -l *");
    ASSERT(cpl_policy_count(policy) == 2);

    cpl_error_t err = cpl_policy_remove(policy, "git commit -m *");
    ASSERT(err == CPL_OK);
    ASSERT(cpl_policy_count(policy) == 1);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_remove_nonexistent(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");
    cpl_error_t err = cpl_policy_remove(policy, "docker run *");
    ASSERT(err == CPL_OK);
    ASSERT(cpl_policy_count(policy) == 1);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_remove_pruning(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git commit -m *");
    ASSERT(cpl_policy_count(policy) == 1);

    cpl_policy_remove(policy, "git commit -m *");
    ASSERT(cpl_policy_count(policy) == 0);
    ASSERT(policy != NULL);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_remove_partial_prefix(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_policy_add(policy, "git");
    cpl_policy_add(policy, "git commit");
    cpl_policy_add(policy, "git commit -m *");
    ASSERT(cpl_policy_count(policy) == 3);

    cpl_policy_remove(policy, "git commit");
    ASSERT(cpl_policy_count(policy) == 2);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

static int test_policy_save_load(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy1 = cpl_policy_new(ctx);
    cpl_policy_add(policy1, "git commit -m *");
    cpl_policy_add(policy1, "ls -l *");
    cpl_policy_add(policy1, "cat * | grep *");

    cpl_error_t err = cpl_policy_save(policy1, "tests/test_policy_save.tmp");
    ASSERT(err == CPL_OK);

    cpl_policy_t *policy2 = cpl_policy_new(ctx);
    err = cpl_policy_load(policy2, "tests/test_policy_save.tmp");
    ASSERT(err == CPL_OK);

    ASSERT(cpl_policy_count(policy2) == 3);

    cpl_policy_free(policy1);
    cpl_policy_free(policy2);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_load_empty(void)
{
    FILE *fp = fopen("tests/test_policy_empty.tmp", "w");
    ASSERT(fp != NULL);
    fclose(fp);

    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);
    cpl_error_t err = cpl_policy_load(policy, "tests/test_policy_empty.tmp");
    ASSERT(err == CPL_OK);
    ASSERT(cpl_policy_count(policy) == 0);
    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_policy_roundtrip_many_patterns(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy1 = cpl_policy_new(ctx);
    for (int i = 0; i < 50; i++) {
        char pattern[128];
        snprintf(pattern, sizeof(pattern), "cmd%d arg%d *", i, i);
        cpl_policy_add(policy1, pattern);
    }
    ASSERT(cpl_policy_count(policy1) == 50);

    cpl_policy_save(policy1, "tests/test_policy_many.tmp");

    cpl_policy_t *policy2 = cpl_policy_new(ctx);
    cpl_policy_load(policy2, "tests/test_policy_many.tmp");
    ASSERT(cpl_policy_count(policy2) == 50);

    cpl_policy_free(policy1);
    cpl_policy_free(policy2);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running policy unit tests...\n\n");

    printf("Lifecycle:\n");
    TEST(test_policy_create_free);
    TEST(test_policy_free_null);

    printf("\nAdd:\n");
    TEST(test_policy_add_single);
    TEST(test_policy_add_duplicate);
    TEST(test_policy_add_multiple);
    TEST(test_policy_add_empty);
    TEST(test_policy_add_null);
    TEST(test_policy_add_prefix_patterns);

    printf("\nRemove:\n");
    TEST(test_policy_remove);
    TEST(test_policy_remove_nonexistent);
    TEST(test_policy_remove_pruning);
    TEST(test_policy_remove_partial_prefix);

    printf("\nSerialisation:\n");
    TEST(test_policy_save_load);
    TEST(test_policy_load_empty);
    TEST(test_policy_roundtrip_many_patterns);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
