/*
 * test_policy_compact.c - Unit tests for the compact policy module.
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
    printf("  %-45s ", #name); \
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
 * CONTEXT TESTS
 * ============================================================ */

static int test_ctx_create_free(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    ASSERT(ctx != NULL);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_ctx_intern(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    const char *a = cpl_policy_ctx_intern(ctx, "hello");
    const char *b = cpl_policy_ctx_intern(ctx, "hello");
    const char *c = cpl_policy_ctx_intern(ctx, "world");
    ASSERT(a == b);  /* same pointer for same string */
    ASSERT(a != c);
    ASSERT(strcmp(a, "hello") == 0);
    ASSERT(strcmp(c, "world") == 0);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_ctx_shared_between_policies(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *p1 = cpl_policy_new(ctx);
    cpl_policy_t *p2 = cpl_policy_new(ctx);

    cpl_policy_add(p1, "git commit -m *");
    cpl_policy_add(p2, "git status");

    /* Both policies share the same interned strings */
    const char *a = cpl_policy_ctx_intern(ctx, "git");
    /* The string "git" should already be interned by both policies */
    ASSERT(a != NULL);

    cpl_policy_free(p1);
    cpl_policy_free(p2);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * POLICY LIFECYCLE
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

static int test_policy_null_free(void)
{
    cpl_policy_free(NULL);
    return 1;
}

/* ============================================================
 * ADD PATTERNS
 * ============================================================ */

static int test_add_single(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_error_t err = cpl_policy_add(policy, "git commit");
    ASSERT(err == CPL_OK);
    ASSERT(cpl_policy_count(policy) == 1);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_add_duplicate(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git commit");
    cpl_policy_add(policy, "git commit");
    ASSERT(cpl_policy_count(policy) == 1);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_add_multiple(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git commit");
    cpl_policy_add(policy, "git status");
    cpl_policy_add(policy, "ls -la");
    ASSERT(cpl_policy_count(policy) == 3);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_add_empty(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_error_t err = cpl_policy_add(policy, "");
    ASSERT(err == CPL_ERR_INVALID);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_add_null(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_error_t err = cpl_policy_add(policy, NULL);
    ASSERT(err == CPL_ERR_INVALID);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_add_wildcards(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "cat *");
    cpl_policy_add(policy, "ls -la *");
    cpl_policy_add(policy, "head -n #n");
    ASSERT(cpl_policy_count(policy) == 3);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_add_shared_prefix(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    /* These share "git commit" prefix */
    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "git commit -a");
    cpl_policy_add(policy, "git status");
    ASSERT(cpl_policy_count(policy) == 3);

    /* Memory should be less than 3x individual patterns */
    size_t usage = cpl_policy_memory_usage(policy);
    ASSERT(usage > 0);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * REMOVE PATTERNS
 * ============================================================ */

static int test_remove(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git commit");
    cpl_policy_add(policy, "git status");
    ASSERT(cpl_policy_count(policy) == 2);

    cpl_policy_remove(policy, "git commit");
    ASSERT(cpl_policy_count(policy) == 1);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_remove_nonexistent(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git commit");
    cpl_policy_remove(policy, "git status");
    ASSERT(cpl_policy_count(policy) == 1);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * VERIFICATION
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

static int test_verify_wildcard_path(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "cat *");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "cat /etc/passwd", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "cat *");

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_verify_wildcard_number(void)
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

static int test_verify_exact_length(void)
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

static int test_verify_multiple_patterns(void)
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
    err = cpl_policy_verify(policy, "rm -rf /", &matched);
    ASSERT(err == CPL_ERR_INVALID);

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

/* ============================================================
 * VERIFY ALL
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

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

static int test_save_load(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *p1 = cpl_policy_new(ctx);

    cpl_policy_add(p1, "git commit -m *");
    cpl_policy_add(p1, "ls -la *");
    cpl_policy_add(p1, "cat * | grep *");

    cpl_error_t err = cpl_policy_save(p1, "tests/test_compact_save.tmp");
    ASSERT(err == CPL_OK);

    cpl_policy_t *p2 = cpl_policy_new(ctx);
    err = cpl_policy_load(p2, "tests/test_compact_save.tmp");
    ASSERT(err == CPL_OK);
    ASSERT(cpl_policy_count(p2) == 3);

    /* Verify loaded patterns work */
    const char *matched = NULL;
    err = cpl_policy_verify(p2, "git commit -m fix", &matched);
    ASSERT(err == CPL_OK);
    ASSERT_STR_EQ(matched, "git commit -m *");

    cpl_policy_free(p1);
    cpl_policy_free(p2);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * MEMORY USAGE
 * ============================================================ */

static int test_memory_usage(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    size_t empty = cpl_policy_memory_usage(policy);
    ASSERT(empty > 0);

    /* Add patterns with different literals at the end (100 distinct patterns) */
    for (int i = 0; i < 100; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "git commit -m msg%d", i);
        cpl_policy_add(policy, cmd);
    }
    ASSERT(cpl_policy_count(policy) == 100);

    /* Add patterns that share a wildcard tail — these collapse to 1 pattern */
    for (int i = 0; i < 50; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -la /path/to/dir%d", i);
        cpl_policy_add(policy, cmd);
    }
    /* All /path/to/dirN are #p, so they share the same wildcard node */
    ASSERT(cpl_policy_count(policy) == 101);

    size_t filled = cpl_policy_memory_usage(policy);
    ASSERT(filled > empty);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_state_count(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    ASSERT(cpl_policy_state_count(policy) == 1); /* root only */

    cpl_policy_add(policy, "git commit -m *");
    ASSERT(cpl_policy_state_count(policy) == 5); /* git, commit, -m, * */

    cpl_policy_add(policy, "git status");
    ASSERT(cpl_policy_state_count(policy) == 6); /* + status */

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * LARGE POLICY
 * ============================================================ */

static int test_large_policy(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    /* Add 1000 distinct patterns */
    for (int i = 0; i < 1000; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "cmd%d --option * /path/to/file%d", i, i);
        cpl_policy_add(policy, cmd);
    }

    ASSERT(cpl_policy_count(policy) == 1000);

    /* Verify a few */
    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "cmd42 --option something /path/to/file42", &matched);
    ASSERT(err == CPL_OK);

    err = cpl_policy_verify(policy, "cmd999 --option test /path/to/file999", &matched);
    ASSERT(err == CPL_OK);

    err = cpl_policy_verify(policy, "cmd1000 --option x /path/to/file1000", &matched);
    ASSERT(err == CPL_ERR_INVALID);

    size_t alloc = cpl_policy_memory_usage(policy);
    size_t ws = cpl_policy_working_set(policy);
    printf("  (allocated: %zu bytes, working set: %zu bytes for 1000 patterns) ", alloc, ws);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * BLOOM FILTER
 * ============================================================ */

static int test_bloom_definite_no(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git commit -m *");
    cpl_policy_add(policy, "ls -la *");

    /* "zzz" is a literal that appears in no pattern — bloom rejects */
    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "zzz commit -m hello", &matched);
    ASSERT(err == CPL_ERR_INVALID);
    ASSERT(matched == NULL);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_bloom_no_false_negatives(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "cat /etc/passwd");
    cpl_policy_add(policy, "git status");
    cpl_policy_add(policy, "ls -la *");

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "cat /etc/passwd", &matched);
    ASSERT(err == CPL_OK);

    matched = NULL;
    err = cpl_policy_verify(policy, "git status", &matched);
    ASSERT(err == CPL_OK);

    matched = NULL;
    err = cpl_policy_verify(policy, "ls -la /tmp", &matched);
    ASSERT(err == CPL_OK);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_bloom_empty_policy(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    const char *matched = NULL;
    cpl_error_t err = cpl_policy_verify(policy, "anything", &matched);
    ASSERT(err == CPL_ERR_INVALID);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

/* ============================================================
 * NFA RENDERING
 * ============================================================ */

static int test_render_nfa_basic(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git status");

    cpl_nfa_render_opts_t opts = {
        .category_mask = 0x01,
        .pattern_id_base = 1,
        .include_tags = true,
        .identifier = "test-policy",
    };

    cpl_error_t err = cpl_policy_render_nfa(policy, "tests/test_render.nfa", &opts);
    ASSERT(err == CPL_OK);

    /* Check file exists and has expected header */
    FILE *fp = fopen("tests/test_render.nfa", "r");
    ASSERT(fp != NULL);

    char line[256];
    ASSERT(fgets(line, sizeof(line), fp) != NULL);
    ASSERT(strstr(line, "NFA_ALPHABET") != NULL);
    ASSERT(fgets(line, sizeof(line), fp) != NULL);
    ASSERT(strstr(line, "Identifier: test-policy") != NULL);

    fclose(fp);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_render_nfa_wildcard(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "cat *");

    cpl_nfa_render_opts_t opts = {
        .category_mask = 0x01,
        .pattern_id_base = 1,
        .include_tags = false,
        .identifier = "wildcard-test",
    };

    cpl_error_t err = cpl_policy_render_nfa(policy, "tests/test_render_wc.nfa", &opts);
    ASSERT(err == CPL_OK);

    /* Check that VSYM_BYTE_ANY (256) appears in the file */
    FILE *fp = fopen("tests/test_render_wc.nfa", "r");
    ASSERT(fp != NULL);

    char buf[16384];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    ASSERT(strstr(buf, "Symbol 256") != NULL);

    fclose(fp);

    cpl_policy_free(policy);
    cpl_policy_ctx_free(ctx);
    return 1;
}

static int test_render_nfa_multiple_patterns(void)
{
    cpl_policy_ctx_t *ctx = cpl_policy_ctx_new();
    cpl_policy_t *policy = cpl_policy_new(ctx);

    cpl_policy_add(policy, "git commit");
    cpl_policy_add(policy, "git status");
    cpl_policy_add(policy, "ls -la");

    cpl_nfa_render_opts_t opts = {
        .category_mask = 0x01,
        .pattern_id_base = 1,
        .include_tags = true,
        .identifier = "multi-test",
    };

    cpl_error_t err = cpl_policy_render_nfa(policy, "tests/test_render_multi.nfa", &opts);
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
    printf("Running compact policy unit tests...\n\n");

    printf("Context:\n");
    TEST(test_ctx_create_free);
    TEST(test_ctx_intern);
    TEST(test_ctx_shared_between_policies);

    printf("\nLifecycle:\n");
    TEST(test_policy_create_free);
    TEST(test_policy_null_free);

    printf("\nAdd:\n");
    TEST(test_add_single);
    TEST(test_add_duplicate);
    TEST(test_add_multiple);
    TEST(test_add_empty);
    TEST(test_add_null);
    TEST(test_add_wildcards);
    TEST(test_add_shared_prefix);

    printf("\nRemove:\n");
    TEST(test_remove);
    TEST(test_remove_nonexistent);

    printf("\nVerify:\n");
    TEST(test_verify_exact_match);
    TEST(test_verify_no_match);
    TEST(test_verify_wildcard_path);
    TEST(test_verify_wildcard_number);
    TEST(test_verify_exact_length);
    TEST(test_verify_pipeline);
    TEST(test_verify_multiple_patterns);
    TEST(test_verify_flag_value);

    printf("\nVerify all:\n");
    TEST(test_verify_all_matches);
    TEST(test_verify_all_no_match);

    printf("\nSerialization:\n");
    TEST(test_save_load);

    printf("\nMemory:\n");
    TEST(test_memory_usage);
    TEST(test_state_count);

    printf("\nLarge policy:\n");
    TEST(test_large_policy);

    printf("\nNFA rendering:\n");
    TEST(test_render_nfa_basic);
    TEST(test_render_nfa_wildcard);
    TEST(test_render_nfa_multiple_patterns);

    printf("\nBloom filter:\n");
    TEST(test_bloom_definite_no);
    TEST(test_bloom_no_false_negatives);
    TEST(test_bloom_empty_policy);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
