/**
 * @file test_radix_tree_edge.c
 * @brief Edge-case tests for the radix tree core.
 */

#include "test_framework.h"
#include "radix_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ------------------------------------------------------------------ */
/*  radix_tree_is_denied direct tests                                  */
/* ------------------------------------------------------------------ */

static void test_is_denied_basic(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_deny(tree, "/home/secret");

    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/home/secret"), 1,
                   "exact deny path detected");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/home"), 0,
                   "parent of deny not denied");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/home/secret/file"), 0,
                   "child of deny not denied");

    radix_tree_free(tree);
}

static void test_is_denied_multiple(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_deny(tree, "/a");
    radix_tree_deny(tree, "/b/c");
    radix_tree_deny(tree, "/d/e/f");

    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/a"), 1, "/a denied");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/b/c"), 1, "/b/c denied");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/d/e/f"), 1, "/d/e/f denied");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/b"), 0, "/b not denied");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/x"), 0, "/x not denied");

    radix_tree_free(tree);
}

static void test_is_denied_null_inputs(void)
{
    radix_tree_t *tree = radix_tree_new();

    TEST_ASSERT_EQ(radix_tree_is_denied(NULL, "/x"), 0,
                   "NULL tree returns 0");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, NULL), 0,
                   "NULL path returns 0");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, ""), 0,
                   "empty path returns 0");

    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  radix_tree_arena_usage                                             */
/* ------------------------------------------------------------------ */

static void test_arena_usage_basic(void)
{
    radix_tree_t *tree = radix_tree_new();

    size_t initial = radix_tree_arena_usage(tree);

    radix_tree_allow(tree, "/home", 7);
    radix_tree_allow(tree, "/usr", 3);
    radix_tree_allow(tree, "/etc", 1);

    size_t after = radix_tree_arena_usage(tree);
    TEST_ASSERT(after > initial, "arena usage increased after inserts");

    radix_tree_free(tree);
}

static void test_arena_usage_null(void)
{
    TEST_ASSERT_EQ(radix_tree_arena_usage(NULL), 0,
                   "NULL tree returns 0 usage");
}

/* ------------------------------------------------------------------ */
/*  NULL input tests                                                   */
/* ------------------------------------------------------------------ */

static void test_null_inputs(void)
{
    TEST_ASSERT(radix_tree_new() != NULL, "new tree succeeds");

    TEST_ASSERT_EQ(radix_tree_allow(NULL, "/x", 1), -1,
                   "allow NULL tree fails");
    TEST_ASSERT_EQ(radix_tree_allow(NULL, NULL, 1), -1,
                   "allow NULL tree+path fails");
    TEST_ASSERT_EQ(radix_tree_deny(NULL, "/x"), -1,
                   "deny NULL tree fails");
    TEST_ASSERT_EQ(radix_tree_deny(NULL, NULL), -1,
                   "deny NULL tree+path fails");
    TEST_ASSERT_EQ(radix_tree_is_denied(NULL, "/x"), 0,
                   "is_denied NULL tree returns 0");

    radix_tree_overlap_removal(NULL);   /* should not crash */
    radix_tree_simplify(NULL);          /* should not crash */

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(NULL, &rules, &count);
    TEST_ASSERT_EQ(count, 0, "collect NULL tree");

    radix_tree_t *tree = radix_tree_new();
    radix_tree_collect_rules(tree, NULL, &count);
    radix_tree_free(tree);
}

static void test_free_null(void)
{
    radix_tree_free(NULL);  /* should not crash */
}

/* ------------------------------------------------------------------ */
/*  Long path (PATH_MAX boundary)                                      */
/* ------------------------------------------------------------------ */

static void test_path_max_length(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Build a path exactly PATH_MAX-1 bytes long (fits in buffer) */
    char path[PATH_MAX];
    memset(path, 'a', sizeof(path) - 1);
    path[0] = '/';
    path[sizeof(path) - 1] = '\0';

    int ret = radix_tree_allow(tree, path, 7);
    TEST_ASSERT_EQ(ret, 0, "path of PATH_MAX-1 bytes accepted");

    /* Verify the rule was collected correctly */
    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "long path rule collected");
    TEST_ASSERT_STR_EQ(rules[0].path, path, "collected path matches original");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

static void test_path_too_long(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Build a path exceeding PATH_MAX */
    char path[PATH_MAX + 100];
    memset(path, 'b', sizeof(path) - 1);
    path[0] = '/';
    path[sizeof(path) - 1] = '\0';

    int ret = radix_tree_allow(tree, path, 7);
    TEST_ASSERT_EQ(ret, -1, "path exceeding PATH_MAX rejected");

    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Many segments (256+) hitting the split_path limit                  */
/* ------------------------------------------------------------------ */

static void test_many_segments(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Build a path with 300 segments (split_path caps at 256) */
    char path[4000];
    int pos = 0;
    for (int i = 0; i < 300; i++) {
        pos += snprintf(path + pos, sizeof(path) - pos, "/s%d", i);
    }

    int ret = radix_tree_allow(tree, path, 7);
    TEST_ASSERT_EQ(ret, 0, "long segment path accepted (capped at 256)");

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "one rule collected (truncated path)");

    /* The collected path should start with "/s0/s1/..." and NOT end with
     * the full 300 segments — it should be truncated at segment 256 */
    TEST_ASSERT(strstr(rules[0].path, "/s0") != NULL,
                "collected path starts with first segment");
    /* The last included segment index is 255 (0-based), so /s255 */
    TEST_ASSERT(strstr(rules[0].path, "/s255") != NULL,
                "collected path includes segment 255");
    /* Segment 256 should NOT be in the collected path */
    TEST_ASSERT(strstr(rules[0].path, "/s256") == NULL,
                "collected path excludes segment 256 (capped at 256)");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Allow with access == 0                                            */
/* ------------------------------------------------------------------ */

static void test_allow_zero_access(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/empty", 0);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* access == 0 → not collected (access_mask != 0 check) */
    TEST_ASSERT_EQ(count, 0, "zero access rule not collected");

    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Large-scale arena usage measurement                                */
/* ------------------------------------------------------------------ */

static void test_large_arena_usage(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Insert 1000 paths */
    for (int i = 0; i < 1000; i++) {
        char path[128];
        snprintf(path, sizeof(path), "/base/prefix_%04d/file", i);
        radix_tree_allow(tree, path, 7);
    }

    size_t usage = radix_tree_arena_usage(tree);
    printf("    1000 paths arena usage: %.1f KB\n", usage / 1024.0);

    /* Reasonable upper bound: < 1 MB for 1000 paths */
    TEST_ASSERT(usage < 1024 * 1024, "arena usage < 1 MB for 1000 paths");

    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_radix_tree_edge_run(void)
{
    printf("=== Radix Tree Edge-Case Tests ===\n");
    RUN_TEST(test_is_denied_basic);
    RUN_TEST(test_is_denied_multiple);
    RUN_TEST(test_is_denied_null_inputs);
    RUN_TEST(test_arena_usage_basic);
    RUN_TEST(test_arena_usage_null);
    RUN_TEST(test_null_inputs);
    RUN_TEST(test_free_null);
    RUN_TEST(test_path_max_length);
    RUN_TEST(test_path_too_long);
    RUN_TEST(test_many_segments);
    RUN_TEST(test_allow_zero_access);
    RUN_TEST(test_large_arena_usage);
}
