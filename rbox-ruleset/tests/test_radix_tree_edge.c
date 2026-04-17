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

static void test_is_denied_all_cases(void)
{
    radix_tree_t *tree;

    /* Case 1: Basic deny with parent/child checks */
    tree = radix_tree_new();
    radix_tree_deny(tree, "/home/secret");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/home/secret"), 1,
                   "exact deny path detected");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/home"), 0,
                   "parent of deny not denied");
    TEST_ASSERT_EQ(radix_tree_is_denied(tree, "/home/secret/file"), 0,
                   "child of deny not denied");
    radix_tree_free(tree);

    /* Case 2: Multiple deny entries */
    tree = radix_tree_new();
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

/* ------------------------------------------------------------------ */
/*  Arena usage: small and large scale                                */
/* ------------------------------------------------------------------ */

static void test_arena_usage(void)
{
    radix_tree_t *tree;
    size_t usage;

    /* Case 1: Small arena usage increases after inserts */
    tree = radix_tree_new();
    size_t initial = radix_tree_arena_usage(tree);
    radix_tree_allow(tree, "/home", 7);
    radix_tree_allow(tree, "/usr", 3);
    radix_tree_allow(tree, "/etc", 1);
    size_t after = radix_tree_arena_usage(tree);
    TEST_ASSERT(after > initial, "small: arena usage increased after inserts");
    radix_tree_free(tree);

    /* Case 2: Large-scale usage stays within bounds */
    tree = radix_tree_new();
    for (int i = 0; i < 1000; i++) {
        char path[128];
        snprintf(path, sizeof(path), "/base/prefix_%04d/file", i);
        radix_tree_allow(tree, path, 7);
    }
    usage = radix_tree_arena_usage(tree);
    printf("    large: 1000 paths arena usage: %.1f KB\n", (double)usage / 1024.0);
    TEST_ASSERT(usage < 1024 * 1024, "large: usage < 1 MB for 1000 paths");
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  NULL inputs and zero access                                       */
/* ------------------------------------------------------------------ */

static void test_null_and_zero_inputs(void)
{
    radix_tree_t *tree;
    landlock_rule_t *rules;
    size_t count;

    /* Case 1: NULL input handling */
    radix_tree_t *test_tree = radix_tree_new();
    TEST_ASSERT(test_tree != NULL, "null: new tree succeeds");
    radix_tree_free(test_tree);
    
    TEST_ASSERT_EQ(radix_tree_allow(NULL, "/x", 1), -1,
                   "null: allow NULL tree fails");
    TEST_ASSERT_EQ(radix_tree_allow(NULL, NULL, 1), -1,
                   "null: allow NULL tree+path fails");
    TEST_ASSERT_EQ(radix_tree_deny(NULL, "/x"), -1,
                   "null: deny NULL tree fails");
    TEST_ASSERT_EQ(radix_tree_deny(NULL, NULL), -1,
                   "null: deny NULL tree+path fails");
    TEST_ASSERT_EQ(radix_tree_is_denied(NULL, "/x"), 0,
                   "null: is_denied NULL tree returns 0");
    radix_tree_overlap_removal(NULL);   /* should not crash */
    radix_tree_simplify(NULL);          /* should not crash */
    rules = NULL; count = 0;
    radix_tree_collect_rules(NULL, &rules, &count);
    TEST_ASSERT_EQ(count, 0, "null: collect NULL tree");
    tree = radix_tree_new();
    radix_tree_collect_rules(tree, NULL, &count);
    radix_tree_free(tree);

    /* Case 2: Zero access mask not collected */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/empty", 0);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 0, "zero: zero access rule not collected");
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Long path (PATH_MAX boundary)                                      */
/* ------------------------------------------------------------------ */

static void test_path_max_boundary(void)
{
    radix_tree_t *tree;
    landlock_rule_t *rules;
    size_t count;

    /* Case 1: Path exactly PATH_MAX-1 bytes → accepted */
    tree = radix_tree_new();
    char path1[PATH_MAX];
    memset(path1, 'a', sizeof(path1) - 1);
    path1[0] = '/';
    path1[sizeof(path1) - 1] = '\0';
    int ret1 = radix_tree_allow(tree, path1, 7);
    TEST_ASSERT_EQ(ret1, 0, "path of PATH_MAX-1 bytes accepted");
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "long path: rule collected");
    TEST_ASSERT_STR_EQ(rules[0].path, path1, "long path: matches original");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 2: Path exceeding PATH_MAX → rejected */
    tree = radix_tree_new();
    char path2[PATH_MAX + 100];
    memset(path2, 'b', sizeof(path2) - 1);
    path2[0] = '/';
    path2[sizeof(path2) - 1] = '\0';
    int ret2 = radix_tree_allow(tree, path2, 7);
    TEST_ASSERT_EQ(ret2, -1, "path exceeding PATH_MAX rejected");
    radix_tree_free(tree);

    /* Case 3: Many segments (256+) capped at 256 */
    tree = radix_tree_new();
    char path3[4000];
    size_t pos = 0;
    for (unsigned int i = 0; i < 300; i++) {
        int ret = snprintf(path3 + pos, sizeof(path3) - pos, "/s%u", i);
        if (ret < 0) break;
        pos += (size_t)ret;
    }
    int ret3 = radix_tree_allow(tree, path3, 7);
    TEST_ASSERT_EQ(ret3, 0, "segments: long path accepted");
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "segments: one rule collected");
    TEST_ASSERT(strncmp(rules[0].path, "/s0/", 4) == 0,
                "segments: starts with first segment");
    size_t path_len = strlen(rules[0].path);
    TEST_ASSERT(path_len > 5 &&
                strcmp(rules[0].path + path_len - 5, "/s255") == 0,
                "segments: ends with segment 255");
    TEST_ASSERT(strstr(rules[0].path, "/s256") == NULL,
                "segments: excludes segment 256");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Allow with access == 0                                            */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_radix_tree_edge_run(void)
{
    printf("=== Radix Tree Edge-Case Tests ===\n");
    RUN_TEST(test_is_denied_all_cases);
    RUN_TEST(test_arena_usage);
    RUN_TEST(test_null_and_zero_inputs);
    RUN_TEST(test_path_max_boundary);
}
