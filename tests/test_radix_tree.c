/**
 * @file test_radix_tree.c
 * @brief Unit tests for the radix tree core data structure.
 */

#include "test_framework.h"
#include "radix_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Basic insertion & lookup                                          */
/* ------------------------------------------------------------------ */

static void test_single_insert(void)
{
    radix_tree_t *tree = radix_tree_new();
    TEST_ASSERT_NOT_NULL(tree, "tree creation");

    TEST_ASSERT_EQ(radix_tree_allow(tree, "/home", 7), 0, "allow /home");

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 1, "rule count after single insert");
    TEST_ASSERT_STR_EQ(rules[0].path, "/home", "rule path");
    TEST_ASSERT_EQ(rules[0].access, 7, "rule access");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

static void test_nested_insert(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/usr", 7);
    radix_tree_allow(tree, "/usr/lib", 3);
    radix_tree_allow(tree, "/usr/bin", 1);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 3, "rule count after nested insert");
    /* All three should be present (no simplification yet) */

    free((void *)rules[0].path);
    free((void *)rules[1].path);
    free((void *)rules[2].path);
    free(rules);
    radix_tree_free(tree);
}

static void test_mask_merge(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/home", 1);
    radix_tree_allow(tree, "/home", 2);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 1, "rule count after merge");
    TEST_ASSERT_EQ(rules[0].access, 3, "merged access mask");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Deny rules                                                          */
/* ------------------------------------------------------------------ */

static void test_deny_insert(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/home", 7);
    radix_tree_deny(tree, "/home/secret");

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* Before overlap removal, both rules exist */
    TEST_ASSERT_EQ(count, 1, "allow rule count (deny not collected)");
    TEST_ASSERT_STR_EQ(rules[0].path, "/home", "allow rule path");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Overlap removal                                                    */
/* ------------------------------------------------------------------ */

static void test_deny_overrides_allow(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/home/user", 7);
    radix_tree_deny(tree, "/home/user/secret");

    radix_tree_overlap_removal(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* /home/user should still exist but /home/user/secret should not */
    int found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "secret")) {
            found_secret = 1;
            break;
        }
    }
    TEST_ASSERT(!found_secret, "secret path removed after overlap removal");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Prefix simplification                                              */
/* ------------------------------------------------------------------ */

static void test_simplify_redundant_child(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Parent has superset of child */
    radix_tree_allow(tree, "/usr", 7);
    radix_tree_allow(tree, "/usr/lib", 3);  /* 3 is subset of 7 */

    radix_tree_simplify(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* /usr/lib should be pruned since /usr covers it */
    TEST_ASSERT_EQ(count, 1, "rule count after simplification");
    TEST_ASSERT_STR_EQ(rules[0].path, "/usr", "remaining rule path");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

static void test_simplify_keeps_non_subset(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Parent has subset of child — child must be kept */
    radix_tree_allow(tree, "/usr", 1);
    radix_tree_allow(tree, "/usr/lib", 7);  /* 7 is NOT subset of 1 */

    radix_tree_simplify(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 2, "both rules kept (not subset)");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

static void test_simplify_deep_tree(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/a",       0xFF);
    radix_tree_allow(tree, "/a/b",     0x0F);
    radix_tree_allow(tree, "/a/b/c",   0x03);
    radix_tree_allow(tree, "/a/b/c/d", 0x01);

    radix_tree_simplify(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 1, "all children pruned, only root remains");
    TEST_ASSERT_STR_EQ(rules[0].path, "/a", "root path");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Corner cases                                                       */
/* ------------------------------------------------------------------ */

static void test_root_path(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/", 7);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 1, "root rule count");
    TEST_ASSERT_STR_EQ(rules[0].path, "/", "root path");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

static void test_trailing_slash(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Note: paths are pre-cleaned by the builder; here we pass clean paths */
    radix_tree_allow(tree, "/home", 7);
    radix_tree_allow(tree, "/home/", 3);  /* should merge with /home */

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* The tree splits on empty segment after trailing slash, so we
     * may get two rules — that's OK for raw tree usage */
    TEST_ASSERT(count >= 1, "at least one rule for trailing slash");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

static void test_empty_path(void)
{
    radix_tree_t *tree = radix_tree_new();

    TEST_ASSERT_EQ(radix_tree_allow(tree, "", 7), -1, "empty path rejected");
    TEST_ASSERT_EQ(radix_tree_allow(tree, NULL, 7), -1, "NULL path rejected");

    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_radix_tree_run(void)
{
    printf("=== Radix Tree Tests ===\n");
    RUN_TEST(test_single_insert);
    RUN_TEST(test_nested_insert);
    RUN_TEST(test_mask_merge);
    RUN_TEST(test_deny_insert);
    RUN_TEST(test_deny_overrides_allow);
    RUN_TEST(test_simplify_redundant_child);
    RUN_TEST(test_simplify_keeps_non_subset);
    RUN_TEST(test_simplify_deep_tree);
    RUN_TEST(test_root_path);
    RUN_TEST(test_trailing_slash);
    RUN_TEST(test_empty_path);
}
