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

    /* Verify each specific path and mask */
    int found_usr = 0, found_lib = 0, found_bin = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/usr") == 0) {
            found_usr = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "/usr mask correct");
        }
        if (strcmp(rules[i].path, "/usr/lib") == 0) {
            found_lib = 1;
            TEST_ASSERT_EQ(rules[i].access, 3, "/usr/lib mask correct");
        }
        if (strcmp(rules[i].path, "/usr/bin") == 0) {
            found_bin = 1;
            TEST_ASSERT_EQ(rules[i].access, 1, "/usr/bin mask correct");
        }
    }
    TEST_ASSERT(found_usr, "found /usr");
    TEST_ASSERT(found_lib, "found /usr/lib");
    TEST_ASSERT(found_bin, "found /usr/bin");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
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
    TEST_ASSERT_STR_EQ(rules[0].path, "/home", "merged path is /home");
    TEST_ASSERT_EQ(rules[0].access, 3, "merged access mask");

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
    int found_user = 0, found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home/user") == 0) found_user = 1;
        if (strcmp(rules[i].path, "/home/user/secret") == 0) found_secret = 1;
    }
    TEST_ASSERT(found_user, "/home/user survives overlap removal");
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

    /* Verify both specific paths and masks */
    int found_usr = 0, found_lib = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/usr") == 0) {
            found_usr = 1;
            TEST_ASSERT_EQ(rules[i].access, 1, "/usr mask unchanged");
        }
        if (strcmp(rules[i].path, "/usr/lib") == 0) {
            found_lib = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "/usr/lib mask unchanged");
        }
    }
    TEST_ASSERT(found_usr, "found /usr");
    TEST_ASSERT(found_lib, "found /usr/lib");

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
    RUN_TEST(test_deny_overrides_allow);
    RUN_TEST(test_simplify_redundant_child);
    RUN_TEST(test_simplify_keeps_non_subset);
    RUN_TEST(test_simplify_deep_tree);
    RUN_TEST(test_root_path);
    RUN_TEST(test_empty_path);
}
