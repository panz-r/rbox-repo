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
/*  Basic insertion, merge, and overlap removal                       */
/* ------------------------------------------------------------------ */

static void test_insert_and_merge(void)
{
    radix_tree_t *tree;
    landlock_rule_t *rules;
    size_t count;
    int found_usr, found_lib, found_bin;

    /* Case 1: Single insert */
    tree = radix_tree_new();
    TEST_ASSERT_NOT_NULL(tree, "insert: tree creation");
    TEST_ASSERT_EQ(radix_tree_allow(tree, "/home", 7), 0, "insert: allow /home");
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "insert: single rule count");
    TEST_ASSERT_STR_EQ(rules[0].path, "/home", "insert: rule path");
    TEST_ASSERT_EQ(rules[0].access, 7, "insert: rule access");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 2: Nested insert */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/usr", 7);
    radix_tree_allow(tree, "/usr/lib", 3);
    radix_tree_allow(tree, "/usr/bin", 1);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 3, "nested: rule count");
    found_usr = 0; found_lib = 0; found_bin = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/usr") == 0) {
            found_usr = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "nested: /usr mask correct");
        }
        if (strcmp(rules[i].path, "/usr/lib") == 0) {
            found_lib = 1;
            TEST_ASSERT_EQ(rules[i].access, 3, "nested: /usr/lib mask correct");
        }
        if (strcmp(rules[i].path, "/usr/bin") == 0) {
            found_bin = 1;
            TEST_ASSERT_EQ(rules[i].access, 1, "nested: /usr/bin mask correct");
        }
    }
    TEST_ASSERT(found_usr, "nested: found /usr");
    TEST_ASSERT(found_lib, "nested: found /usr/lib");
    TEST_ASSERT(found_bin, "nested: found /usr/bin");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 3: Mask merge on same path */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/home", 1);
    radix_tree_allow(tree, "/home", 2);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "merge: single merged rule");
    TEST_ASSERT_STR_EQ(rules[0].path, "/home", "merge: path is /home");
    TEST_ASSERT_EQ(rules[0].access, 3, "merge: masks OR'd together");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 4: Deny overrides allow in subtree */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/home/user", 7);
    radix_tree_deny(tree, "/home/user/secret");
    radix_tree_overlap_removal(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    int found_user = 0, found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home/user") == 0) found_user = 1;
        if (strcmp(rules[i].path, "/home/user/secret") == 0) found_secret = 1;
    }
    TEST_ASSERT(found_user, "deny: /home/user survives overlap removal");
    TEST_ASSERT(!found_secret, "deny: secret path removed");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Prefix simplification                                              */
/* ------------------------------------------------------------------ */

static void test_simplify_all_cases(void)
{
    radix_tree_t *tree;
    landlock_rule_t *rules;
    size_t count;
    int found_a, found_b, found_c, found_d, found_lib;

    /* Case 1: Parent has superset of child — child pruned */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/usr", 7);
    radix_tree_allow(tree, "/usr/lib", 3);  /* 3 is subset of 7 */
    radix_tree_simplify(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "superset: child pruned, single rule remains");
    TEST_ASSERT_STR_EQ(rules[0].path, "/usr", "superset: remaining rule path");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 2: Parent has subset of child — both rules kept */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/usr", 1);
    radix_tree_allow(tree, "/usr/lib", 7);  /* 7 is NOT subset of 1 */
    radix_tree_simplify(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 2, "subset: both rules kept");
    found_a = 0; found_lib = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/usr") == 0) {
            found_a = 1;
            TEST_ASSERT_EQ(rules[i].access, 1, "subset: /usr mask unchanged");
        }
        if (strcmp(rules[i].path, "/usr/lib") == 0) {
            found_lib = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "subset: /usr/lib mask unchanged");
        }
    }
    TEST_ASSERT(found_a, "subset: found /usr");
    TEST_ASSERT(found_lib, "subset: found /usr/lib");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 3: Deep chain of subset masks — all collapse to root */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/a",       0xFF);
    radix_tree_allow(tree, "/a/b",     0x0F);
    radix_tree_allow(tree, "/a/b/c",   0x03);
    radix_tree_allow(tree, "/a/b/c/d", 0x01);
    radix_tree_simplify(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "deep: all children pruned, only root remains");
    TEST_ASSERT_STR_EQ(rules[0].path, "/a", "deep: root path");
    TEST_ASSERT_EQ(rules[0].access, 0xFF, "deep: root mask unchanged");
    found_b = 0; found_c = 0; found_d = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/a/b") == 0) found_b = 1;
        if (strcmp(rules[i].path, "/a/b/c") == 0) found_c = 1;
        if (strcmp(rules[i].path, "/a/b/c/d") == 0) found_d = 1;
    }
    TEST_ASSERT(!found_b, "deep: /a/b pruned");
    TEST_ASSERT(!found_c, "deep: /a/b/c pruned");
    TEST_ASSERT(!found_d, "deep: /a/b/c/d pruned");
    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Corner cases                                                       */
/* ------------------------------------------------------------------ */

static void test_corner_cases(void)
{
    radix_tree_t *tree;
    landlock_rule_t *rules;
    size_t count;

    /* Case 1: Root path */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/", 7);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "corner: root rule count");
    TEST_ASSERT_STR_EQ(rules[0].path, "/", "corner: root path");
    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 2: Empty and NULL paths rejected */
    tree = radix_tree_new();
    TEST_ASSERT_EQ(radix_tree_allow(tree, "", 7), -1, "corner: empty path rejected");
    TEST_ASSERT_EQ(radix_tree_allow(tree, NULL, 7), -1, "corner: NULL path rejected");
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_radix_tree_run(void)
{
    printf("=== Radix Tree Tests ===\n");
    RUN_TEST(test_insert_and_merge);
    RUN_TEST(test_simplify_all_cases);
    RUN_TEST(test_corner_cases);
}
