/**
 * @file test_radix_tree_extended.c
 * @brief Extended unit tests for the radix tree — regression tests for
 *        fixed bugs and additional edge case coverage.
 */

#include "test_framework.h"
#include "radix_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Simplify: pruning blocked and siblings with different masks        */
/* ------------------------------------------------------------------ */

static void test_simplify_edge_cases(void)
{
    radix_tree_t *tree;
    landlock_rule_t *rules;
    size_t count;
    int found;
    size_t i;

    /* Case 1: Deep non-subset mask blocks pruning of intermediate nodes
     *
     * /a        (0x0F)
     *   /b      (0x0F)
     *     /c    (0x0F)
     *       /d  (0x80)  ← NOT subset of /a → /b must survive
     */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/a",       0x0F);
    radix_tree_allow(tree, "/a/b",     0x0F);
    radix_tree_allow(tree, "/a/b/c",   0x0F);
    radix_tree_allow(tree, "/a/b/c/d", 0x80);
    radix_tree_simplify(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    found = 0;
    for (i = 0; (size_t)i < count; i++) {
        if (strcmp(rules[i].path, "/a/b/c/d") == 0) {
            found = 1;
            TEST_ASSERT_EQ(rules[i].access, 0x80, "deep: /a/b/c/d mask correct");
        }
    }
    TEST_ASSERT(found, "deep: non-subset mask blocks pruning");
    for (i = 0; (size_t)i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 2: Deny descendant blocks pruning of ancestor
     *
     * /home        (0x03)
     *   /shared    (0x01)
     *     /secret  (deny)  ← deny blocks pruning of /shared
     */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/home",        0x03);
    radix_tree_allow(tree, "/home/shared", 0x01);
    radix_tree_deny(tree,  "/home/shared/secret");
    radix_tree_simplify(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    found = 0;
    for (i = 0; (size_t)i < count; i++) {
        if (strcmp(rules[i].path, "/home/shared") == 0) found = 1;
    }
    TEST_ASSERT(found, "deny: descendant blocks pruning");
    for (i = 0; (size_t)i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 3: Siblings with different masks — non-subset kept, subset pruned
     *
     * /base        (0x01)
     *   /base/a    (0x02)  ← NOT subset of 0x01 → kept
     *   /base/b    (0x01)  ← IS subset of 0x01 → pruned
     */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/base",     0x01);
    radix_tree_allow(tree, "/base/a",   0x02);
    radix_tree_allow(tree, "/base/b",   0x01);
    radix_tree_simplify(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    int found_a = 0, found_b = 0;
    for (i = 0; (size_t)i < count; i++) {
        if (strcmp(rules[i].path, "/base/a") == 0) found_a = 1;
        if (strcmp(rules[i].path, "/base/b") == 0) found_b = 1;
    }
    TEST_ASSERT(found_a,  "sibling: non-subset kept");
    TEST_ASSERT(!found_b, "sibling: subset pruned");
    for (i = 0; (size_t)i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Root path double-count regression (bug #17)                       */
/* ------------------------------------------------------------------ */

static void test_root_double_count(void)
{
    radix_tree_t *tree = radix_tree_new();
    radix_tree_allow(tree, "/", 1);
    radix_tree_allow(tree, "/", 2);
    radix_tree_allow(tree, "/", 4);
    TEST_ASSERT_EQ(tree->num_rules, 1, "root: rule counted once");
    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "root: one rule collected");
    TEST_ASSERT_EQ(rules[0].access, 7, "root: access merged correctly");
    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Overlap removal: deny clears allows at different scopes            */
/* ------------------------------------------------------------------ */

static void test_deny_overlap_removal(void)
{
    radix_tree_t *tree;
    landlock_rule_t *rules;
    size_t count;
    int found_public, found_private;
    size_t i;

    /* Case 1: Deny at root clears all allow rules below it */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/home", 7);
    radix_tree_allow(tree, "/usr",  3);
    radix_tree_allow(tree, "/etc",  1);
    radix_tree_deny(tree, "/");
    radix_tree_overlap_removal(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 0, "overlap: root deny clears all");
    free(rules);
    radix_tree_free(tree);

    /* Case 2: Scoped deny only affects its subtree */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/home/user/public",  7);
    radix_tree_allow(tree, "/home/user/private", 7);
    radix_tree_deny(tree,  "/home/user/private");
    radix_tree_overlap_removal(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    found_public = 0; found_private = 0;
    for (i = 0; (size_t)i < count; i++) {
        if (strcmp(rules[i].path, "/home/user/public") == 0)  found_public = 1;
        if (strcmp(rules[i].path, "/home/user/private") == 0) found_private = 1;
    }
    TEST_ASSERT(found_public,  "overlap: public survives");
    TEST_ASSERT(!found_private, "overlap: private removed");
    for (i = 0; (size_t)i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Large tree: many branches and deep path                            */
/* ------------------------------------------------------------------ */

static void test_large_tree(void)
{
    radix_tree_t *tree;
    landlock_rule_t *rules;
    size_t count;

    /* Case 1: 100 branches from common root — all pruned to single root */
    tree = radix_tree_new();
    radix_tree_allow(tree, "/root", 0xFF);
    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/root/branch_%d", i);
        radix_tree_allow(tree, path, 0x03);
    }
    radix_tree_simplify(tree);
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "large: 100 branches pruned to root");
    TEST_ASSERT_STR_EQ(rules[0].path, "/root", "large: only root remains");
    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);

    /* Case 2: 200-segment deep path — single rule collected */
    tree = radix_tree_new();
    char path[2000];
    size_t pos = 0;
    for (unsigned int i = 0; i < 200; i++) {
        int ret = snprintf(path + pos, sizeof(path) - pos, "/seg%u", i);
        if (ret < 0) break;
        pos += (size_t)ret;
    }
    TEST_ASSERT_EQ(radix_tree_allow(tree, path, 7), 0, "large: deep path inserted");
    rules = NULL; count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    TEST_ASSERT_EQ(count, 1, "large: deep path rule collected");
    const char *suffix = "/seg199";
    size_t len = strlen(rules[0].path);
    size_t slen = strlen(suffix);
    TEST_ASSERT(len > slen &&
                strcmp(rules[0].path + len - slen, suffix) == 0,
                "large: ends with last segment");
    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_radix_tree_extended_run(void)
{
    printf("=== Radix Tree Extended Tests ===\n");
    RUN_TEST(test_simplify_edge_cases);
    RUN_TEST(test_root_double_count);
    RUN_TEST(test_deny_overlap_removal);
    RUN_TEST(test_large_tree);
}
