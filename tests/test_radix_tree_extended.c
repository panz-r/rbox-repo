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
/*  Bug regression: deep subtree simplification (bugs #4/#15)         */
/* ------------------------------------------------------------------ */

static void test_simplify_deep_subtree(void)
{
    /*
     * Structure:
     *   /a        (mask = 0xFF)
     *     /b      (mask = 0x0F)
     *       /c    (mask = 0x0F)
     *         /d  (mask = 0x80)   <-- NOT subset of /a
     *
     * Old buggy code would prune /b because /c (grandchild) passed
     * the shallow check, ignoring /d (great-grandchild).
     * Fixed code with subtree_is_subset should keep /b.
     */
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/a",       0xFF);
    radix_tree_allow(tree, "/a/b",     0x0F);
    radix_tree_allow(tree, "/a/b/c",   0x0F);
    radix_tree_allow(tree, "/a/b/c/d", 0x80);  /* Not subset of 0xFF? 0x80 & ~0xFF = 0 */

    /* Actually 0x80 IS subset of 0xFF. Let me use a different mask */
    radix_tree_free(tree);
    tree = radix_tree_new();

    radix_tree_allow(tree, "/a",       0x0F);  /* Only lower 4 bits */
    radix_tree_allow(tree, "/a/b",     0x0F);
    radix_tree_allow(tree, "/a/b/c",   0x0F);
    radix_tree_allow(tree, "/a/b/c/d", 0x80);  /* Bit 7 — NOT subset of 0x0F */

    radix_tree_simplify(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* /a/b/c/d must survive because its mask (0x80) is NOT covered by /a (0x0F) */
    int found_d = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "/d")) {
            found_d = 1;
            TEST_ASSERT_EQ(rules[i].access, 0x80, "/d has correct mask");
        }
    }
    TEST_ASSERT(found_d, "deep non-subset node preserved after simplify");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Bug regression: simplify with deny blocking pruning               */
/* ------------------------------------------------------------------ */

static void test_simplify_deny_blocks_pruning(void)
{
    /*
     * /home       (mask = READ|WRITE)
     *   /shared   (mask = READ)
     *     /secret (deny)
     *
     * /shared should NOT be pruned because it has a deny descendant.
     */
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/home",        0x03);
    radix_tree_allow(tree, "/home/shared", 0x01);
    radix_tree_deny(tree,  "/home/shared/secret");

    radix_tree_simplify(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* /home/shared must survive — it's needed to block /home/shared/secret */
    int found_shared = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "shared")) {
            found_shared = 1;
        }
    }
    TEST_ASSERT(found_shared, "deny descendant blocks pruning of ancestor");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
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

    TEST_ASSERT_EQ(tree->num_rules, 1, "root rule counted once");

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 1, "one root rule collected");
    TEST_ASSERT_EQ(rules[0].access, 7, "root access merged correctly");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Overlap removal: deny at root clears everything                    */
/* ------------------------------------------------------------------ */

static void test_deny_at_root(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/home", 7);
    radix_tree_allow(tree, "/usr",  3);
    radix_tree_allow(tree, "/etc",  1);
    radix_tree_deny(tree, "/");

    radix_tree_overlap_removal(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* All allow rules below root deny should be cleared */
    TEST_ASSERT_EQ(count, 0, "deny at root clears all allows");

    free(rules);  /* rules may be NULL or empty */
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Overlap removal: deny only affects subtree                         */
/* ------------------------------------------------------------------ */

static void test_deny_scoped(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/home/user/public",  7);
    radix_tree_allow(tree, "/home/user/private", 7);
    radix_tree_deny(tree,  "/home/user/private");

    radix_tree_overlap_removal(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    int found_public = 0, found_private = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home/user/public") == 0)  found_public = 1;
        if (strcmp(rules[i].path, "/home/user/private") == 0) found_private = 1;
    }
    TEST_ASSERT(found_public,  "public survives scoped deny");
    TEST_ASSERT(!found_private, "private is removed by deny");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Overlap removal: deny overrides allow at same path                 */
/* ------------------------------------------------------------------ */

static void test_deny_same_path(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/data", 7);
    radix_tree_deny(tree,  "/data");

    radix_tree_overlap_removal(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 0, "deny at same path removes allow");

    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Simplification: sibling with different masks both kept              */
/* ------------------------------------------------------------------ */

static void test_simplify_siblings_different_masks(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/base",     0x01);
    radix_tree_allow(tree, "/base/a",   0x02);  /* NOT subset of 0x01 */
    radix_tree_allow(tree, "/base/b",   0x01);  /* IS subset of 0x01 */

    radix_tree_simplify(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* /base/b should be pruned (subset of /base).
     * /base/a should survive (not a subset). */
    int found_a = 0, found_b = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "/base/a")) found_a = 1;
        if (strcmp(rules[i].path, "/base/b") == 0) found_b = 1;
    }
    TEST_ASSERT(found_a,  "non-subset sibling kept");
    TEST_ASSERT(!found_b, "subset sibling pruned");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Large tree: many branches from common root                         */
/* ------------------------------------------------------------------ */

static void test_large_branch_simplify(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Root has full mask; 100 branches each with subset mask */
    radix_tree_allow(tree, "/root", 0xFF);
    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/root/branch_%d", i);
        radix_tree_allow(tree, path, 0x03);
    }

    radix_tree_simplify(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* All branches should be pruned, leaving only /root */
    TEST_ASSERT_EQ(count, 1, "all subset branches pruned");
    TEST_ASSERT_STR_EQ(rules[0].path, "/root", "only root remains");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Path with many segments (deep tree)                                */
/* ------------------------------------------------------------------ */

static void test_deep_path_insertion(void)
{
    radix_tree_t *tree = radix_tree_new();

    /* Create a 200-segment deep path */
    char path[2000];
    int pos = 0;
    for (int i = 0; i < 200; i++) {
        pos += snprintf(path + pos, sizeof(path) - pos, "/seg%d", i);
    }

    TEST_ASSERT_EQ(radix_tree_allow(tree, path, 7), 0, "deep path inserted");

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 1, "deep path rule collected");
    /* Check that the path ends with /seg199 */
    const char *suffix = "/seg199";
    size_t len = strlen(rules[0].path);
    size_t slen = strlen(suffix);
    TEST_ASSERT(len > slen &&
                strcmp(rules[0].path + len - slen, suffix) == 0,
                "deep path ends with last segment");

    free((void *)rules[0].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Multiple deny rules                                                */
/* ------------------------------------------------------------------ */

static void test_multiple_denies(void)
{
    radix_tree_t *tree = radix_tree_new();

    radix_tree_allow(tree, "/data", 7);
    radix_tree_deny(tree,  "/data/a");
    radix_tree_deny(tree,  "/data/b");
    radix_tree_deny(tree,  "/data/c");

    radix_tree_overlap_removal(tree);

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);

    /* /data should survive (deny only affects children) */
    int found_data = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/data") == 0) found_data = 1;
    }
    TEST_ASSERT(found_data, "/data survives multiple child denies");

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Empty tree operations                                            */
/* ------------------------------------------------------------------ */

static void test_empty_tree_collect(void)
{
    radix_tree_t *tree = radix_tree_new();

    landlock_rule_t *rules = NULL;
    size_t count = 999;
    radix_tree_collect_rules(tree, &rules, &count);

    TEST_ASSERT_EQ(count, 0, "empty tree collects 0 rules");
    /* rules may be NULL or a valid empty allocation — only count matters */

    radix_tree_free(tree);
}

static void test_null_inputs(void)
{
    TEST_ASSERT_EQ(radix_tree_allow(NULL, "/x", 1), -1, "allow NULL tree");
    TEST_ASSERT_EQ(radix_tree_allow(NULL, NULL, 1), -1, "allow NULL tree+path");
    TEST_ASSERT_EQ(radix_tree_deny(NULL, "/x"), -1, "deny NULL tree");
    TEST_ASSERT_EQ(radix_tree_deny(NULL, NULL), -1, "deny NULL tree+path");

    radix_tree_overlap_removal(NULL);   /* should not crash */
    radix_tree_simplify(NULL);          /* should not crash */

    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(NULL, &rules, &count);
    TEST_ASSERT_EQ(count, 0, "collect from NULL tree");

    radix_tree_t *tree = radix_tree_new();
    radix_tree_collect_rules(tree, NULL, &count);
    TEST_ASSERT_EQ(count, 0, "collect with NULL out_rules");
    radix_tree_collect_rules(tree, &rules, NULL);
    TEST_ASSERT(rules == NULL, "collect with NULL out_count");
    radix_tree_free(tree);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_radix_tree_extended_run(void)
{
    printf("=== Radix Tree Extended Tests ===\n");
    RUN_TEST(test_simplify_deep_subtree);
    RUN_TEST(test_simplify_deny_blocks_pruning);
    RUN_TEST(test_root_double_count);
    RUN_TEST(test_deny_at_root);
    RUN_TEST(test_deny_scoped);
    RUN_TEST(test_deny_same_path);
    RUN_TEST(test_simplify_siblings_different_masks);
    RUN_TEST(test_large_branch_simplify);
    RUN_TEST(test_deep_path_insertion);
    RUN_TEST(test_multiple_denies);
    RUN_TEST(test_empty_tree_collect);
    RUN_TEST(test_null_inputs);
}
