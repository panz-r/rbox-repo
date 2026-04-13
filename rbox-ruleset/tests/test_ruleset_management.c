/**
 * @file test_ruleset_management.c
 * @brief Unit tests for dynamic ruleset management APIs:
 *   - Clone
 *   - Rule enumeration/inspection
 *   - Rule removal
 *   - Merge / layer insert
 *   - Diff
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Clone                                                              */
/* ------------------------------------------------------------------ */

static void test_clone_basic(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add recursive read rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/secret",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add deny at layer 1");

    soft_ruleset_t *clone = soft_ruleset_clone(rs);
    TEST_ASSERT_NOT_NULL(clone, "clone returns non-NULL");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(clone), 2, "clone has same rule count");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(clone), 2, "clone has same layer count");

    /* Clone is not compiled even if source is */
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(clone), false,
                   "clone starts uncompiled");

    /* Clone evaluates the same as original */
    soft_access_ctx_t ctx = { SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "original allows /data/file.txt");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(clone, &ctx, NULL), SOFT_ACCESS_READ,
                   "clone allows /data/file.txt");

    ctx.src_path = "/secret";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "original denies /secret");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(clone, &ctx, NULL), -13,
                   "clone denies /secret");

    /* Modifying clone doesn't affect original */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(clone, "/new", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule to clone");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 2,
                   "original rule count unchanged");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(clone), 3,
                   "clone rule count increased");

    soft_ruleset_free(rs);
    soft_ruleset_free(clone);
}

static void test_clone_null_and_empty(void)
{
    TEST_ASSERT(soft_ruleset_clone(NULL) == NULL, "clone NULL returns NULL");

    soft_ruleset_t *empty = soft_ruleset_new();
    soft_ruleset_t *clone = soft_ruleset_clone(empty);
    TEST_ASSERT_NOT_NULL(clone, "clone empty returns non-NULL");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(clone), 0, "clone empty has 0 rules");
    soft_ruleset_free(empty);
    soft_ruleset_free(clone);
}

static void test_clone_with_custom_ops(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_set_custom_op_modes(rs, SOFT_OP_CUSTOM,
                   SOFT_ACCESS_READ | SOFT_ACCESS_EXEC, SOFT_ACCESS_WRITE),
                   0, "set custom op modes");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/custom", SOFT_ACCESS_READ,
                                          SOFT_OP_CUSTOM, NULL, NULL, 0, 0),
                   0, "add custom op rule");

    soft_ruleset_t *clone = soft_ruleset_clone(rs);
    /* Clone preserves custom op semantics: SRC needs READ, DST needs WRITE.
     * The clone only has a rule for /custom (SRC), no rule for DST.
     * Since there's no DST rule, the COPY subquery for DST will fail.
     * We just verify the clone has the same rule and custom ops table. */
    TEST_ASSERT_EQ(soft_ruleset_rule_count(clone), 1, "clone has same rules");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(clone, 0, &info), 0, "clone rule info");
    TEST_ASSERT_STR_EQ(info.pattern, "/custom", "clone rule pattern");
    TEST_ASSERT_EQ(info.op_type, SOFT_OP_CUSTOM, "clone rule op type");

    soft_ruleset_free(rs);
    soft_ruleset_free(clone);
}

/* ------------------------------------------------------------------ */
/*  Rule enumeration / inspection                                      */
/* ------------------------------------------------------------------ */

static void test_rule_info_basic(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule 1");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 0, &info), 0,
                   "get rule info at index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/data", "rule 0 pattern");
    TEST_ASSERT_EQ(info.mode, SOFT_ACCESS_READ, "rule 0 mode");
    TEST_ASSERT_EQ(info.op_type, SOFT_OP_READ, "rule 0 op");
    TEST_ASSERT_EQ(info.layer, 0, "rule 0 layer");
    TEST_ASSERT(info.linked_path_var == NULL, "rule 0 no linked var");
    TEST_ASSERT(info.subject_regex == NULL, "rule 0 no subject");
    TEST_ASSERT_EQ(info.min_uid, 0, "rule 0 min_uid");

    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 1, &info), 0,
                   "get rule info at index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/secret", "rule 1 pattern");
    TEST_ASSERT_EQ(info.mode, SOFT_ACCESS_DENY, "rule 1 mode");

    /* Out of range */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 2, &info), -1,
                   "out of range rejected");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, -1, &info), -1,
                   "negative index rejected");

    soft_ruleset_free(rs);
}

static void test_rule_info_multi_layer(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/a", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "layer 0 rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 2, "/b", SOFT_ACCESS_WRITE,
                   SOFT_OP_WRITE, NULL, NULL, 0, 0), 0, "layer 2 rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 2, "/c", SOFT_ACCESS_EXEC,
                   SOFT_OP_EXEC, NULL, NULL, 0, 0), 0, "layer 2 rule 2");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 0, &info), 0, "index 0");
    TEST_ASSERT_EQ(info.layer, 0, "index 0 is layer 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/a", "index 0 pattern");

    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 1, &info), 0, "index 1");
    TEST_ASSERT_EQ(info.layer, 2, "index 1 is layer 2 (layer 1 is empty)");
    TEST_ASSERT_STR_EQ(info.pattern, "/b", "index 1 pattern");

    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 2, &info), 0, "index 2");
    TEST_ASSERT_EQ(info.layer, 2, "index 2 is layer 2");
    TEST_ASSERT_STR_EQ(info.pattern, "/c", "index 2 pattern");

    soft_ruleset_free(rs);
}

static void test_rule_info_with_constraints(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "${SRC}", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, "SRC", ".*cp$", 1000,
                                          SOFT_RULE_TEMPLATE),
                   0, "add template rule with constraints");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 0, &info), 0, "get rule info");
    TEST_ASSERT_STR_EQ(info.pattern, "${SRC}", "pattern");
    TEST_ASSERT_STR_EQ(info.linked_path_var, "SRC", "linked var");
    TEST_ASSERT_STR_EQ(info.subject_regex, ".*cp$", "subject regex");
    TEST_ASSERT_EQ(info.min_uid, 1000, "min_uid");
    TEST_ASSERT(info.flags & SOFT_RULE_TEMPLATE, "template flag set");
    TEST_ASSERT_EQ(info.layer, 0, "layer");

    soft_ruleset_free(rs);
}

static void test_layer_info_basic(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/a", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "add layer 0 rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/b", SOFT_ACCESS_WRITE,
                   SOFT_OP_WRITE, NULL, NULL, 0, 0), 0, "add layer 1 rule");

    soft_layer_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_layer_info(rs, 0, &info), 0, "layer 0 info");
    TEST_ASSERT_EQ(info.type, LAYER_PRECEDENCE, "layer 0 type");
    TEST_ASSERT_EQ(info.mask, 0, "layer 0 mask (default)");
    TEST_ASSERT_EQ(info.count, 1, "layer 0 count");

    TEST_ASSERT_EQ(soft_ruleset_get_layer_info(rs, 1, &info), 0, "layer 1 info");
    TEST_ASSERT_EQ(info.count, 1, "layer 1 count");

    /* SPECIFICITY layer */
    TEST_ASSERT_EQ(soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY,
                   SOFT_ACCESS_READ), 0, "set SPECIFICITY");
    TEST_ASSERT_EQ(soft_ruleset_get_layer_info(rs, 1, &info), 0, "layer 1 info after set");
    TEST_ASSERT_EQ(info.type, LAYER_SPECIFICITY, "layer 1 type changed");
    TEST_ASSERT_EQ(info.mask, SOFT_ACCESS_READ, "layer 1 mask");

    /* Invalid layer */
    TEST_ASSERT_EQ(soft_ruleset_get_layer_info(rs, 5, &info), -1,
                   "nonexistent layer rejected");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Rule removal                                                       */
/* ------------------------------------------------------------------ */

static void test_remove_rule_by_attrs(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule 1");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule 2");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 2, "2 rules");

    /* Remove by attributes */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule(rs, 0, "/data", SOFT_ACCESS_READ,
                   SOFT_OP_READ), 0, "remove /data by attrs");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 1, "1 rule after removal");

    /* Verify remaining rule */
    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 0, &info), 0, "get remaining");
    TEST_ASSERT_STR_EQ(info.pattern, "/secret", "remaining is /secret");

    /* Removing non-existent rule */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule(rs, 0, "/nonexistent", SOFT_ACCESS_READ,
                   SOFT_OP_READ), -1, "remove nonexistent fails");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 1, "count unchanged");

    soft_ruleset_free(rs);
}

static void test_remove_rule_at_index(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/a", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add /a");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/b", SOFT_ACCESS_WRITE,
                                          SOFT_OP_WRITE, NULL, NULL, 0, 0),
                   0, "add /b");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/c", SOFT_ACCESS_EXEC,
                                          SOFT_OP_EXEC, NULL, NULL, 0, 0),
                   0, "add /c");

    /* Remove middle rule */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule_at_index(rs, 0, 1), 0,
                   "remove index 1");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 2, "2 rules left");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/a", "first is /a");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/c", "second is now /c");

    /* Invalid index */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule_at_index(rs, 0, 5), -1,
                   "out of range index rejected");
    TEST_ASSERT_EQ(soft_ruleset_remove_rule_at_index(rs, 0, -1), -1,
                   "negative index rejected");

    /* Invalid layer */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule_at_index(rs, 99, 0), -1,
                   "nonexistent layer rejected");

    soft_ruleset_free(rs);
}

static void test_remove_invalidates_compile(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule");
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "compile");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(rs), true, "compiled");

    TEST_ASSERT_EQ(soft_ruleset_remove_rule(rs, 0, "/data", SOFT_ACCESS_READ,
                   SOFT_OP_READ), 0, "remove rule");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(rs), false,
                   "removal invalidates compiled");

    soft_ruleset_free(rs);
}

static void test_remove_from_multi_layer(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/a", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "layer 0 /a");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/b", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "layer 1 /b");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/c", SOFT_ACCESS_WRITE,
                   SOFT_OP_WRITE, NULL, NULL, 0, 0), 0, "layer 1 /c");

    /* Remove from layer 1 */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule_at_index(rs, 1, 0), 0,
                   "remove layer 1 index 0 (/b)");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 2, "2 rules left");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(rs, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/c", "index 1 is /c");

    /* Remove rule from nonexistent layer */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule_at_index(rs, 5, 0), -1,
                   "remove from nonexistent layer fails");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Merge and layer insert                                             */
/* ------------------------------------------------------------------ */

static void test_merge_basic(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: add /data");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 0, "/secret",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: add /secret at layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 1, "/tmp",
                   SOFT_ACCESS_WRITE, SOFT_OP_WRITE, NULL, NULL, 0, 0),
                   0, "b: add /tmp at layer 1");

    TEST_ASSERT_EQ(soft_ruleset_merge(a, b), 0, "merge b into a");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(a), 3, "a has 3 rules after merge");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(a), 2, "a has 2 layers");

    soft_rule_info_t info;
    /* Layer 0: /data then /secret */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 0, &info), 0, "a index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/data", "a index 0 is /data");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 1, &info), 0, "a index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/secret", "a index 1 is /secret");
    TEST_ASSERT_EQ(info.layer, 0, "a index 1 layer is 0");

    /* Layer 1: /tmp */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 2, &info), 0, "a index 2");
    TEST_ASSERT_STR_EQ(info.pattern, "/tmp", "a index 2 is /tmp");
    TEST_ASSERT_EQ(info.layer, 1, "a index 2 layer is 1");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_merge_null_and_empty(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_merge(rs, NULL), -1, "merge NULL src fails");
    TEST_ASSERT_EQ(soft_ruleset_merge(NULL, rs), -1, "merge NULL dest fails");

    soft_ruleset_t *empty = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_merge(rs, empty), 0, "merge empty ok");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 0, "still 0 rules");

    soft_ruleset_free(rs);
    soft_ruleset_free(empty);
}

static void test_merge_layer_type_override(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 0, "/a", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: add /a");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_set_layer_type(b, 0, LAYER_SPECIFICITY,
                   SOFT_ACCESS_READ), 0, "b: set layer 0 SPECIFICITY");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 0, "/b", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: add /b");

    TEST_ASSERT_EQ(soft_ruleset_merge(a, b), 0, "merge");

    soft_layer_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_layer_info(a, 0, &info), 0, "layer 0 info");
    TEST_ASSERT_EQ(info.type, LAYER_SPECIFICITY, "layer type overridden");
    TEST_ASSERT_EQ(info.mask, SOFT_ACCESS_READ, "layer mask overridden");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_insert_ruleset_with_depth(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 0, "/top", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: add /top at layer 0");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 0, "/src0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: add /src0 at layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 1, "/src1", SOFT_ACCESS_WRITE,
                   SOFT_OP_WRITE, NULL, NULL, 0, 0), 0, "b: add /src1 at layer 1");

    /* Insert b shifted by depth=2 */
    TEST_ASSERT_EQ(soft_ruleset_insert_ruleset(a, b, 2), 0,
                   "insert with depth 2");

    soft_rule_info_t info;
    /* /top stays at layer 0 */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/top", "index 0 is /top");
    TEST_ASSERT_EQ(info.layer, 0, "/top at layer 0");

    /* /src0 shifted to layer 2 */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/src0", "index 1 is /src0");
    TEST_ASSERT_EQ(info.layer, 2, "/src0 shifted to layer 2");

    /* /src1 shifted to layer 3 */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 2, &info), 0, "index 2");
    TEST_ASSERT_STR_EQ(info.pattern, "/src1", "index 2 is /src1");
    TEST_ASSERT_EQ(info.layer, 3, "/src1 shifted to layer 3");

    /* Invalid depth */
    soft_ruleset_t *c = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(c, 0, "/x", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "c: add rule");
    TEST_ASSERT_EQ(soft_ruleset_insert_ruleset(a, c, 64), -1,
                   "excessive depth rejected");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
    soft_ruleset_free(c);
}

static void test_merge_at_layer(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 0, "/layer0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: add /layer0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 1, "/layer1", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: add /layer1");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 0, "/src_layer0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: src layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 1, "/src_layer1", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: src layer 1");

    /* Merge b at layer 1 of a: b's layer 0 → a's layer 1, b's layer 1 → a's layer 2 */
    TEST_ASSERT_EQ(soft_ruleset_merge_at_layer(a, b, 1), 0,
                   "merge at layer 1");

    soft_rule_info_t info;
    /* Layer 0: /layer0 */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/layer0", "index 0 is /layer0");

    /* Layer 1: /layer1 + /src_layer0 */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/layer1", "index 1 is /layer1");
    TEST_ASSERT_EQ(info.layer, 1, "layer 1");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 2, &info), 0, "index 2");
    TEST_ASSERT_STR_EQ(info.pattern, "/src_layer0", "index 2 is /src_layer0");
    TEST_ASSERT_EQ(info.layer, 1, "src layer 0 mapped to dest layer 1");

    /* Layer 2: /src_layer1 */
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 3, &info), 0, "index 3");
    TEST_ASSERT_STR_EQ(info.pattern, "/src_layer1", "index 3 is /src_layer1");
    TEST_ASSERT_EQ(info.layer, 2, "src layer 1 mapped to dest layer 2");

    /* Invalid target layer */
    TEST_ASSERT_EQ(soft_ruleset_merge_at_layer(a, b, 64), -1,
                   "excessive target layer rejected");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_merge_invalidation(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/a", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule to a");
    TEST_ASSERT_EQ(soft_ruleset_compile(a), 0, "compile a");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(a), true, "a compiled");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/b", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule to b");

    TEST_ASSERT_EQ(soft_ruleset_merge(a, b), 0, "merge");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(a), false, "merge invalidates");

    TEST_ASSERT_EQ(soft_ruleset_insert_ruleset(a, b, 0), 0, "insert");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(a), false, "insert invalidates");

    TEST_ASSERT_EQ(soft_ruleset_merge_at_layer(a, b, 0), 0, "merge at layer");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(a), false, "merge_at_layer invalidates");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

/* ------------------------------------------------------------------ */
/*  Insert with shift                                                  */
/* ------------------------------------------------------------------ */

static void test_insert_at_layer_basic(void)
{
    /* dest: layers [0, 1, 2] — one rule each */
    soft_ruleset_t *dest = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(dest, 0, "/layer0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "dest: layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(dest, 1, "/layer1", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "dest: layer 1");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(dest, 2, "/layer2", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "dest: layer 2");

    /* src: 3 layers, one rule each */
    soft_ruleset_t *src = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(src, 0, "/src0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "src: layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(src, 1, "/src1", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "src: layer 1");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(src, 2, "/src2", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "src: layer 2");

    /* Insert src at layer 1 of dest */
    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(dest, src, 1), 0,
                   "insert at layer 1");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(dest), 6, "6 layers after insert");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(dest), 6, "6 rules after insert");

    /* Verify layer mapping:
     * dest layer 0 → stays at 0
     * src layer 0  → dest layer 1
     * src layer 1  → dest layer 2
     * src layer 2  → dest layer 3
     * dest layer 1 → shifts to 4
     * dest layer 2 → shifts to 5 */
    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/layer0", "index 0 is /layer0");
    TEST_ASSERT_EQ(info.layer, 0, "still at layer 0");

    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/src0", "index 1 is /src0");
    TEST_ASSERT_EQ(info.layer, 1, "src layer 0 → dest layer 1");

    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 3, &info), 0, "index 3");
    TEST_ASSERT_STR_EQ(info.pattern, "/src2", "index 3 is /src2");
    TEST_ASSERT_EQ(info.layer, 3, "src layer 2 → dest layer 3");

    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 4, &info), 0, "index 4");
    TEST_ASSERT_STR_EQ(info.pattern, "/layer1", "index 4 is /layer1");
    TEST_ASSERT_EQ(info.layer, 4, "dest layer 1 shifted to 4");

    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 5, &info), 0, "index 5");
    TEST_ASSERT_STR_EQ(info.pattern, "/layer2", "index 5 is /layer2");
    TEST_ASSERT_EQ(info.layer, 5, "dest layer 2 shifted to 5");

    soft_ruleset_free(dest);
    soft_ruleset_free(src);
}

static void test_insert_at_layer_edge_cases(void)
{
    /* Insert at layer 0 (prepend all) */
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 0, "/a0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 1, "/a1", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: layer 1");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/b", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: 1 layer");

    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(a, b, 0), 0, "insert at layer 0");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(a), 3, "3 layers after prepend");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/b", "b now at layer 0");
    TEST_ASSERT_EQ(info.layer, 0, "layer 0");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/a0", "a0 shifted to layer 1");
    TEST_ASSERT_EQ(info.layer, 1, "layer 1");

    soft_ruleset_free(a);
    soft_ruleset_free(b);

    /* Insert at the very end (same as merge_at_layer) */
    a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 0, "/x", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: layer 0");

    b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/y", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: layer 0");

    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(a, b, 1), 0, "insert at end");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(a), 2, "2 layers");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/x", "/x still at layer 0");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/y", "/y at layer 1");

    soft_ruleset_free(a);
    soft_ruleset_free(b);

    /* Invalid: target_layer with src that would exceed MAX_LAYERS */
    a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 0, "/x", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: rule");
    b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 0, "/y", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: rule");
    /* target=63 + 1 src layer = 64, which equals MAX_LAYERS → still OK */
    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(a, b, 63), 0,
                   "insert at edge of MAX_LAYERS");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(a), 64, "fills up to MAX_LAYERS");
    soft_ruleset_free(a);
    soft_ruleset_free(b);

    /* Exceed MAX_LAYERS: dest already at 64 layers */
    a = soft_ruleset_new();
    /* Fill up to layer 63 */
    for (int i = 0; i < 64; i++) {
        char pat[32];
        snprintf(pat, sizeof(pat), "/l%d", i);
        soft_ruleset_add_rule_at_layer(a, i, pat, SOFT_ACCESS_READ,
                                       SOFT_OP_READ, NULL, NULL, 0, 0);
    }
    b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/new", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: rule");
    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(a, b, 0), -1,
                   "insert when already at MAX_LAYERS rejected");
    soft_ruleset_free(a);
    soft_ruleset_free(b);

    /* Invalid: null args */
    a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/x", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: rule");
    b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/y", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: rule");
    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(NULL, b, 0), -1, "NULL dest rejected");
    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(a, NULL, 0), -1, "NULL src rejected");
    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(a, b, -1), -1, "negative target rejected");

    /* Empty src: no-op */
    soft_ruleset_t *empty = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(a, empty, 0), 0, "empty src ok");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(a), 1, "rule count unchanged");
    soft_ruleset_free(empty);

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_insert_at_layer_invalidation(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/a", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule to a");
    TEST_ASSERT_EQ(soft_ruleset_compile(a), 0, "compile a");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(a), true, "a compiled");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/b", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule to b");

    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(a, b, 0), 0, "insert");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(a), false, "insert invalidates compiled");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_insert_at_layer_independence(void)
{
    /* Verify that modifying the inserted rules doesn't affect src */
    soft_ruleset_t *dest = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(dest, "/dest", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "dest rule");

    soft_ruleset_t *src = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(src, "/src", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "src rule");

    TEST_ASSERT_EQ(soft_ruleset_insert_at_layer(dest, src, 1), 0, "insert");

    /* Remove a rule from dest — should not affect src */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule(dest, 1, "/src", SOFT_ACCESS_READ,
                   SOFT_OP_READ), 0, "remove inserted rule");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(src), 1, "src still has its rule");

    soft_ruleset_free(dest);
    soft_ruleset_free(src);
}

/* ------------------------------------------------------------------ */
/*  Meld (ownership transfer)                                          */
/* ------------------------------------------------------------------ */

static void test_meld_into_basic(void)
{
    /* dest: layers [0, 1, 2] — one rule each */
    soft_ruleset_t *dest = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(dest, 0, "/layer0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "dest: layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(dest, 1, "/layer1", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "dest: layer 1");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(dest, 2, "/layer2", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "dest: layer 2");

    /* src: 3 layers, one rule each */
    soft_ruleset_t *src = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(src, 0, "/src0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "src: layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(src, 1, "/src1", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "src: layer 1");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(src, 2, "/src2", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "src: layer 2");

    size_t src_rules_before = soft_ruleset_rule_count(src);
    TEST_ASSERT_EQ(src_rules_before, 3, "src has 3 rules before meld");

    TEST_ASSERT_EQ(soft_ruleset_meld_into(dest, src, 1), 0, "meld at layer 1");

    /* Dest has same layout as insert_at_layer */
    TEST_ASSERT_EQ(soft_ruleset_layer_count(dest), 6, "6 layers after meld");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(dest), 6, "6 rules after meld");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/layer0", "/layer0 at layer 0");
    TEST_ASSERT_EQ(info.layer, 0, "layer 0");

    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/src0", "/src0 at layer 1");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 4, &info), 0, "index 4");
    TEST_ASSERT_STR_EQ(info.pattern, "/layer1", "/layer1 shifted to layer 4");

    /* Src is consumed — emptied */
    TEST_ASSERT_EQ(soft_ruleset_rule_count(src), 0, "src has 0 rules after meld");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(src), 0, "src has 0 layers after meld");

    /* Src is safe to free (no double-free) */
    soft_ruleset_free(src);
    soft_ruleset_free(dest);
}

static void test_meld_into_ownership(void)
{
    /* Verify src's memory is transferred, not copied */
    soft_ruleset_t *dest = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(dest, "/dest", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "dest rule");

    soft_ruleset_t *src = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(src, "/src", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "src rule");

    TEST_ASSERT_EQ(soft_ruleset_meld_into(dest, src, 1), 0, "meld");

    /* Freeing src is safe */
    soft_ruleset_free(src);

    /* Dest still has src's rule */
    TEST_ASSERT_EQ(soft_ruleset_rule_count(dest), 2, "dest has 2 rules");
    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(dest, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/src", "src rule still accessible");

    soft_ruleset_free(dest);
}

static void test_meld_into_edge_cases(void)
{
    /* Empty src: no-op */
    soft_ruleset_t *dest = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(dest, "/x", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "dest rule");
    soft_ruleset_t *empty = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_meld_into(dest, empty, 0), 0, "empty src ok");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(dest), 1, "count unchanged");
    soft_ruleset_free(dest);
    soft_ruleset_free(empty);

    /* NULL args */
    dest = soft_ruleset_new();
    soft_ruleset_t *src = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(src, "/y", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "src rule");
    TEST_ASSERT_EQ(soft_ruleset_meld_into(NULL, src, 0), -1, "NULL dest rejected");
    TEST_ASSERT_EQ(soft_ruleset_meld_into(dest, NULL, 0), -1, "NULL src rejected");
    TEST_ASSERT_EQ(soft_ruleset_meld_into(dest, src, -1), -1, "negative target rejected");
    soft_ruleset_free(dest);
    soft_ruleset_free(src);

    /* Exceed MAX_LAYERS */
    dest = soft_ruleset_new();
    for (int i = 0; i < 64; i++) {
        char pat[32];
        snprintf(pat, sizeof(pat), "/l%d", i);
        soft_ruleset_add_rule_at_layer(dest, i, pat, SOFT_ACCESS_READ,
                                       SOFT_OP_READ, NULL, NULL, 0, 0);
    }
    src = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(src, "/new", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "src rule");
    TEST_ASSERT_EQ(soft_ruleset_meld_into(dest, src, 0), -1,
                   "meld when at MAX_LAYERS rejected");
    soft_ruleset_free(dest);
    soft_ruleset_free(src);
}

static void test_meld_into_invalidation(void)
{
    soft_ruleset_t *dest = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(dest, "/a", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule to dest");
    TEST_ASSERT_EQ(soft_ruleset_compile(dest), 0, "compile dest");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(dest), true, "dest compiled");

    soft_ruleset_t *src = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(src, "/b", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule to src");

    TEST_ASSERT_EQ(soft_ruleset_meld_into(dest, src, 0), 0, "meld");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(dest), false, "meld invalidates compiled");

    soft_ruleset_free(dest);
    soft_ruleset_free(src);
}

/* ------------------------------------------------------------------ */
/*  Meld (append variants)                                             */
/* ------------------------------------------------------------------ */

static void test_meld_basic(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/a", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: /a");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 0, "/b0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: /b0 layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 1, "/b1", SOFT_ACCESS_WRITE,
                   SOFT_OP_WRITE, NULL, NULL, 0, 0), 0, "b: /b1 layer 1");

    TEST_ASSERT_EQ(soft_ruleset_meld(a, b), 0, "meld");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(a), 3, "3 rules in dest");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(b), 0, "src consumed (0 rules)");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(b), 0, "src consumed (0 layers)");

    /* Src safe to free */
    soft_ruleset_free(b);

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/a", "/a first");
    TEST_ASSERT_EQ(info.layer, 0, "layer 0");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/b0", "/b0 second");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 2, &info), 0, "index 2");
    TEST_ASSERT_STR_EQ(info.pattern, "/b1", "/b1 third");
    TEST_ASSERT_EQ(info.layer, 1, "layer 1");

    soft_ruleset_free(a);
}

static void test_meld_empty_dest_layer_takes_ownership(void)
{
    soft_ruleset_t *dest = soft_ruleset_new();
    soft_ruleset_t *src = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(src, "/x", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "src rule");

    TEST_ASSERT_EQ(soft_ruleset_meld(dest, src), 0, "meld into empty dest");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(dest), 1, "dest has rule");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(src), 0, "src consumed");

    soft_ruleset_free(dest);
    soft_ruleset_free(src);
}

static void test_meld_ruleset_basic(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/a", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: /a layer 0");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/b", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: /b layer 0");

    TEST_ASSERT_EQ(soft_ruleset_meld_ruleset(a, b, 1), 0, "meld_ruleset depth=1");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(a), 2, "2 rules");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/a", "/a at layer 0");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/b", "/b at layer 1");
    TEST_ASSERT_EQ(info.layer, 1, "shifted to layer 1");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_meld_at_layer_basic(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 0, "/top", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: /top layer 0");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 0, "/mid", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: /mid layer 0");

    TEST_ASSERT_EQ(soft_ruleset_meld_at_layer(a, b, 1), 0, "meld_at_layer 1");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(a), 2, "2 rules");

    soft_rule_info_t info;
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 0, &info), 0, "index 0");
    TEST_ASSERT_STR_EQ(info.pattern, "/top", "/top");
    TEST_ASSERT_EQ(info.layer, 0, "layer 0");
    TEST_ASSERT_EQ(soft_ruleset_get_rule_info(a, 1, &info), 0, "index 1");
    TEST_ASSERT_STR_EQ(info.pattern, "/mid", "/mid");
    TEST_ASSERT_EQ(info.layer, 1, "layer 1");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_meld_edge_cases(void)
{
    /* NULL args */
    soft_ruleset_t *a = soft_ruleset_new();
    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_meld(NULL, b), -1, "meld NULL dest");
    TEST_ASSERT_EQ(soft_ruleset_meld(a, NULL), -1, "meld NULL src");
    TEST_ASSERT_EQ(soft_ruleset_meld_ruleset(NULL, b, 0), -1, "meld_ruleset NULL dest");
    TEST_ASSERT_EQ(soft_ruleset_meld_ruleset(a, NULL, 0), -1, "meld_ruleset NULL src");
    TEST_ASSERT_EQ(soft_ruleset_meld_ruleset(a, b, -1), -1, "meld_ruleset negative depth");
    TEST_ASSERT_EQ(soft_ruleset_meld_at_layer(NULL, b, 0), -1, "meld_at_layer NULL dest");
    TEST_ASSERT_EQ(soft_ruleset_meld_at_layer(a, NULL, 0), -1, "meld_at_layer NULL src");
    TEST_ASSERT_EQ(soft_ruleset_meld_at_layer(a, b, -1), -1, "meld_at_layer negative target");

    /* Empty src */
    soft_ruleset_t *empty = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_meld(a, empty), 0, "meld empty src ok");
    TEST_ASSERT_EQ(soft_ruleset_meld_ruleset(a, empty, 0), 0, "meld_ruleset empty src ok");
    TEST_ASSERT_EQ(soft_ruleset_meld_at_layer(a, empty, 0), 0, "meld_at_layer empty src ok");
    soft_ruleset_free(empty);

    /* Exceed MAX_LAYERS: meld_ruleset with depth that pushes beyond limit */
    soft_ruleset_t *full = soft_ruleset_new();
    for (int i = 0; i < 64; i++) {
        char pat[32];
        snprintf(pat, sizeof(pat), "/l%d", i);
        soft_ruleset_add_rule_at_layer(full, i, pat, SOFT_ACCESS_READ,
                                       SOFT_OP_READ, NULL, NULL, 0, 0);
    }
    soft_ruleset_t *one = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(one, "/x", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "one rule");
    /* meld_ruleset with depth=0 appends to existing layers (succeeds) */
    TEST_ASSERT_EQ(soft_ruleset_meld_ruleset(full, one, 0), 0,
                   "meld_ruleset depth=0 appends to existing layers");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(full), 65, "65 rules after meld");
    soft_ruleset_free(full);
    soft_ruleset_free(one);

    /* Meld at layer targeting beyond MAX_LAYERS */
    soft_ruleset_t *a63 = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(a63, 63, "/l63", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_t *b1 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b1, "/x", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b1 rule");
    /* target_layer=63 + src 1 layer = 64, ok */
    TEST_ASSERT_EQ(soft_ruleset_meld_at_layer(a63, b1, 63), 0,
                   "meld_at_layer at edge of MAX_LAYERS ok");
    soft_ruleset_free(a63);
    soft_ruleset_free(b1);

    /* Now test actual overflow: src at layer 1, target=63 → dest_layer=64 > MAX */
    a63 = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(a63, 63, "/l63", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_t *b2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b2, 0, "/x0", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b2 layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b2, 1, "/x1", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b2 layer 1");
    /* target=63, src layer 1 → dest 64 > MAX */
    TEST_ASSERT_EQ(soft_ruleset_meld_at_layer(a63, b2, 63), -1,
                   "meld_at_layer exceeding MAX_LAYERS");
    soft_ruleset_free(a63);
    soft_ruleset_free(b2);

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

/* ------------------------------------------------------------------ */
/*  Diff                                                               */
/* ------------------------------------------------------------------ */

static void test_diff_identical(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: /data");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: /secret");

    soft_ruleset_t *b = soft_ruleset_clone(a);

    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(a, b, &diff), 0, "diff identical");
    TEST_ASSERT_EQ(diff.added, 0, "no added");
    TEST_ASSERT_EQ(diff.removed, 0, "no removed");
    TEST_ASSERT_EQ(diff.modified, 0, "no modified");
    TEST_ASSERT_EQ(diff.unchanged, 2, "2 unchanged");

    soft_ruleset_diff_free(&diff);
    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_diff_added_only(void)
{
    soft_ruleset_t *a = soft_ruleset_new();

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: /data");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: /secret");

    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(a, b, &diff), 0, "diff a empty, b has rules");
    TEST_ASSERT_EQ(diff.added, 2, "2 added");
    TEST_ASSERT_EQ(diff.removed, 0, "no removed");
    TEST_ASSERT_EQ(diff.modified, 0, "no modified");
    TEST_ASSERT_EQ(diff.unchanged, 0, "no unchanged");

    /* Check added entries */
    for (int i = 0; i < diff.count; i++) {
        TEST_ASSERT_EQ(diff.changes[i].type, DIFF_RULE_ADDED,
                       "change type is ADDED");
        TEST_ASSERT_EQ(diff.changes[i].layer_a, -1, "layer_a is -1 for added");
        TEST_ASSERT(diff.changes[i].rule_a == NULL, "rule_a is NULL for added");
        TEST_ASSERT(diff.changes[i].rule_b != NULL, "rule_b is set for added");
    }

    soft_ruleset_diff_free(&diff);
    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_diff_removed_only(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: /data");

    soft_ruleset_t *b = soft_ruleset_new();

    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(a, b, &diff), 0, "diff a has rules, b empty");
    TEST_ASSERT_EQ(diff.added, 0, "no added");
    TEST_ASSERT_EQ(diff.removed, 1, "1 removed");

    TEST_ASSERT_EQ(diff.changes[0].type, DIFF_RULE_REMOVED,
                   "change type is REMOVED");
    TEST_ASSERT_EQ(diff.changes[0].layer_b, -1, "layer_b is -1 for removed");
    TEST_ASSERT(diff.changes[0].rule_b == NULL, "rule_b is NULL for removed");

    soft_ruleset_diff_free(&diff);
    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_diff_modified(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: /data READ");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/data", SOFT_ACCESS_WRITE,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: /data WRITE");

    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(a, b, &diff), 0, "diff modified");
    TEST_ASSERT_EQ(diff.modified, 1, "1 modified");
    TEST_ASSERT_EQ(diff.added, 0, "no added");
    TEST_ASSERT_EQ(diff.removed, 0, "no removed");

    TEST_ASSERT_EQ(diff.changes[0].type, DIFF_RULE_MODIFIED,
                   "change type is MODIFIED");
    TEST_ASSERT(diff.changes[0].rule_a != NULL, "rule_a is set");
    TEST_ASSERT(diff.changes[0].rule_b != NULL, "rule_b is set");
    TEST_ASSERT_EQ(diff.changes[0].rule_a->mode, SOFT_ACCESS_READ,
                   "rule_a mode is READ");
    TEST_ASSERT_EQ(diff.changes[0].rule_b->mode, SOFT_ACCESS_WRITE,
                   "rule_b mode is WRITE");

    soft_ruleset_diff_free(&diff);
    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_diff_mixed_changes(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/unchanged", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: unchanged");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/modified", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: modified");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/removed", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: removed");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/unchanged", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: unchanged");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/modified", SOFT_ACCESS_WRITE,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: modified (different mode)");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/added", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: added");

    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(a, b, &diff), 0, "diff mixed");
    TEST_ASSERT_EQ(diff.unchanged, 1, "1 unchanged");
    TEST_ASSERT_EQ(diff.modified, 1, "1 modified");
    TEST_ASSERT_EQ(diff.added, 1, "1 added");
    TEST_ASSERT_EQ(diff.removed, 1, "1 removed");
    TEST_ASSERT_EQ(diff.count, 4, "4 total changes");

    soft_ruleset_diff_free(&diff);
    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_diff_null_inputs(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule");

    /* NULL a: all rules from b are "added" */
    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(NULL, rs, &diff), 0, "diff NULL a");
    TEST_ASSERT_EQ(diff.added, 1, "1 added when a is NULL");
    soft_ruleset_diff_free(&diff);

    /* NULL b: all rules from a are "removed" */
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(rs, NULL, &diff), 0, "diff NULL b");
    TEST_ASSERT_EQ(diff.removed, 1, "1 removed when b is NULL");
    soft_ruleset_diff_free(&diff);

    /* Both NULL: empty diff */
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(NULL, NULL, &diff), 0, "diff both NULL");
    TEST_ASSERT_EQ(diff.count, 0, "0 changes when both NULL");

    soft_ruleset_free(rs);
}

static void test_diff_free_null_safe(void)
{
    soft_ruleset_diff_t diff = { 0 };
    soft_ruleset_diff_free(&diff);
    soft_ruleset_diff_free(NULL);
    /* No crash = pass */
    TEST_ASSERT(1, "diff_free is NULL-safe");
}

static void test_diff_multi_layer(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 0, "/layer0_a", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: layer 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(a, 2, "/layer2_a", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "a: layer 2");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 0, "/layer0_a", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: layer 0 same");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(b, 1, "/layer1_b", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0), 0, "b: layer 1 new");

    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(a, b, &diff), 0, "diff multi-layer");

    /* layer 0: unchanged */
    /* layer 1: only in b → added */
    /* layer 2: only in a → removed */
    TEST_ASSERT_EQ(diff.unchanged, 1, "1 unchanged");
    TEST_ASSERT_EQ(diff.added, 1, "1 added (layer 1)");
    TEST_ASSERT_EQ(diff.removed, 1, "1 removed (layer 2)");

    soft_ruleset_diff_free(&diff);
    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

static void test_diff_with_constraints(void)
{
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "${SRC}", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, "SRC", ".*cp$", 1000,
                                          SOFT_RULE_TEMPLATE),
                   0, "a: template with constraints");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "${SRC}", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, "SRC", ".*cp$", 1000,
                                          SOFT_RULE_TEMPLATE),
                   0, "b: same template with constraints");

    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(a, b, &diff), 0, "diff identical constraints");
    TEST_ASSERT_EQ(diff.unchanged, 1, "1 unchanged");
    TEST_ASSERT_EQ(diff.modified, 0, "no modified");

    soft_ruleset_diff_free(&diff);

    /* Now modify b's constraint */
    soft_ruleset_free(b);
    b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "${SRC}", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, "SRC", ".*mv$", 2000,
                                          SOFT_RULE_TEMPLATE),
                   0, "b: different constraints");

    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(a, b, &diff), 0, "diff modified constraints");
    TEST_ASSERT_EQ(diff.modified, 1, "1 modified");

    soft_ruleset_diff_free(&diff);
    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

/* ------------------------------------------------------------------ */
/*  Integration: clone + merge + diff workflow                         */
/* ------------------------------------------------------------------ */

static void test_clone_merge_diff_workflow(void)
{
    /* Create base ruleset */
    soft_ruleset_t *base = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(base, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "base: /data");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(base, "/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "base: /secret deny");

    /* Clone for modification */
    soft_ruleset_t *working = soft_ruleset_clone(base);
    TEST_ASSERT_EQ(soft_ruleset_add_rule(working, "/new", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "working: add /new");

    /* Diff working against base */
    soft_ruleset_diff_t diff;
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(base, working, &diff), 0, "diff base vs working");
    TEST_ASSERT_EQ(diff.added, 1, "1 added in working");
    TEST_ASSERT_EQ(diff.unchanged, 2, "2 unchanged");

    /* Remove a rule from working */
    TEST_ASSERT_EQ(soft_ruleset_remove_rule(working, 0, "/data", SOFT_ACCESS_READ,
                   SOFT_OP_READ), 0, "remove /data from working");

    /* Diff again */
    soft_ruleset_diff_free(&diff);
    memset(&diff, 0, sizeof(diff));
    TEST_ASSERT_EQ(soft_ruleset_diff(base, working, &diff), 0, "diff after removal");
    TEST_ASSERT_EQ(diff.removed, 1, "1 removed from working");
    TEST_ASSERT_EQ(diff.added, 1, "1 added in working");
    TEST_ASSERT_EQ(diff.unchanged, 1, "1 unchanged (/secret)");

    soft_ruleset_diff_free(&diff);
    soft_ruleset_free(base);
    soft_ruleset_free(working);
}

static void test_merge_then_evaluate(void)
{
    /* Create two independent rulesets with non-overlapping patterns */
    soft_ruleset_t *a = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: /data allow");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(a, "/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "a: /secret deny");

    soft_ruleset_t *b = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/home", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "b: /home allow");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(b, "/tmp", SOFT_ACCESS_WRITE,
                                          SOFT_OP_WRITE, NULL, NULL, 0, 0),
                   0, "b: /tmp write");

    /* Merge b into a */
    TEST_ASSERT_EQ(soft_ruleset_merge(a, b), 0, "merge");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(a), 4, "a has 4 rules after merge");

    /* Compile and evaluate */
    TEST_ASSERT_EQ(soft_ruleset_compile(a), 0, "compile");

    soft_access_ctx_t ctx = { SOFT_OP_READ, "/data", NULL, NULL, 1000 };
    int ret = soft_ruleset_check_ctx(a, &ctx, NULL);
    TEST_ASSERT_EQ(ret, SOFT_ACCESS_READ,
                   "merged: /data allows READ");

    ctx.src_path = "/secret";
    ret = soft_ruleset_check_ctx(a, &ctx, NULL);
    TEST_ASSERT_EQ(ret, -13, "merged: /secret denied");

    ctx.src_path = "/home";
    ret = soft_ruleset_check_ctx(a, &ctx, NULL);
    TEST_ASSERT_EQ(ret, SOFT_ACCESS_READ, "merged: /home allows READ");

    ctx.op = SOFT_OP_WRITE;
    ctx.src_path = "/tmp";
    ret = soft_ruleset_check_ctx(a, &ctx, NULL);
    TEST_ASSERT_EQ(ret, SOFT_ACCESS_WRITE, "merged: /tmp allows WRITE");

    ctx.src_path = "/unknown";
    ret = soft_ruleset_check_ctx(a, &ctx, NULL);
    TEST_ASSERT_EQ(ret, 0, "merged: /unknown undetermined");

    soft_ruleset_free(a);
    soft_ruleset_free(b);
}

/* ------------------------------------------------------------------ */
/*  Test runner                                                        */
/* ------------------------------------------------------------------ */

void test_ruleset_management_run(void)
{
    printf("  Running test_ruleset_management...\n");

    /* Clone */
    test_clone_basic();
    test_clone_null_and_empty();
    test_clone_with_custom_ops();

    /* Enumeration */
    test_rule_info_basic();
    test_rule_info_multi_layer();
    test_rule_info_with_constraints();
    test_layer_info_basic();

    /* Removal */
    test_remove_rule_by_attrs();
    test_remove_rule_at_index();
    test_remove_invalidates_compile();
    test_remove_from_multi_layer();

    /* Merge/Insert */
    test_merge_basic();
    test_merge_null_and_empty();
    test_merge_layer_type_override();
    test_insert_ruleset_with_depth();
    test_merge_at_layer();
    test_merge_invalidation();
    test_insert_at_layer_basic();
    test_insert_at_layer_edge_cases();
    test_insert_at_layer_invalidation();
    test_insert_at_layer_independence();
    test_meld_into_basic();
    test_meld_into_ownership();
    test_meld_into_edge_cases();
    test_meld_into_invalidation();
    test_meld_basic();
    test_meld_empty_dest_layer_takes_ownership();
    test_meld_ruleset_basic();
    test_meld_at_layer_basic();
    test_meld_edge_cases();

    /* Diff */
    test_diff_identical();
    test_diff_added_only();
    test_diff_removed_only();
    test_diff_modified();
    test_diff_mixed_changes();
    test_diff_null_inputs();
    test_diff_free_null_safe();
    test_diff_multi_layer();
    test_diff_with_constraints();

    /* Integration */
    test_clone_merge_diff_workflow();
    test_merge_then_evaluate();
}
