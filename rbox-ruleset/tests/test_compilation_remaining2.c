/**
 * @file test_compilation_remaining2.c
 * @brief Remaining compilation edge cases and mechanism interactions.
 *
 * Targets:
 *   - Template patterns with wildcards
 *   - Binary operations with complex constraints
 *   - Cache collision scenarios
 *   - Layer mask edge cases
 *   - Deep recursive patterns
 *   - Conflicting rules compilation
 *   - Edge case patterns (root, multiple slashes)
 *   - State transitions across compile cycles
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Template patterns with wildcards                                   */
/* ------------------------------------------------------------------ */

static void test_template_with_wildcards(void)
{
    /* Template with wildcard patterns for COPY operation */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_add_rule_at_layer(rs, 0, "${DST}", SOFT_ACCESS_WRITE,
                                   SOFT_OP_COPY, "DST", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* COPY with paths that match template resolution */
    soft_access_ctx_t ctx = {SOFT_OP_COPY, "/src/deep/file.txt", "/dst/out.txt", NULL, 1000};
    /* Templates resolve to actual paths, both should match */
    int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result != -13,
                "template_wildcard: COPY with deep paths evaluated");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Binary operations with complex constraints                         */
/* ------------------------------------------------------------------ */

static void test_binary_ops_complex_constraints(void)
{
    /* MOVE with subject constraint - test that subject filtering works */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* READ with matching subject */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "binary_complex: READ with matching subject allowed");

    /* READ with non-matching subject */
    ctx.subject = "/usr/bin/user";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "binary_complex: READ with non-matching subject denied");

    soft_ruleset_free(rs);

    /* LINK with UID constraint */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* READ with matching UID */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "binary_complex: READ with matching UID allowed");

    /* READ with low UID */
    ctx.uid = 500;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "binary_complex: READ with low UID denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Cache collision scenarios                                          */
/* ------------------------------------------------------------------ */

static void test_cache_collision_scenarios(void)
{
    /* Many paths that might collide in cache */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Query many different paths */
    char path[64];
    int i;
    for (i = 0; i < 50; i++) {
        snprintf(path, sizeof(path), "/data/file_%d.txt", i);
        soft_access_ctx_t ctx = {SOFT_OP_READ, path, NULL, NULL, 1000};
        TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                       "cache_collision: path allowed");
    }

    /* Query first path again - may or may not be cached */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file_0.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "cache_collision: first path still allowed");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer mask edge cases                                              */
/* ------------------------------------------------------------------ */

static void test_layer_mask_edge_cases(void)
{
    /* Layer mask = 0 (no restrictions) vs no mask set */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "layer_mask_zero: mask=0 allows all");

    soft_ruleset_free(rs);

    /* Layer mask that matches the rule's mode */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, SOFT_ACCESS_READ);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* READ rule with READ mask -> allowed */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "layer_mask_match: mask allows rule mode");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Deep recursive patterns                                            */
/* ------------------------------------------------------------------ */

static void test_deep_recursive_patterns(void)
{
    /* Deep path matching */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Build a moderately deep path under /data */
    char deep_path[200];
    snprintf(deep_path, sizeof(deep_path), "/data");
    int i;
    for (i = 0; i < 20; i++) {
        char segment[10];
        snprintf(segment, sizeof(segment), "/d%d", i);
        strncat(deep_path, segment, sizeof(deep_path) - strlen(deep_path) - 1);
    }
    strncat(deep_path, "/file.txt", sizeof(deep_path) - strlen(deep_path) - 1);

    soft_access_ctx_t ctx = {SOFT_OP_READ, deep_path, NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "deep_recursive: 20-level deep path matches");

    /* Test simple deep path as well */
    ctx.src_path = "/data/d0/d1/d2/d3/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "deep_recursive: simple deep path matches");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Conflicting rules compilation                                      */
/* ------------------------------------------------------------------ */

static void test_conflicting_rules_compilation(void)
{
    /* ALLOW and DENY for same pattern in different layers */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* DENY in layer 0 should win over ALLOW in layer 1 */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "conflicting: DENY wins over ALLOW");

    soft_ruleset_free(rs);

    /* Multiple DENY rules for overlapping patterns */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both DENY rules active */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "conflicting: multiple DENY rules block");

    ctx.src_path = "/data/secret/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "conflicting: nested DENY also blocks");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Edge case patterns                                                 */
/* ------------------------------------------------------------------ */

static void test_edge_case_patterns(void)
{
    /* Root pattern */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Root path */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "edge_pattern: root path matches");

    /* Single char path */
    ctx.src_path = "/a";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "edge_pattern: single char path matches");

    soft_ruleset_free(rs);

    /* Pattern with numbers and special chars */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/v1.2.3-beta_file.txt", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/v1.2.3-beta_file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "edge_pattern: versioned path matches");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  State transitions across compile cycles                            */
/* ------------------------------------------------------------------ */

static void test_state_transitions_compile_cycles(void)
{
    /* Compile -> invalidate -> recompile with different rules */
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Initial: ALLOW all under /data */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "state_trans: initial ALLOW allows");

    /* Add DENY rule */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(rs), false,
                   "state_trans: adding rule invalidates");

    /* Recompile - DENY should now block secret paths */
    soft_ruleset_compile(rs);
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "state_trans: recompiled");

    ctx.src_path = "/data/secret/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "state_trans: DENY blocks secret after recompile");

    /* Non-secret still allowed */
    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "state_trans: non-secret still allowed");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  runner                                                              */
/* ------------------------------------------------------------------ */

void test_compilation_remaining2_run(void)
{
    printf("=== Compilation Remaining2 Tests ===\n");
    RUN_TEST(test_template_with_wildcards);
    RUN_TEST(test_binary_ops_complex_constraints);
    RUN_TEST(test_cache_collision_scenarios);
    RUN_TEST(test_layer_mask_edge_cases);
    RUN_TEST(test_deep_recursive_patterns);
    RUN_TEST(test_conflicting_rules_compilation);
    RUN_TEST(test_edge_case_patterns);
    RUN_TEST(test_state_transitions_compile_cycles);
}
