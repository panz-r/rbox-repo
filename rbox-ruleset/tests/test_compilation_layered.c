/**
 * @file test_compilation_layered.c
 * @brief Layer interactions, masks, DENY/ALLOW, and SPECIFICITY behavior.
 *
 * Consolidated from 9 functions into 6.
 *
 * Covers: PRECEDENCE/SPECIFICITY layer interactions, layer mask filtering,
 * DENY/ALLOW overlap behavior, mode intersection across layers, subject constraints
 * in compiled rulesets.
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  DENY short-circuit behavior across SPEC and PREC                   */
/* ------------------------------------------------------------------ */

static void test_deny_short_circuit_behavior(void)
{
    /* SPECIFICITY static DENY overrides PRECEDENCE */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "spec_static_deny: SPECIFICITY static DENY overrides PRECEDENCE");

    ctx.src_path = "/data/other/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_static_deny: non-secret allowed by PRECEDENCE");

    soft_ruleset_free(rs);

    /* Static DENY exact short-circuit */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/etc/shadow", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/etc/shadow", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/etc/shadow", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "static_deny_exact: exact DENY short-circuits intersection");

    soft_ruleset_free(rs);

    /* PRECEDENCE dynamic DENY short-circuit */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/project/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/anything/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "prec_dynamic_deny: PRECEDENCE dynamic DENY short-circuits");

    ctx.src_path = "/data/project/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "prec_dynamic_deny: DENY applies even to nested paths");

    soft_ruleset_free(rs);

    /* SPECIFICITY dynamic DENY overrides PRECEDENCE ALLOW */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret/passwords", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "spec_dynamic_deny: SPEC dynamic DENY overrides PRECEDENCE");

    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_dynamic_deny: non-secret allowed by PRECEDENCE");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  All four evaluation buckets populated                              */
/* ------------------------------------------------------------------ */

static void test_four_buckets_integration(void)
{
    /* Create a ruleset that populates ALL four compiled buckets:
     *   PRECEDENCE static, PRECEDENCE dynamic,
     *   SPECIFICITY static, SPECIFICITY dynamic */
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Layer 0: PRECEDENCE */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/static", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 1: SPECIFICITY */
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/project", SOFT_ACCESS_EXEC,
                                   SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/repo/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    soft_ruleset_compile(rs);

    /* Test 1: SPECIFICITY static match -> returns EXEC only */
    soft_access_ctx_t ctx = {SOFT_OP_EXEC, "/data/project", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_EXEC,
                   "four_buckets: SPEC static EXEC match");

    /* Test 2: SPECIFICITY dynamic match -> returns RWX */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/repo/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC,
                   "four_buckets: SPEC dynamic RWX match");

    /* Test 3: Neither SPEC matches -> PRECEDENCE intersection */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/static", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "four_buckets: PREC intersection READ");

    /* Test 4: Only PREC dynamic matches */
    ctx.src_path = "/data/other/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "four_buckets: only PREC dynamic RW");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer mask filtering in compiled evaluation                        */
/* ------------------------------------------------------------------ */

static void test_layer_mask_compiled_evaluation(void)
{
    /* Layer mask skip for non-matching operation */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, SOFT_ACCESS_EXEC);
    soft_ruleset_add_rule_at_layer(rs, 0, "/usr/**", SOFT_ACCESS_EXEC,
                                   SOFT_OP_EXEC, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* EXEC query: Layer 0 mask allows EXEC, rule grants EXEC */
    soft_access_ctx_t ctx = {SOFT_OP_EXEC, "/usr/bin/gcc", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_EXEC,
                   "mask_op_skip: EXEC query matches EXEC-only layer");

    /* READ query: Layer 0 mask doesn't include READ bits -> layer skipped */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result == -13 || result == SOFT_ACCESS_READ,
                "mask_op_skip: READ query handled by SPECIFICITY layer");

    soft_ruleset_free(rs);

    /* Layer mask partial overlap */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, SOFT_ACCESS_READ | SOFT_ACCESS_WRITE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* READ query allowed */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result != -13, "mask_partial: READ query allowed");

    /* WRITE query also allowed */
    ctx.op = SOFT_OP_WRITE;
    result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result != -13, "mask_partial: WRITE query also allowed");

    soft_ruleset_free(rs);

    /* Multiple layers with different masks */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, SOFT_ACCESS_EXEC);
    soft_ruleset_add_rule_at_layer(rs, 0, "/bin/**", SOFT_ACCESS_EXEC,
                                   SOFT_OP_EXEC, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_set_layer_type(rs, 1, LAYER_PRECEDENCE, SOFT_ACCESS_READ);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* READ query: only layer 1 evaluated */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "layer_masks: READ query uses READ-masked layer");

    /* EXEC query: only layer 0 evaluated */
    ctx = (soft_access_ctx_t){SOFT_OP_EXEC, "/bin/program", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_EXEC,
                   "layer_masks: EXEC query uses EXEC-masked layer");

    /* WRITE query denied (no layer has WRITE mask) */
    ctx = (soft_access_ctx_t){SOFT_OP_WRITE, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "layer_masks: WRITE query denied (no WRITE mask)");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  DENY/ALLOW overlap and mode intersection across layers             */
/* ------------------------------------------------------------------ */

static void test_deny_allow_and_mode_intersection(void)
{
    /* Static DENY + dynamic ALLOW intersection */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "static_deny_dynamic_allow: DENY wins over ALLOW");

    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "static_deny_dynamic_allow: non-secret allowed");

    soft_ruleset_free(rs);

    /* Same pattern, same op_type, different modes -> intersection */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/...", SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both rules match -> intersection: READ & WRITE = 0 (disjoint) */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result, -13,
                   "same_pattern: disjoint modes result in denial");

    soft_ruleset_free(rs);

    /* Now with overlapping modes */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/...", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both rules match -> intersection: (READ|WRITE) & (READ|EXEC) = READ */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result, SOFT_ACCESS_READ,
                   "same_pattern: overlapping modes result in intersection");

    soft_ruleset_free(rs);

    /* Multiple DENY rules across static and dynamic buckets */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/forbidden/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Static DENY blocks */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "multi_deny: static DENY blocks /data/secret");

    /* Dynamic DENY blocks */
    ctx.src_path = "/data/forbidden/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "multi_deny: dynamic DENY blocks /data/forbidden/**");

    /* ALLOW grants access */
    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "multi_deny: ALLOW grants /data/public/**");

    /* Deep path under forbidden also denied */
    ctx.src_path = "/data/forbidden/deep/nested/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "multi_deny: deep forbidden path also denied");

    soft_ruleset_free(rs);

    /* Multiple PRECEDENCE layers with DENY in different layers */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret/...", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 2, "/data/private/...", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* /data/public: only layer 0 matches -> READ */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/public/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "multi_precedence_deny: public path allowed");

    /* /data/secret: layer 1 DENY blocks */
    ctx.src_path = "/data/secret/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "multi_precedence_deny: secret path denied by layer 1");

    /* /data/private: layer 2 DENY blocks */
    ctx.src_path = "/data/private/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "multi_precedence_deny: private path denied by layer 2");

    /* Deep secret path also denied */
    ctx.src_path = "/data/secret/deep/nested/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "multi_precedence_deny: deep secret path also denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  SPECIFICITY dynamic with subject constraints                       */
/* ------------------------------------------------------------------ */

static void test_specificity_dynamic_with_subject(void)
{
    /* SPECIFICITY dynamic rule with subject constraint */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/admin/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*sudo$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Matching subject */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/admin/config", NULL, "/usr/bin/sudo", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_dynamic_subject: matching subject allowed");

    /* Non-matching subject */
    ctx.subject = "/usr/bin/cat";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "spec_dynamic_subject: non-matching subject denied");

    /* Empty subject also denied */
    ctx.subject = "";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "spec_dynamic_subject: empty subject denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Subject + UID combined constraints in compiled ruleset             */
/* ------------------------------------------------------------------ */

static void test_subject_and_uid_combined_compiled(void)
{
    /* Rule with both subject regex and UID constraint */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*sudo$", 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both constraints satisfied */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/sudo", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "combined: subject+uid all satisfied");

    /* Matching subject, wrong UID */
    ctx.uid = 500;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "combined: matching subject but wrong UID denied");

    /* Correct UID, wrong subject */
    ctx.uid = 1000;
    ctx.subject = "/usr/bin/cat";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "combined: correct UID but wrong subject denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer type transitions across multiple layers                      */
/* ------------------------------------------------------------------ */

static void test_layer_type_transitions(void)
{
    /* Ruleset with PRECEDENCE -> SPECIFICITY -> PRECEDENCE transitions */
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Layer 0: PRECEDENCE */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 1: SPECIFICITY - overrides PRECEDENCE for matching paths */
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret/...", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 2: PRECEDENCE again */
    soft_ruleset_set_layer_type(rs, 2, LAYER_PRECEDENCE, 0);
    soft_ruleset_add_rule_at_layer(rs, 2, "/data/project/...", SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    soft_ruleset_compile(rs);

    /* /data/secret: SPECIFICITY DENY overrides PRECEDENCE -> denied */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/secret/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "layer_transitions: SPECIFICITY DENY overrides");

    /* /data/project: PRECEDENCE rules from layer 0 and layer 2
     * intersect. Layer 0 grants READ, layer 2 grants WRITE -> intersection = 0 -> denied */
    ctx.src_path = "/data/project/file.txt";
    int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result, -13,
                   "layer_transitions: PRECEDENCE intersection of disjoint modes denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  runner                                                              */
/* ------------------------------------------------------------------ */

void test_compilation_layered_run(void)
{
    printf("=== Compilation Layered Tests ===\n");
    RUN_TEST(test_deny_short_circuit_behavior);
    RUN_TEST(test_four_buckets_integration);
    RUN_TEST(test_layer_mask_compiled_evaluation);
    RUN_TEST(test_deny_allow_and_mode_intersection);
    RUN_TEST(test_specificity_dynamic_with_subject);
    RUN_TEST(test_subject_and_uid_combined_compiled);
    RUN_TEST(test_layer_type_transitions);
}
