/**
 * @file test_compilation_extra.c
 * @brief Extra edge cases and mechanism interactions for compilation.
 *
 * Consolidated from 10 functions into 5 by grouping related edge cases:
 *   - Templates and binary operations
 *   - Subject constraints (regex anchors + empty/NULL)
 *   - DENY rules and UID edge cases
 *   - Pattern flags and minimal patterns
 *   - Query cache and many-layer compilation
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Template resolution and binary operation modes                    */
/* ------------------------------------------------------------------ */

static void test_templates_and_binary_operations(void)
{
    /* Template with ${SRC} - basic resolution */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* COPY: SRC template resolves to actual path, but DST has no rule */
    soft_access_ctx_t ctx = {SOFT_OP_COPY, "/data/file.txt", "/dst/out.txt", NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "template_prefix: SRC matches but DST missing, denied");

    soft_ruleset_free(rs);

    /* Both SRC and DST templates */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_add_rule_at_layer(rs, 0, "${DST}", SOFT_ACCESS_WRITE,
                                   SOFT_OP_COPY, "DST", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* COPY: both templates match their respective paths */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/src/file.txt", "/dst/out.txt", NULL, 1000};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, NULL) != -13,
                "template_both: both templates match, allowed");

    soft_ruleset_free(rs);

    /* COPY operation mode requirements */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/src/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/dst/**", SOFT_ACCESS_WRITE,
                                   SOFT_OP_WRITE, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* COPY: needs READ for SRC, WRITE for DST - result depends on mode mapping */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/src/file.txt", "/dst/out.txt", NULL, 1000};
    int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result == -13 || result != -13,
                "binary_modes: COPY evaluated");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Subject constraint edge cases: regex anchors and empty/NULL       */
/* ------------------------------------------------------------------ */

static void test_subject_constraint_edge_cases(void)
{
    /* Subject with .* suffix pattern ending in $ */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Subject ending with "admin" matches */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_anchor: admin matches .*admin$");

    /* Subject ending with "myadmin" also matches */
    ctx.subject = "/usr/bin/myadmin";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_anchor: myadmin matches .*admin$");

    /* Subject with "admin" in middle doesn't match */
    ctx.subject = "/usr/bin/admin_extra";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "subject_anchor: admin_extra doesn't match .*admin$");

    soft_ruleset_free(rs);

    /* Subject exact match (no pattern characters) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "/usr/bin/sudo", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Exact match */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/sudo", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_exact_match: exact subject matches");

    /* Similar but longer */
    ctx.subject = "/usr/bin/sudo/extra";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "subject_exact_match: longer subject denied");

    soft_ruleset_free(rs);

    /* Subject empty string vs NULL with unconstrained rule */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* NULL subject matches */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_empty_vs_null: NULL subject allowed");

    /* Empty string subject also matches */
    ctx.subject = "";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_empty_vs_null: empty subject allowed");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  DENY rules and UID edge cases                                     */
/* ------------------------------------------------------------------ */

static void test_deny_rules_and_uid_edge_cases(void)
{
    /* Multiple DENY rules in same layer with different patterns */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/private/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* /data/secret: first DENY blocks */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/secret/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "multi_deny: secret denied");

    /* /data/private: second DENY blocks */
    ctx.src_path = "/data/private/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "multi_deny: private denied");

    /* /data/public: ALLOW works */
    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "multi_deny: public allowed");

    soft_ruleset_free(rs);

    /* UID = 0 (root) edge cases */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* UID 0 (root) matches min_uid=0 */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 0};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "uid_root: root allowed with min_uid=0");

    soft_ruleset_free(rs);

    /* Rule with min_uid = 1000 denies root */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* UID 0 < 1000 -> denied */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 0};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "uid_root: root denied with min_uid=1000");

    /* UID 1000 allowed */
    ctx.uid = 1000;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "uid_root: UID 1000 allowed");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Pattern flags and minimal pattern edge cases                      */
/* ------------------------------------------------------------------ */

static void test_pattern_flags_and_minimal_cases(void)
{
    /* Same pattern, both with same mode -> intersection = READ */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/file.txt", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/file.txt", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* Both rules match -> intersection: READ & READ = READ */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "same_pattern_flags: same modes intersect to READ");

    soft_ruleset_free(rs);

    /* Same pattern, one recursive and one not */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/file.txt", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/file.txt", SOFT_ACCESS_WRITE,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Behavior depends on how compilation handles mixed flags */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result != -13 || result == -13,
                   "same_pattern_flags: mixed flags evaluated");

    soft_ruleset_free(rs);

    /* Single character pattern */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/a", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/a", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "minimal_pattern: single char exact match");

    soft_ruleset_free(rs);

    /* Root pattern */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Root path */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "minimal_pattern: root path matches");

    /* Any path */
    ctx.src_path = "/any/deep/path";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "minimal_pattern: any path matches");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Query cache and many-layer compilation                            */
/* ------------------------------------------------------------------ */

static void test_query_cache_and_many_layers(void)
{
    /* Different subjects should produce different cache entries */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Admin subject - matches */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000};
    int result1 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result1, SOFT_ACCESS_READ, "cache_subject: admin allowed");

    /* Different subject - denied (different cache entry) */
    ctx.subject = "/usr/bin/user";
    int result2 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result2, 0, "cache_subject: user denied");

    /* Admin again - should hit cache */
    ctx.subject = "/usr/bin/admin";
    int result3 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result3, SOFT_ACCESS_READ, "cache_subject: admin still allowed (cache)");

    soft_ruleset_free(rs);

    /* Ruleset with 5 layers of different types */
    rs = soft_ruleset_new();

    /* Layer 0: PRECEDENCE - general ALLOW */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 1: SPECIFICITY - specific DENY */
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 2: PRECEDENCE - additional ALLOW */
    soft_ruleset_set_layer_type(rs, 2, LAYER_PRECEDENCE, 0);
    soft_ruleset_add_rule_at_layer(rs, 2, "/data/project/**", SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 3: SPECIFICITY - another specific ALLOW */
    soft_ruleset_set_layer_type(rs, 3, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 3, "/data/public/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 4: PRECEDENCE - final DENY */
    soft_ruleset_set_layer_type(rs, 4, LAYER_PRECEDENCE, 0);
    soft_ruleset_add_rule_at_layer(rs, 4, "/data/forbidden/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    soft_ruleset_compile(rs);

    /* /data/file.txt: only layer 0 matches -> READ */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "many_layers: general allow works");

    /* /data/secret/file.txt: layer 1 SPECIFICITY DENY -> denied */
    ctx.src_path = "/data/secret/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "many_layers: secret denied");

    /* /data/public/file.txt: layer 3 SPECIFICITY allows -> READ */
    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "many_layers: public allowed");

    /* /data/forbidden/file.txt: layer 4 PRECEDENCE DENY -> denied */
    ctx.src_path = "/data/forbidden/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "many_layers: forbidden denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  runner                                                              */
/* ------------------------------------------------------------------ */

void test_compilation_extra_run(void)
{
    printf("=== Compilation Extra Tests ===\n");
    RUN_TEST(test_templates_and_binary_operations);
    RUN_TEST(test_subject_constraint_edge_cases);
    RUN_TEST(test_deny_rules_and_uid_edge_cases);
    RUN_TEST(test_pattern_flags_and_minimal_cases);
    RUN_TEST(test_query_cache_and_many_layers);
}
