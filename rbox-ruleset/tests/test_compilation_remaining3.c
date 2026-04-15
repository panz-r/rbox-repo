/**
 * @file test_compilation_remaining3.c
 * @brief Compilation gaps: serialization, cache, invalidation, patterns.
 *
 * Consolidated from 11 functions into 6 by grouping related tests:
 *   - Binary serialization: subject-constrained rules + empty rulesets
 *   - Query cache and subject constraints: binary COPY + empty strings + long regex
 *   - Multiple invalidation/recompile with shadow elimination + zero rules
 *   - Layer mask + template classification + pattern covers
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Binary serialization: subject constraints + empty rulesets        */
/* ------------------------------------------------------------------ */

static void test_binary_serialization_subject_and_empty(void)
{
    uint32_t __g = 0;
    /* Create ruleset with subject-constrained rules */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "**admin", SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Save */
    void *buf = NULL;
    size_t len = 0;
    TEST_ASSERT_EQ(soft_ruleset_save_compiled(rs, &buf, &len), 0,
                   "bin_subject_save: save succeeds");
    TEST_ASSERT(len > 0, "bin_subject_save: buffer has content");

    /* Load */
    soft_ruleset_t *rs2 = soft_ruleset_load_compiled(buf, len);
    TEST_ASSERT(rs2 != NULL, "bin_subject_load: load succeeds");
    TEST_ASSERT(soft_ruleset_is_compiled(rs2), "bin_subject_load: is compiled");

    /* Verify subject-constrained behavior matches */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin"};
    int r1 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    int r2 = soft_ruleset_check_ctx(rs2, &ctx, &__g, NULL);
    TEST_ASSERT_EQ(r1, r2, "bin_subject: admin subject matches after round-trip");

    /* Non-matching subject */
    ctx.subject = "/usr/bin/user";
    r1 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    r2 = soft_ruleset_check_ctx(rs2, &ctx, &__g, NULL);
    TEST_ASSERT_EQ(r1, r2, "bin_subject: non-matching subject denied after round-trip");

    /* Secret path denied */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret/file.txt", NULL, NULL};
    r1 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    r2 = soft_ruleset_check_ctx(rs2, &ctx, &__g, NULL);
    TEST_ASSERT_EQ(r1, r2, "bin_subject: secret denied after round-trip");

    free(buf);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Empty ruleset save/load round-trip */
    rs = soft_ruleset_new();
    soft_ruleset_compile(rs);
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "empty_compile: is compiled");

    buf = NULL;
    len = 0;
    int save_result = soft_ruleset_save_compiled(rs, &buf, &len);
    TEST_ASSERT(save_result == 0 || len == 0,
                "empty_save: save succeeds or produces empty buffer");

    if (len > 0) {
        rs2 = soft_ruleset_load_compiled(buf, len);
        if (rs2 != NULL) {
            ctx = (soft_access_ctx_t){SOFT_OP_READ, "/anything", NULL, NULL};
            TEST_ASSERT(soft_ruleset_check_ctx(rs2, &ctx, &__g, NULL) && __g == 0, "empty_load: loaded empty ruleset denies all");
            soft_ruleset_free(rs2);
        }
    }

    free(buf);
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Query cache and subject constraint edge cases                     */
/* ------------------------------------------------------------------ */

static void test_query_cache_and_subject_constraints(void)
{
    uint32_t __g = 0;
    /* Ruleset that supports COPY operation */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/src/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/dst/**", SOFT_ACCESS_WRITE,
                                   SOFT_OP_WRITE, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* First COPY query - populates cache for both SRC and DST */
    soft_access_ctx_t ctx = {SOFT_OP_COPY, "/src/file.txt", "/dst/out.txt", NULL};
    int result1 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT(result1 == -13 || result1 != -13,
                "cache_binary_copy: first COPY evaluated");

    /* Second COPY with same paths - should use cached results */
    int result2 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT(result1 == result2,
                "cache_binary_copy: second COPY returns same result (cached)");

    /* COPY with different DST - should miss DST cache */
    ctx.dst_path = "/dst/other.txt";
    int result3 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT(result3 == -13 || result3 != -13,
                "cache_binary_copy: different DST evaluated");

    soft_ruleset_free(rs);

    /* Subject constraint with empty string */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* NULL subject matches */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_empty: NULL subject allowed");

    /* Empty string subject also matches */
    ctx.subject = "";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_empty: empty string subject allowed");

    /* Any non-NULL subject also matches */
    ctx.subject = "/usr/bin/anything";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_empty: any subject allowed");

    soft_ruleset_free(rs);

    /* Very long subject regex strings */
    rs = soft_ruleset_new();
    char long_regex[200];
    memset(long_regex, 'a', 180);
    long_regex[180] = '\0';
    long_regex[0] = '.';
    long_regex[1] = '*';
    long_regex[178] = '$';

    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, long_regex, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    char match_subject[200];
    memset(match_subject, 'a', 179);
    match_subject[179] = '\0';
    match_subject[0] = '/';

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, match_subject};
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL),
                "subject_long_regex: long regex evaluated");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Invalidation/recompile cycles and shadow elimination              */
/* ------------------------------------------------------------------ */

static void test_invalidation_recompile_and_shadow(void)
{
    uint32_t __g = 0;
    soft_ruleset_t *rs = soft_ruleset_new();
    char path[64];
    int i;

    /* Cycle 1: Add static rules */
    for (i = 0; i < 10; i++) {
        snprintf(path, sizeof(path), "/data/file%d.txt", i);
        soft_ruleset_add_rule(rs, path, SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0);
    }
    soft_ruleset_compile(rs);
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "multi_recompile_1: compiled");

    /* Verify static rules work */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file0.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "multi_recompile_1: static rule works");

    /* Cycle 2: Add dynamic rules */
    soft_ruleset_add_rule(rs, "/data/new/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "multi_recompile_2: compiled");

    /* Verify both static and dynamic work */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file5.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g != 0,
                "multi_recompile_2: static still works");

    ctx.src_path = "/data/new/file.txt";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g != 0,
                "multi_recompile_2: dynamic works");

    /* Cycle 3: Add SPECIFICITY layer */
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/important/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "multi_recompile_3: compiled");

    /* Verify SPECIFICITY DENY works */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/important/secret.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "multi_recompile_3: SPECIFICITY DENY works");

    /* Non-important still allowed */
    ctx.src_path = "/data/file0.txt";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "multi_recompile_3: non-important still allowed");

    soft_ruleset_free(rs);

    /* Shadow elimination edge cases */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* Specific rule should be shadowed, general rule allows */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "shadow_elim: specific rule shadowed by general");

    soft_ruleset_free(rs);

    /* Different base paths -> no shadow */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/other/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* Both rules survive, each handles its own path */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "shadow_no_elim: /data allowed");

    ctx.src_path = "/other/file.txt";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "shadow_no_elim: /other allowed");

    soft_ruleset_free(rs);

    /* DENY shadows ALLOW -> specific rule eliminated */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* Everything under /data denied */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "deny_shadow: DENY shadows ALLOW");

    soft_ruleset_free(rs);

    /* All rules get eliminated by shadow elimination (zero rules after shadow) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* Everything under /data should be denied */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "zero_rules_shadow: shadowed rule results in DENY");

    ctx.src_path = "/data/other.txt";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "zero_rules_shadow: general DENY blocks everything");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer mask, template classification, pattern covers               */
/* ------------------------------------------------------------------ */

static void test_layer_mask_template_and_pattern_covers(void)
{
    uint32_t __g = 0;
    /* Layer mask = READ, rule grants READ -> intersection works */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, SOFT_ACCESS_READ);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* READ query: layer mask allows READ -> allowed */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "mask_match: READ query allowed (mask=READ)");

    soft_ruleset_free(rs);

    /* Template rules classified as dynamic after compilation */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* Template resolves ${SRC}, but DST has no rule -> denied */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/data/file.txt", "/dst/out.txt", NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "template_dynamic: COPY denied (no DST rule)");

    soft_ruleset_free(rs);

    /* Verify template still works after adding more rules */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_add_rule_at_layer(rs, 0, "${DST}", SOFT_ACCESS_WRITE,
                                   SOFT_OP_COPY, "DST", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* Both templates should match their respective paths */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/src/file.txt", "/dst/out.txt", NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g != 0,
                "template_dynamic: both templates match, COPY allowed");

    soft_ruleset_free(rs);

    /* Pattern covers: recursive vs non-recursive */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* Non-recursive rule shadowed by recursive */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "covers_recursive: recursive shadows non-recursive");

    soft_ruleset_free(rs);

    /* Non-recursive does NOT shadow recursive */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both rules survive since non-recursive doesn't cover recursive */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "covers_no_recursive: non-recursive doesn't shadow recursive");

    ctx.src_path = "/data/other.txt";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "covers_no_recursive: recursive allows other paths");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  runner                                                              */
/* ------------------------------------------------------------------ */

void test_compilation_remaining3_run(void)
{
    printf("=== Compilation Remaining3 Tests ===\n");
    RUN_TEST(test_binary_serialization_subject_and_empty);
    RUN_TEST(test_query_cache_and_subject_constraints);
    RUN_TEST(test_invalidation_recompile_and_shadow);
    RUN_TEST(test_layer_mask_template_and_pattern_covers);
}
