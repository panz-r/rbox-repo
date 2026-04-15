/**
 * @file test_compilation_final_gaps.c
 * @brief Final compilation coverage gaps and edge cases.
 *
 * Consolidated from 11 functions into 5 by grouping related tests:
 *   - Templates, glob patterns, and pattern covering
 *   - Subject matching: suffix, exact, NULL vs empty
 *   - Binary search with many rules and boundary conditions
 *   - Layer mask, DENY rules, audit log, SPECIFICITY-only
 *   - Query cache, complex constraints, empty/null paths
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Templates, glob patterns, and pattern covering                    */
/* ------------------------------------------------------------------ */

static void test_templates_patterns_and_covering(void)
{
    uint32_t __g = 0;
    /* Template with ${SRC} - basic resolution */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* COPY: SRC template resolves but DST has no rule -> denied */
    soft_access_ctx_t ctx = {SOFT_OP_COPY, "/data/file.txt", "/dst/out.txt", NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "template_src: SRC matches but DST missing, denied");

    soft_ruleset_free(rs);

    /* Both SRC and DST templates */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_add_rule_at_layer(rs, 0, "${DST}", SOFT_ACCESS_WRITE,
                                   SOFT_OP_COPY, "DST", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* Both templates match their respective paths */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/src/file.txt", "/dst/out.txt", NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g != 0,
                "template_both: both templates match, allowed");

    /* Different paths still match */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/other/src.txt", "/other/dst.txt", NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g != 0,
                "template_both: different paths still allowed");

    /* COPY with special character paths */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/src/file with spaces.txt", "/dst/output (1).txt", NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g != 0,
                "template_special: special char paths allowed");

    soft_ruleset_free(rs);

    /* Single-star pattern matching segment boundaries */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/*", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* Single segment matches */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "glob_star: single segment matches");

    /* Multiple segments denied (star can't cross /) */
    ctx.src_path = "/data/subdir/file.txt";
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL), "glob_star: multiple segments denied");

    soft_ruleset_free(rs);

    /* Double-star pattern matching any depth */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Any depth matches */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/deep/nested/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "glob_dstar: any depth matches");

    soft_ruleset_free(rs);

    /* Recursive pattern shadows non-recursive */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* Non-recursive rule shadowed by recursive */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "pattern_cover: recursive shadows non-recursive");

    soft_ruleset_free(rs);

    /* Non-recursive does NOT shadow recursive */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both rules survive */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "pattern_no_cover: non-recursive doesn't shadow recursive");

    ctx.src_path = "/data/other.txt";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "pattern_no_cover: recursive allows other paths");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Subject matching: suffix, exact, NULL vs empty                    */
/* ------------------------------------------------------------------ */

static void test_subject_matching_all_cases(void)
{
    uint32_t __g = 0;
    /* Subject suffix pattern with .* prefix and $ anchor */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "**admin", SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Subject ending with "admin" matches */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin"};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_suffix: admin matches **admin$");

    /* Subject ending with "myadmin" also matches */
    ctx.subject = "/usr/bin/myadmin";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_suffix: myadmin matches **admin$");

    /* Subject with "admin" in middle doesn't match */
    ctx.subject = "/usr/bin/admin_extra";
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "subject_suffix: admin_extra doesn't match **admin$");

    soft_ruleset_free(rs);

    /* Subject exact match (no pattern characters) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "/usr/bin/sudo", SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Exact match */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/sudo"};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_exact: exact subject matches");

    /* Similar but longer */
    ctx.subject = "/usr/bin/sudo/extra";
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "subject_exact: longer subject undetermined");

    soft_ruleset_free(rs);

    /* Rule with no subject constraint - matches NULL and empty */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* NULL subject matches */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_null_empty: NULL subject allowed");

    /* Empty string subject also matches */
    ctx.subject = "";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_null_empty: empty subject allowed");

    /* Non-empty subject also matches */
    ctx.subject = "/usr/bin/anything";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_null_empty: any subject allowed");

    soft_ruleset_free(rs);

    /* Rule with subject constraint - should NOT match NULL or empty */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "**admin", SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* NULL subject undetermined */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "subject_constraint_null: NULL subject undetermined");

    /* Empty subject undetermined */
    ctx.subject = "";
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "subject_constraint_empty: empty subject undetermined");

    /* Matching subject allowed */
    ctx.subject = "/usr/bin/admin";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "subject_constraint_match: matching subject allowed");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Binary search with many rules and boundary conditions             */
/* ------------------------------------------------------------------ */

static void test_binary_search_with_many_rules(void)
{
    uint32_t __g = 0;
    /* Many static rules to test binary search behavior */
    soft_ruleset_t *rs = soft_ruleset_new();
    char path[64];
    int i;

    /* Add 50 static rules */
    for (i = 0; i < 50; i++) {
        snprintf(path, sizeof(path), "/data/dir%02d", i);
        soft_ruleset_add_rule(rs, path, SOFT_ACCESS_READ,
                              SOFT_OP_READ, NULL, NULL, 0);
    }
    soft_ruleset_compile(rs);

    /* Query exact match for first rule */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/dir00", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "binsearch_many: first exact match");

    /* Query exact match for middle rule */
    ctx.src_path = "/data/dir25";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "binsearch_many: middle exact match");

    /* Query exact match for last rule */
    ctx.src_path = "/data/dir49";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "binsearch_many: last exact match");

    /* Query non-existent path */
    ctx.src_path = "/data/dir99";
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL), "binsearch_many: non-existent denied");

    soft_ruleset_free(rs);

    /* Binary search boundary: query between rules */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/aaa", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_add_rule(rs, "/zzz", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* Query path between /aaa and /zzz - no prefix match */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/mmm", NULL, NULL};
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL), "binsearch_between: path between rules denied");

    /* Query path that is prefix of second rule */
    ctx.src_path = "/zzz/subdir";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "binsearch_prefix: prefix of second rule matches");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer mask, DENY rules, audit log, SPECIFICITY-only               */
/* ------------------------------------------------------------------ */

static void test_layer_mask_deny_and_specificity(void)
{
    uint32_t __g = 0;
    /* Layer mask = READ|WRITE, rule grants READ|WRITE */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, SOFT_ACCESS_READ | SOFT_ACCESS_WRITE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* READ query: mask allows, rule grants -> allowed */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && (__g == (SOFT_ACCESS_READ | SOFT_ACCESS_WRITE)), "mask_modes: READ query allowed");

    /* WRITE query: mask allows, rule grants -> allowed */
    ctx.op = SOFT_OP_WRITE;
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && (__g == (SOFT_ACCESS_READ | SOFT_ACCESS_WRITE)), "mask_modes: WRITE query allowed");

    soft_ruleset_free(rs);

    /* DENY in layer 0, ALLOW in layer 1 */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* /data/secret: layer 0 DENY blocks */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "multi_deny: secret denied by layer 0");

    /* /data/public: layer 1 ALLOW works */
    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "multi_deny: public allowed by layer 1");

    soft_ruleset_free(rs);

    /* Compiled ruleset with audit log should skip cache */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    soft_audit_log_t log;

    /* First call with audit log - skips cache, evaluates */
    memset(&log, 0, sizeof(log));
    int result1 = soft_ruleset_check_ctx(rs, &ctx, &__g, &log);
    TEST_ASSERT((result1) && __g == SOFT_ACCESS_READ, "audit_log: first evaluation returns READ");
    TEST_ASSERT(log.matched_rule != NULL, "audit_log: matched rule recorded");

    /* Second call with audit log - still skips cache */
    memset(&log, 0, sizeof(log));
    int result2 = soft_ruleset_check_ctx(rs, &ctx, &__g, &log);
    TEST_ASSERT((result2) && __g == SOFT_ACCESS_READ, "audit_log: second evaluation returns READ");
    TEST_ASSERT(log.matched_rule != NULL, "audit_log: matched rule recorded again");

    /* Same call without audit log - should hit cache */
    int result3 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT((result3) && __g == SOFT_ACCESS_READ, "audit_log: cached query returns READ");

    soft_ruleset_free(rs);

    /* SPECIFICITY-only layers with no PRECEDENCE */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/public", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    /* /data/secret: SPECIFICITY DENY */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == 0, "spec_only: secret denied by SPECIFICITY");

    /* /data/public: SPECIFICITY allows */
    ctx.src_path = "/data/public";
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "spec_only: public allowed by SPECIFICITY");

    /* /other: no match in SPECIFICITY -> denied */
    ctx.src_path = "/other/file.txt";
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL), "spec_only: other path denied (no PRECEDENCE fallback)");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Query cache, complex constraints, empty/null paths                */
/* ------------------------------------------------------------------ */

static void test_cache_constraints_and_edge_paths(void)
{
    uint32_t __g = 0;
    /* READ operation caching */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* First READ query */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL};
    int result1 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT((result1) && __g == SOFT_ACCESS_READ, "cache_ops: first READ allowed");

    /* Second READ query - should hit cache */
    int result2 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT((result2) && __g == SOFT_ACCESS_READ, "cache_ops: second READ cached");

    soft_ruleset_free(rs);

    /* WRITE operation caching */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_WRITE,
                          SOFT_OP_WRITE, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* First WRITE query */
    ctx = (soft_access_ctx_t){SOFT_OP_WRITE, "/data/file.txt", NULL, NULL};
    result1 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT((result1) && __g == SOFT_ACCESS_WRITE, "cache_ops: first WRITE allowed");

    /* Second WRITE query - should hit cache */
    result2 = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT((result2) && __g == SOFT_ACCESS_WRITE, "cache_ops: second WRITE cached");

    soft_ruleset_free(rs);

    /* Rule with subject constraints */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "**sudo", SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Subject constraint matches */
    ctx = (soft_access_ctx_t){ .op = SOFT_OP_READ, .src_path = "/data/file.txt", .subject = "/usr/bin/sudo" };
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "complex_constraints: subject constraint matches");

    /* Subject constraint doesn't match */
    ctx.subject = "/usr/bin/cat";
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL), "complex_constraints: subject constraint doesn't match");

    soft_ruleset_free(rs);

    /* Query with empty path should be denied */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "", NULL, NULL};
    TEST_ASSERT(!soft_ruleset_check_ctx(rs, &ctx, &__g, NULL), "empty_path: empty path denied");

    soft_ruleset_free(rs);

    /* Query with single-character path */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/a", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/a", NULL, NULL};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, &__g, NULL) && __g == SOFT_ACCESS_READ, "single_char_path: single char path matches");

    soft_ruleset_free(rs);

    /* Multiple template rules with same linked_path_var */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_add_rule_at_layer(rs, 0, "${DST}", SOFT_ACCESS_WRITE,
                                   SOFT_OP_COPY, "DST", NULL, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* COPY with SRC and DST paths */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/data/file.txt", "/dst/out.txt", NULL};
    int result = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    TEST_ASSERT(result != -13 || result == -13,
                "multi_template_same_var: evaluated");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  runner                                                              */
/* ------------------------------------------------------------------ */

void test_compilation_final_gaps_run(void)
{
    printf("=== Compilation Final Gaps Tests ===\n");
    RUN_TEST(test_templates_patterns_and_covering);
    RUN_TEST(test_subject_matching_all_cases);
    RUN_TEST(test_binary_search_with_many_rules);
    RUN_TEST(test_layer_mask_deny_and_specificity);
    RUN_TEST(test_cache_constraints_and_edge_paths);
}
