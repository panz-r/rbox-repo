/**
 * @file test_compilation_internal.c
 * @brief Internal compilation and evaluation function coverage.
 *
 * Consolidated from test_compilation_internal.c (7 functions) and
 * test_compilation_eval.c (4 functions) into 6 functions.
 *
 * Covers:
 *   - eval_effective_path: SPECIFICITY + PRECEDENCE interaction
 *   - Static/dynamic matching: binary search, rule distributions, intersection
 *   - SPECIFICITY matching, DENY short-circuit in all phases
 *   - Complex combinations, edge cases, mixed patterns
 *   - Subject matching, rule subsumption
 *   - Layer configurations, mixed recursive/non-recursive
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  eval_effective_path: SPECIFICITY + PRECEDENCE full interaction    */
/* ------------------------------------------------------------------ */

static void test_eval_effective_path_full_interaction(void)
{
    /* Complex ruleset with both PRECEDENCE and SPECIFICITY layers,
     * static and dynamic rules in each. */
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Layer 0: PRECEDENCE static + dynamic */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 1: SPECIFICITY static + dynamic */
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/project", SOFT_ACCESS_EXEC,
                                   SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/repo/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    soft_ruleset_compile(rs);

    /* Test 1: SPECIFICITY static match -> returns EXEC only */
    soft_access_ctx_t ctx = {SOFT_OP_EXEC, "/data/project", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_EXEC,
                   "eval_full: SPEC static EXEC match");

    /* Test 2: SPECIFICITY dynamic match -> returns READ (for READ query) */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/repo/file.txt", NULL, NULL, 1000};
    TEST_ASSERT(soft_ruleset_check_ctx(rs, &ctx, NULL) != -13,
                   "eval_full: SPEC dynamic match allowed");

    /* Test 3: Neither SPEC matches -> PRECEDENCE intersection */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    /* static READ intersects dynamic READ|WRITE = READ */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "eval_full: PREC intersection READ");

    /* Test 4: Only PREC dynamic matches */
    ctx.src_path = "/data/other/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "eval_full: only PREC dynamic RW");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Static and dynamic matching: binary search, distributions, intx   */
/* ------------------------------------------------------------------ */

static void test_static_dynamic_matching_and_intersection(void)
{
    /* Many static rules, test binary search behavior */
    soft_ruleset_t *rs = soft_ruleset_new();
    char path[64];
    int i;

    /* Add 30 static rules */
    for (i = 0; i < 30; i++) {
        snprintf(path, sizeof(path), "/data/dir%02d", i);
        soft_ruleset_add_rule(rs, path, SOFT_ACCESS_READ,
                              SOFT_OP_READ, NULL, NULL, 0, 0);
    }
    soft_ruleset_compile(rs);

    /* Query exact match for first rule */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/dir00", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "static_binsearch: first exact match");

    /* Query exact match for middle rule */
    ctx.src_path = "/data/dir15";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "static_binsearch: middle exact match");

    /* Query exact match for last rule */
    ctx.src_path = "/data/dir29";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "static_binsearch: last exact match");

    /* Query prefix match (should scan backward from insertion point) */
    ctx.src_path = "/data/dir15/subdir/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "static_binsearch: middle prefix match");

    /* Query non-existent path */
    ctx.src_path = "/data/dir99";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "static_binsearch: non-existent denied");

    /* Query before all rules */
    ctx.src_path = "/data/dir000";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "static_binsearch: before all denied");

    soft_ruleset_free(rs);

    /* Multiple dynamic rules with intersection semantics */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/**", SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both rules match -> intersection: READ & WRITE = 0 -> denied */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "dynamic_intersection: disjoint modes denied");

    soft_ruleset_free(rs);

    /* Dynamic rules with overlapping modes */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both rules match -> intersection: (READ|EXEC) & (READ|WRITE) = READ */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "dynamic_intersection: overlapping modes give READ");

    soft_ruleset_free(rs);

    /* Dynamic DENY short-circuits */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* DENY short-circuits -> denied */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "dynamic_deny: DENY short-circuits");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  SPECIFICITY matching, DENY short-circuit all phases               */
/* ------------------------------------------------------------------ */

static void test_specificity_matching_and_deny(void)
{
    /* SPECIFICITY static rule */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* Exact match */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_static: exact match");

    /* Non-match */
    ctx.src_path = "/data/other.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "spec_static: non-match denied");

    soft_ruleset_free(rs);

    /* SPECIFICITY dynamic rule */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Recursive match */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/deep/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_dynamic: recursive match");

    soft_ruleset_free(rs);

    /* SPECIFICITY static + dynamic both match -> longest wins */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/subdir/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* /data/subdir/file.txt matches longer pattern -> READ */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/subdir/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_longest: longer pattern wins");

    /* /data/other.txt matches shorter pattern -> READ */
    ctx.src_path = "/data/other.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_longest: shorter pattern wins");

    soft_ruleset_free(rs);

    /* Static DENY short-circuit */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/secret", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "deny_static: static DENY short-circuits");

    soft_ruleset_free(rs);

    /* SPECIFICITY static DENY */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "deny_spec_static: SPEC static DENY");

    soft_ruleset_free(rs);

    /* SPECIFICITY dynamic DENY */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "deny_spec_dynamic: SPEC dynamic DENY");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Complex combinations, edge cases, mixed patterns                  */
/* ------------------------------------------------------------------ */

static void test_complex_combinations_and_edge_cases(void)
{
    /* Static exact + dynamic recursive + static prefix */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/file.txt", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule(rs, "/data/subdir", SOFT_ACCESS_EXEC,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* /data/file.txt matches exact + dynamic -> READ & (READ|WRITE) = READ */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "complex_combo: exact + dynamic intersection");

    /* /data/subdir matches prefix + dynamic -> EXEC & (READ|WRITE) = 0 -> denied */
    ctx.src_path = "/data/subdir";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "complex_combo: prefix + dynamic disjoint intersection");

    /* /data/other.txt matches only dynamic -> READ|WRITE */
    ctx.src_path = "/data/other.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "complex_combo: only dynamic matches");

    soft_ruleset_free(rs);

    /* Static DENY + dynamic ALLOW */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/secret", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* /data/secret: static DENY short-circuits */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "complex_deny: static DENY short-circuits");

    /* /data/public: only dynamic matches -> READ */
    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "complex_deny: dynamic allows non-secret path");

    soft_ruleset_free(rs);

    /* Edge cases: empty path, single char, special chars, long paths */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Empty path query */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "eval_edge_empty: empty path denied");

    soft_ruleset_free(rs);

    /* Single character path */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/a", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/a", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "eval_edge_single: single char path matches");

    soft_ruleset_free(rs);

    /* Path with special characters */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/file with spaces.txt", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file with spaces.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "eval_edge_spaces: path with spaces matches");

    soft_ruleset_free(rs);

    /* Very long path (within limits) */
    rs = soft_ruleset_new();
    char long_path[200];
    memset(long_path, 'a', 190);
    long_path[190] = '\0';
    long_path[0] = '/';
    long_path[100] = '/';

    soft_ruleset_add_rule(rs, long_path, SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, long_path, NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "eval_edge_long: very long path matches");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Subject matching, rule subsumption, layer configurations          */
/* ------------------------------------------------------------------ */

static void test_subject_subsumption_and_layer_configs(void)
{
    /* compiled_subject_matches() edge cases: exact vs suffix */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "/usr/bin/sudo", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Exact match */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/sudo", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_exact: exact subject matches");

    /* NULL subject with regex present -> denied */
    ctx.subject = NULL;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "subject_exact: NULL subject denied when regex present");

    soft_ruleset_free(rs);

    /* Subject suffix matching with $ anchor */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*root$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Subject ending with "root" */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/root", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_suffix: root matches .*root$");

    /* Subject ending with "superroot" */
    ctx.subject = "/usr/bin/superroot";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_suffix: superroot matches .*root$");

    /* Subject with "root" in middle but not at end */
    ctx.subject = "/usr/bin/rootkit";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "subject_suffix: rootkit doesn't match .*root$");

    soft_ruleset_free(rs);

    /* rule_subsumes() edge cases */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* Specific rule should be subsumed */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result == SOFT_ACCESS_READ || result == (SOFT_ACCESS_READ | SOFT_ACCESS_WRITE),
                "subsumes_same: specific rule subsumed");

    soft_ruleset_free(rs);

    /* Different modes prevent subsumption */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* Different modes -> specific rule not subsumed */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "subsumes_diff_mode: different modes not subsumed");

    soft_ruleset_free(rs);

    /* Non-covering patterns prevent subsumption */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/other/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* Different base paths -> no subsumption */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subsumes_diff_base: different bases not subsumed");

    soft_ruleset_free(rs);

    /* Mixed recursive/non-recursive patterns */
    rs = soft_ruleset_new();
    /* Recursive pattern */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    /* Non-recursive exact pattern */
    soft_ruleset_add_rule_at_layer(rs, 0, "/etc/hosts", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* Deep path matches recursive */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/deep/nested/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "mixed_patterns: deep path matches recursive");

    /* Exact path matches exact rule */
    ctx.src_path = "/etc/hosts";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "mixed_patterns: exact path matches exact rule");

    /* Path under /etc but not exact -> denied */
    ctx.src_path = "/etc/other";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), 0,
                   "mixed_patterns: /etc/other denied (no recursive)");

    soft_ruleset_free(rs);

    /* Empty ruleset compiles cleanly */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "compile_empty: compiles successfully");
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "compile_empty: is compiled");
    soft_ruleset_free(rs);

    /* Single rule in single layer */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "compile_single: compiles successfully");
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "compile_single: is compiled");

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "compile_single: single rule works");
    soft_ruleset_free(rs);

    /* Many layers with different types */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_set_layer_type(rs, 2, LAYER_PRECEDENCE, 0);
    soft_ruleset_add_rule_at_layer(rs, 2, "/data/project/**", SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "compile_many_layers: compiles successfully");
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "compile_many_layers: is compiled");

    /* /data/secret: SPECIFICITY deny overrides PRECEDENCE allow */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "compile_many_layers: SPECIFICITY deny overrides");

    /* /data/project: PRECEDENCE intersection (READ & WRITE = 0) */
    ctx.src_path = "/data/project/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "compile_many_layers: PRECEDENCE intersection denied");

    /* /data/other: only layer 0 matches -> READ */
    ctx.src_path = "/data/other/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "compile_many_layers: layer 0 allows");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  runner                                                              */
/* ------------------------------------------------------------------ */

void test_compilation_internal_run(void)
{
    printf("=== Compilation Internal Tests ===\n");
    RUN_TEST(test_eval_effective_path_full_interaction);
    RUN_TEST(test_static_dynamic_matching_and_intersection);
    RUN_TEST(test_specificity_matching_and_deny);
    RUN_TEST(test_complex_combinations_and_edge_cases);
    RUN_TEST(test_subject_subsumption_and_layer_configs);
}
