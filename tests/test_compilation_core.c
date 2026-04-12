/**
 * @file test_compilation_core.c
 * @brief Core compilation mechanics and edge cases.
 *
 * Consolidated from 12 functions into 5.
 *
 * Covers: pattern classification, subject constraints, zero-mode elimination,
 * template compilation, prefix matching, SPEC rules, static+dynamic intersection,
 * binary search boundaries, subject matching, and pattern edge cases.
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Pattern classification: pattern_covers_classified() all 9 branches */
/* ------------------------------------------------------------------ */

static void test_pattern_covers_all_combos(void)
{
    /* Case 1: Non-recursive exact shadows non-recursive exact (same pattern) */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: identical exact rules compile");
    soft_ruleset_free(rs);

    /* Case 2: Non-recursive exact shadows non-recursive single-star */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/*", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: exact shadows star");
    soft_ruleset_free(rs);

    /* Case 3: Recursive shadows non-recursive exact */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: recursive shadows exact");
    soft_ruleset_free(rs);

    /* Case 4: Recursive shadows recursive (same pattern) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: identical recursive rules compile");
    soft_ruleset_free(rs);

    /* Case 5: double-star shadows double-star */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: identical double-star rules compile");
    soft_ruleset_free(rs);

    /* Case 6: double-star shadows more specific double-star */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/usr/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/usr/local/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: broader double-star shadows narrower");
    soft_ruleset_free(rs);

    /* Case 7: Exact doesn't shadow exact (different path) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/other.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: different exact rules don't shadow");
    soft_ruleset_free(rs);

    /* Case 8: Recursive doesn't shadow non-recursive (different base) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/other/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: different bases don't shadow");
    soft_ruleset_free(rs);

    /* Case 9: Single-star shadows single-star (broader pattern) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/*", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/x", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "covers: single-star shadows exact");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Subject constraints: redundancy, exact, suffix, and edge cases     */
/* ------------------------------------------------------------------ */

static void test_subject_constraints_and_redunancy(void)
{
    /* Subject rule redundancy elimination */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*admin$", 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Both admin and non-admin should get READ */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_redundant: admin gets READ");

    ctx.subject = "/usr/bin/user";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_redundant: non-admin also gets READ");

    soft_ruleset_free(rs);

    /* compiled_subject_matches() exact string match (no suffix pattern) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "/usr/bin/sudo", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Exact match */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/sudo", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_exact: exact subject matches");

    /* NULL subject with regex present -> denied */
    ctx.subject = NULL;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "subject_exact: NULL subject denied when regex present");

    soft_ruleset_free(rs);

    /* Subject suffix matching with various patterns */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Subject ending with "admin" matches */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "admin", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_suffix: bare 'admin' matches");

    /* Subject ending with "sudo" doesn't match */
    ctx.subject = "/usr/bin/sudo";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "subject_suffix: 'sudo' doesn't match 'admin'");

    soft_ruleset_free(rs);

    /* Subject exact match (no suffix pattern) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, "/usr/bin/admin", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Exact match */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "subject_exact: exact subject matches");

    /* Partial prefix denied */
    ctx.subject = "/usr/bin";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "subject_exact: partial prefix denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Zero-mode elimination, template, prefix match, and SPEC tests      */
/* ------------------------------------------------------------------ */

static void test_zero_mode_template_prefix_and_spec(void)
{
    /* Zero-mode elimination: disjoint modes result in denial */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/...", SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "zero_mode: disjoint modes result in denial");

    soft_ruleset_free(rs);

    /* Template compilation */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/data/file.txt", "/dst/out.txt", NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "template: COPY denied (no DST rule)");

    soft_ruleset_free(rs);

    /* Compiled prefix match (binary search) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/project", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* /data/project/sub matches /data/project prefix */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/project/sub", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "prefix_match: matches /data/project prefix");

    /* /data/file matches /data prefix */
    ctx.src_path = "/data/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "prefix_match: matches /data prefix");

    soft_ruleset_free(rs);

    /* SPECIFICITY dynamic longest match */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/project/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/project/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_longest: single pattern wins");

    soft_ruleset_free(rs);

    /* SPECIFICITY DENY on compiled ruleset */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret/**", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/secret/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "spec_deny: SPECIFICITY DENY overrides PRECEDENCE");

    ctx.src_path = "/data/public/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "spec_deny: non-secret allowed by PRECEDENCE");

    soft_ruleset_free(rs);

    /* Compiled static + dynamic intersection */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/file.txt", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* /data/file.txt: static READ intersects dynamic READ|WRITE = READ */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "intersect: static READ & dynamic READ|WRITE = READ");

    /* /data/other.txt: only dynamic matches -> READ|WRITE */
    ctx.src_path = "/data/other.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "intersect: only dynamic matches -> READ|WRITE");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Binary search and exact-match boundaries                           */
/* ------------------------------------------------------------------ */

static void test_binary_search_and_exact_boundaries(void)
{
    /* Binary search: query path before all rules */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/zzz", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/aaa", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "binsearch_before: no match when query before all rules");
    soft_ruleset_free(rs);

    /* Pattern length equals query path length exactly */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/file.txt", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "exact_length: exact match at same length");
    ctx.src_path = "/data/file.txt/";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "exact_length: longer path matches as prefix");
    ctx.src_path = "/data/file";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "exact_length: shorter path doesn't match");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Pattern boundary and universal matching                            */
/* ------------------------------------------------------------------ */

static void test_pattern_boundary_and_universal_matching(void)
{
    /* Pattern at MAX_PATTERN_LEN boundary exact match */
    char pattern[260];
    memset(pattern, 'a', 255);
    pattern[255] = '\0';
    pattern[0] = '/';

    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, pattern, SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    soft_access_ctx_t ctx = {SOFT_OP_READ, pattern, NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "max_len_exact: exact max-length pattern matches");

    /* Different last character */
    char different[260];
    memcpy(different, pattern, 255);
    different[254] = 'z';
    different[255] = '\0';
    ctx.src_path = different;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "max_len_exact: different last char doesn't match");

    /* Shorter prefix doesn't match */
    char shorter[260];
    memcpy(shorter, pattern, 10);
    shorter[10] = '\0';
    ctx.src_path = shorter;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "max_len_exact: shorter prefix doesn't match");

    soft_ruleset_free(rs);

    /* Pattern with only double-star matches everything */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    /* All paths should match */
    const char *paths[] = {"/", "/a", "/a/b", "/a/b/c/file.txt", "/data/file.txt"};
    size_t i;
    for (i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
        ctx = (soft_access_ctx_t){SOFT_OP_READ, paths[i], NULL, NULL, 1000};
        TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                       "ds_universal: matches every path");
    }

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  runner                                                              */
/* ------------------------------------------------------------------ */

void test_compilation_core_run(void)
{
    printf("=== Compilation Core Tests ===\n");
    RUN_TEST(test_pattern_covers_all_combos);
    RUN_TEST(test_subject_constraints_and_redunancy);
    RUN_TEST(test_zero_mode_template_prefix_and_spec);
    RUN_TEST(test_binary_search_and_exact_boundaries);
    RUN_TEST(test_pattern_boundary_and_universal_matching);
}
