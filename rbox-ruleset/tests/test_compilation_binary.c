/**
 * @file test_compilation_binary.c
 * @brief Binary operations, serialization, and batch evaluation.
 *
 * Consolidated from 8 functions into 5.
 *
 * Covers: COPY/MOVE/LINK operations, binary serialization with corruption detection,
 * batch evaluation edge cases, query cache with binary operations.
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Binary operations and template linked variables                    */
/* ------------------------------------------------------------------ */

static void test_binary_ops_and_template_interactions(void)
{
    /* READ and WRITE operations on compiled rulesets */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/src/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule(rs, "/dst/**", SOFT_ACCESS_WRITE,
                          SOFT_OP_WRITE, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* READ query on /src should work */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/src/data.txt", NULL, NULL, 1000};
    int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result != -13, "binops_compiled: READ on /src allowed");

    /* WRITE query on /dst should work */
    ctx = (soft_access_ctx_t){SOFT_OP_WRITE, "/dst/output.txt", NULL, NULL, 1000};
    result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result != -13, "binops_compiled: WRITE on /dst allowed");

    soft_ruleset_free(rs);

    /* Template rules with different linked_path_var */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_add_rule_at_layer(rs, 0, "${DST}", SOFT_ACCESS_WRITE,
                                   SOFT_OP_COPY, "DST", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* COPY: both templates match their respective paths */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/data/file.txt", "/data/out.txt", NULL, 1000};
    result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(result != -13, "linked_var: both templates match, COPY allowed");
    soft_ruleset_free(rs);

    /* Template rules resolve to paths but DST may not have a rule */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);

    /* COPY: SRC matches template, but DST has no rule -> denied */
    ctx = (soft_access_ctx_t){SOFT_OP_COPY, "/data/file.txt", "/dst/out.txt", NULL, 1000};
    result = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result, -13, "template_resolve: SRC matches but DST missing, COPY denied");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Binary serialization: full round-trip with all variants            */
/* ------------------------------------------------------------------ */

static void test_binary_serialization_all_variants(void)
{
    /* Full round-trip with multiple rule types */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/usr/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC,
                                   SOFT_OP_EXEC, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/project/...", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, ".*admin$", 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* Save */
    void *buf = NULL;
    size_t len = 0;
    TEST_ASSERT_EQ(soft_ruleset_save_compiled(rs, &buf, &len), 0,
                   "bin_full: save succeeds");
    TEST_ASSERT(buf != NULL, "bin_full: buffer not NULL");
    TEST_ASSERT(len > 0, "bin_full: length > 0");

    /* Load */
    soft_ruleset_t *rs2 = soft_ruleset_load_compiled(buf, len);
    TEST_ASSERT(rs2 != NULL, "bin_full: load succeeds");
    TEST_ASSERT(soft_ruleset_is_compiled(rs2), "bin_full: loaded ruleset is compiled");

    /* Verify behavior matches */
    struct { const char *path; soft_binary_op_t op; const char *subject; uid_t uid; } queries[] = {
        {"/usr/bin/gcc", SOFT_OP_EXEC, NULL, 1000},
        {"/data/file.txt", SOFT_OP_READ, NULL, 1000},
        {"/secret", SOFT_OP_READ, NULL, 1000},
        {"/data/project/file.txt", SOFT_OP_READ, "/usr/bin/admin", 1000},
        {"/data/project/file.txt", SOFT_OP_READ, "/usr/bin/user", 1000},
    };

    size_t i;
    for (i = 0; i < sizeof(queries)/sizeof(queries[0]); i++) {
        soft_access_ctx_t ctx = {queries[i].op, queries[i].path, NULL, queries[i].subject, queries[i].uid};
        int r1 = soft_ruleset_check_ctx(rs, &ctx, NULL);
        int r2 = soft_ruleset_check_ctx(rs2, &ctx, NULL);
        TEST_ASSERT_EQ(r1, r2, "bin_full: query matches after round-trip");
    }

    free(buf);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Corruption detection */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    buf = NULL; len = 0;
    soft_ruleset_save_compiled(rs, &buf, &len);
    unsigned char *p = (unsigned char *)buf;

    /* Corrupt payload */
    p[20] ^= 0xFF;
    TEST_ASSERT(soft_ruleset_load_compiled(buf, len) == NULL, "bin_full: payload corruption detected");
    p[20] ^= 0xFF;

    /* Corrupt CRC */
    p[len - 7] ^= 0xFF;
    TEST_ASSERT(soft_ruleset_load_compiled(buf, len) == NULL, "bin_full: CRC corruption detected");
    p[len - 7] ^= 0xFF;

    /* Corrupt FNV */
    p[len - 3] ^= 0xFF;
    TEST_ASSERT(soft_ruleset_load_compiled(buf, len) == NULL, "bin_full: FNV corruption detected");
    p[len - 3] ^= 0xFF;

    /* Bad magic */
    p[0] = 'X';
    TEST_ASSERT(soft_ruleset_load_compiled(buf, len) == NULL, "bin_full: bad magic rejected");

    /* Version mismatch */
    p[0] = 'R';
    p[5] = 0xFF;
    TEST_ASSERT(soft_ruleset_load_compiled(buf, len) == NULL, "bin_full: version mismatch rejected");

    /* Truncated buffer */
    TEST_ASSERT(soft_ruleset_load_compiled(buf, len / 2) == NULL, "bin_full: truncated buffer rejected");

    free(buf);
    soft_ruleset_free(rs);

    /* Binary serialization with subject constraints */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    buf = NULL; len = 0;
    TEST_ASSERT_EQ(soft_ruleset_save_compiled(rs, &buf, &len), 0,
                   "bin_subject: save with subject constraint succeeds");

    rs2 = soft_ruleset_load_compiled(buf, len);
    TEST_ASSERT(rs2 != NULL, "bin_subject: load succeeds");

    /* Verify behavior matches */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000};
    int r1 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    int r2 = soft_ruleset_check_ctx(rs2, &ctx, NULL);
    TEST_ASSERT_EQ(r1, r2, "bin_subject: matching subject gives same result");

    ctx.subject = "/usr/bin/user";
    r1 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    r2 = soft_ruleset_check_ctx(rs2, &ctx, NULL);
    TEST_ASSERT_EQ(r1, r2, "bin_subject: non-matching subject gives same result");

    /* NULL subject behavior also matches */
    ctx.subject = NULL;
    r1 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    r2 = soft_ruleset_check_ctx(rs2, &ctx, NULL);
    TEST_ASSERT_EQ(r1, r2, "bin_subject: NULL subject gives same result after round-trip");

    free(buf);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Binary serialization with only static rules */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/etc/hosts", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/etc/passwd", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/usr/bin/gcc", SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    buf = NULL; len = 0;
    TEST_ASSERT_EQ(soft_ruleset_save_compiled(rs, &buf, &len), 0,
                   "bin_only_static: save with only static rules succeeds");

    rs2 = soft_ruleset_load_compiled(buf, len);
    TEST_ASSERT(rs2 != NULL, "bin_only_static: load succeeds");

    /* Verify all rules work after round-trip */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/etc/hosts", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs2, &ctx, NULL), SOFT_ACCESS_READ,
                   "bin_only_static: first rule works");

    ctx.src_path = "/etc/passwd";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs2, &ctx, NULL), SOFT_ACCESS_READ,
                   "bin_only_static: second rule works");

    ctx = (soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/gcc", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs2, &ctx, NULL), SOFT_ACCESS_EXEC,
                   "bin_only_static: third rule works");

    /* Unmatched path should be denied */
    ctx = (soft_access_ctx_t){SOFT_OP_READ, "/etc/shadow", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs2, &ctx, NULL), 0,
                   "bin_only_static: unmatched path denied");

    free(buf);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Binary serialization with all rule types */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/etc/hosts", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ,
                                   SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/admin/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/restricted/...", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_compile(rs);

    buf = NULL; len = 0;
    TEST_ASSERT_EQ(soft_ruleset_save_compiled(rs, &buf, &len), 0,
                   "bin_all_types: save succeeds");

    rs2 = soft_ruleset_load_compiled(buf, len);
    TEST_ASSERT(rs2 != NULL, "bin_all_types: load succeeds");

    /* Verify all rule types work after round-trip */
    struct { const char *path; soft_binary_op_t op; const char *subject; uid_t uid; } tests[] = {
        {"/etc/hosts", SOFT_OP_READ, NULL, 1000},
        {"/data/file.txt", SOFT_OP_READ, NULL, 1000},
        {"/admin/config", SOFT_OP_READ, "/usr/bin/admin", 1000},
        {"/admin/config", SOFT_OP_READ, "/usr/bin/user", 1000},
        {"/restricted/file", SOFT_OP_READ, NULL, 1000},
        {"/restricted/file", SOFT_OP_READ, NULL, 500},
        {"/nowhere", SOFT_OP_READ, NULL, 1000},
    };

    for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        soft_access_ctx_t c = {tests[i].op, tests[i].path, NULL, tests[i].subject, tests[i].uid};
        int r1 = soft_ruleset_check_ctx(rs, &c, NULL);
        int r2 = soft_ruleset_check_ctx(rs2, &c, NULL);
        TEST_ASSERT_EQ(r1, r2, "bin_all_types: query matches after round-trip");
    }

    free(buf);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  Batch evaluation edge cases                                         */
/* ------------------------------------------------------------------ */

static void test_batch_evaluation_edge_cases(void)
{
    /* Batch with 0 entries should fail gracefully */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    const soft_access_ctx_t *ctxs[1];
    int results[1];
    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, ctxs, results, 0), -1,
                   "batch_zero: batch with 0 entries returns error");

    /* NULL ctxs array should also fail */
    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, NULL, results, 1), -1,
                   "batch_zero: NULL ctxs array returns error");

    soft_ruleset_free(rs);

    /* Batch with all paths denied */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);

    soft_access_ctx_t ctx_arr[3];
    memset(ctx_arr, 0, sizeof(ctx_arr));
    ctx_arr[0].op = SOFT_OP_READ; ctx_arr[0].src_path = "/data/secret"; ctx_arr[0].uid = 1000;
    ctx_arr[1].op = SOFT_OP_READ; ctx_arr[1].src_path = "/other/file.txt"; ctx_arr[1].uid = 1000;
    ctx_arr[2].op = SOFT_OP_READ; ctx_arr[2].src_path = "/data/secret"; ctx_arr[2].uid = 1000;
    const soft_access_ctx_t *c[3];
    c[0] = &ctx_arr[0]; c[1] = &ctx_arr[1]; c[2] = &ctx_arr[2];

    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, c, results, 3), 0,
                   "batch_all_denied: batch succeeds");
    TEST_ASSERT_EQ(results[0], -13, "batch_all_denied: first path denied");
    TEST_ASSERT_EQ(results[1], -13, "batch_all_denied: second path denied");
    TEST_ASSERT_EQ(results[2], -13, "batch_all_denied: third path denied");

    soft_ruleset_free(rs);

    /* Batch with mixed cache hit/miss */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* First query to populate cache */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file1.txt", NULL, NULL, 1000};
    soft_ruleset_check_ctx(rs, &ctx, NULL);

    /* Batch: first entry cached, others not */
    memset(ctx_arr, 0, sizeof(ctx_arr));
    ctx_arr[0].op = SOFT_OP_READ; ctx_arr[0].src_path = "/data/file1.txt"; ctx_arr[0].uid = 1000;
    ctx_arr[1].op = SOFT_OP_READ; ctx_arr[1].src_path = "/data/file2.txt"; ctx_arr[1].uid = 1000;
    ctx_arr[2].op = SOFT_OP_READ; ctx_arr[2].src_path = "/data/file3.txt"; ctx_arr[2].uid = 1000;
    c[0] = &ctx_arr[0]; c[1] = &ctx_arr[1]; c[2] = &ctx_arr[2];

    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, c, results, 3), 0,
                   "batch_mixed: batch succeeds");
    TEST_ASSERT_EQ(results[0], SOFT_ACCESS_READ, "batch_mixed: cached path allowed");
    TEST_ASSERT_EQ(results[1], SOFT_ACCESS_READ, "batch_mixed: uncached path1 allowed");
    TEST_ASSERT_EQ(results[2], SOFT_ACCESS_READ, "batch_mixed: uncached path2 allowed");

    /* Batch with NULL entry in middle */
    c[1] = NULL;
    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, c, results, 3), 0,
                   "batch_null_entry: batch with NULL entry succeeds");
    TEST_ASSERT_EQ(results[0], SOFT_ACCESS_READ, "batch_null_entry: first result correct");
    TEST_ASSERT_EQ(results[1], -13, "batch_null_entry: NULL entry returns -EACCES");
    TEST_ASSERT_EQ(results[2], SOFT_ACCESS_READ, "batch_null_entry: third result correct");

    soft_ruleset_free(rs);

    /* Batch with different subjects/UIDs */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, ".*admin$", 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    memset(ctx_arr, 0, sizeof(ctx_arr));
    ctx_arr[0].op = SOFT_OP_READ; ctx_arr[0].src_path = "/data/file.txt";
    ctx_arr[0].subject = "/usr/bin/admin"; ctx_arr[0].uid = 1000;
    ctx_arr[1].op = SOFT_OP_READ; ctx_arr[1].src_path = "/data/file.txt";
    ctx_arr[1].subject = "/usr/bin/admin"; ctx_arr[1].uid = 500;
    ctx_arr[2].op = SOFT_OP_READ; ctx_arr[2].src_path = "/data/file.txt";
    ctx_arr[2].subject = "/usr/bin/user"; ctx_arr[2].uid = 1000;
    c[0] = &ctx_arr[0]; c[1] = &ctx_arr[1]; c[2] = &ctx_arr[2];

    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, c, results, 3), 0,
                   "batch_subjects_uids: batch succeeds");
    TEST_ASSERT_EQ(results[0], SOFT_ACCESS_READ, "batch_subjects_uids: matching subject+uid allowed");
    TEST_ASSERT_EQ(results[1], -13, "batch_subjects_uids: matching subject but low uid denied");
    TEST_ASSERT_EQ(results[2], -13, "batch_subjects_uids: non-matching subject denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Query cache with binary operations                                  */
/* ------------------------------------------------------------------ */

static void test_query_cache_binary_operations(void)
{
    /* Binary operation where both SRC and DST are cached */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/src/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/dst/**", SOFT_ACCESS_WRITE,
                                   SOFT_OP_WRITE, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);

    /* First MOVE to populate cache for both paths */
    soft_access_ctx_t ctx = {SOFT_OP_MOVE, "/src/file.txt", "/dst/out.txt", NULL, 1000};
    int result1 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result1, -13, "cache_bin_both: first MOVE result");

    /* Second MOVE with same paths - should hit cache for both */
    int result2 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result2, -13, "cache_bin_both: cached MOVE returns same");

    /* Third call should also return same cached result */
    int result3 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(result3, -13, "cache_bin_both: third cached MOVE returns same");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  runner                                                              */
/* ------------------------------------------------------------------ */

void test_compilation_binary_run(void)
{
    printf("=== Compilation Binary Tests ===\n");
    RUN_TEST(test_binary_ops_and_template_interactions);
    RUN_TEST(test_binary_serialization_all_variants);
    RUN_TEST(test_batch_evaluation_edge_cases);
    RUN_TEST(test_query_cache_binary_operations);
}
