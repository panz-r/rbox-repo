/**
 * @file test_rule_engine.c
 * @brief Unit tests for the Rule Engine (spec v3.0).
 */

#include "test_framework.h"
#include "rule_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Basic unary operations                                             */
/* ------------------------------------------------------------------ */

static void test_rule_engine_unary_read(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_NOT_NULL(rs, "ruleset creation");

    /* Allow reading from /usr */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/usr/*", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add read rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_READ,
        .src_path = "/usr/bin/bash",
        .dst_path = NULL,
        .subject = NULL,
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(ret > 0, "read from /usr/bin/bash allowed");

    /* Deny reading from /etc/shadow */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/etc/shadow", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add deny rule");

    ctx.src_path = "/etc/shadow";
    ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(ret, -13, "read from /etc/shadow denied");  /* -EACCES */

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Binary operations (COPY)                                           */
/* ------------------------------------------------------------------ */

static void test_rule_engine_copy_allowed(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Allow reading from /readonly */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/readonly/...", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add SRC read rule");

    /* Allow writing to /scratch */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/scratch/...", SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                                          SOFT_OP_COPY, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add DST write rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_COPY,
        .src_path = "/readonly/file.txt",
        .dst_path = "/scratch/output.txt",
        .subject = NULL,
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(ret > 0, "copy from /readonly to /scratch allowed");

    soft_ruleset_free(rs);
}

static void test_rule_engine_copy_denied_wrong_src(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Allow writing to /scratch, but no read rule for /home */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/scratch/...", SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                                          SOFT_OP_COPY, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add DST write rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_COPY,
        .src_path = "/home/user/secret",
        .dst_path = "/scratch/output.txt",
        .subject = NULL,
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(ret, -13, "copy denied when SRC has no read rule");

    soft_ruleset_free(rs);
}

static void test_rule_engine_copy_denied_wrong_dst(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Allow reading from /readonly, but no write rule for /etc */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/readonly/...", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add SRC read rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_COPY,
        .src_path = "/readonly/file.txt",
        .dst_path = "/etc/output.txt",
        .subject = NULL,
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(ret, -13, "copy denied when DST has no write rule");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Path variables (${SRC}, ${DST})                                    */
/* ------------------------------------------------------------------ */

static void test_rule_engine_path_variables(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Generic copy rule: ${SRC} can be read, ${DST} can be written */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "${SRC}", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, "SRC", NULL, 0, 0),
                   0, "add SRC variable rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "${DST}", SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                                          SOFT_OP_COPY, "DST", NULL, 0, 0),
                   0, "add DST variable rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_COPY,
        .src_path = "/data/input.txt",
        .dst_path = "/tmp/output.txt",
        .subject = NULL,
        .uid = 1000
    };

    /* Both paths match their respective variable rules */
    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(ret > 0, "copy allowed with path variables");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Subject constraint                                                 */
/* ------------------------------------------------------------------ */

static void test_rule_engine_subject_match(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Only /usr/bin/cp can copy from /data to /tmp */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, NULL,
                                          ".*/cp$", 0, SOFT_RULE_RECURSIVE),
                   0, "add SRC subject-constrained rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/tmp/...", SOFT_ACCESS_WRITE,
                                          SOFT_OP_COPY, NULL,
                                          ".*/cp$", 0, SOFT_RULE_RECURSIVE),
                   0, "add DST subject-constrained rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_COPY,
        .src_path = "/data/file.txt",
        .dst_path = "/tmp/out.txt",
        .subject = "/usr/bin/cp",
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(ret > 0, "copy allowed when subject matches");

    ctx.subject = "/usr/bin/mv";
    ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(ret, -13, "copy denied when subject doesn't match");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  UID constraint                                                     */
/* ------------------------------------------------------------------ */

static void test_rule_engine_uid_constraint(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/admin/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL,
                                          1000, SOFT_RULE_RECURSIVE),
                   0, "add UID-constrained rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_READ,
        .src_path = "/admin/config",
        .dst_path = NULL,
        .subject = NULL,
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(ret > 0, "read allowed when UID >= min_uid");

    ctx.uid = 500;
    ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(ret, -13, "read denied when UID < min_uid");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Expression parser                                                  */
/* ------------------------------------------------------------------ */

static void test_rule_engine_expression_parser(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Parse: cp from /etc to /tmp with RW access */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs,
                   "cp::/etc/*:/tmp/ -> RW", NULL),
                   0, "parse copy expression");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_COPY,
        .src_path = "/etc/passwd",
        .dst_path = "/tmp/passwd",
        .subject = NULL,
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(ret > 0, "parsed expression allows copy");

    soft_ruleset_free(rs);
}

static void test_rule_engine_expression_parser_errors(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Missing arrow */
    int ret = soft_ruleset_add_rule_str(rs, "cp::/etc:/tmp ->", NULL);
    TEST_ASSERT(ret < 0 || soft_ruleset_error(rs) == NULL,
                "parser handles missing mode");

    /* Missing operation (defaults to READ) */
    ret = soft_ruleset_add_rule_str(rs, "::/data:/out -> R", NULL);
    TEST_ASSERT(ret == 0, "empty operation defaults to READ");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Backward compatibility wrapper                                     */
/* ------------------------------------------------------------------ */

static void test_rule_engine_backward_compat(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/home/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add read rule");

    int ret = soft_ruleset_check(rs, "/home/user/file.txt", 0);
    TEST_ASSERT(ret > 0, "backward compat check allows read");

    ret = soft_ruleset_check(rs, "/etc/shadow", 0);
    TEST_ASSERT_EQ(ret, -13, "backward compat check denies unmatched");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Batch evaluation                                                   */
/* ------------------------------------------------------------------ */

static void test_rule_engine_batch(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/src/...", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add SRC rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/dst/...", SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                                          SOFT_OP_COPY, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add DST rule");

    /* Build batch of 3 copy operations */
    soft_access_ctx_t c1 = { SOFT_OP_COPY, "/src/a.txt", "/dst/a.txt", NULL, 1000 };
    soft_access_ctx_t c2 = { SOFT_OP_COPY, "/src/b.txt", "/dst/b.txt", NULL, 1000 };
    soft_access_ctx_t c3 = { SOFT_OP_COPY, "/etc/x.txt", "/dst/x.txt", NULL, 1000 };

    const soft_access_ctx_t *ctxs[3] = { &c1, &c2, &c3 };
    int results[3];

    int ret = soft_ruleset_check_batch_ctx(rs, ctxs, results, 3);
    TEST_ASSERT_EQ(ret, 0, "batch evaluation succeeds");
    TEST_ASSERT(results[0] > 0, "batch[0] copy allowed");
    TEST_ASSERT(results[1] > 0, "batch[1] copy allowed");
    TEST_ASSERT_EQ(results[2], -13, "batch[2] copy denied (SRC not matching)");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  DENY overrides allow                                               */
/* ------------------------------------------------------------------ */

static void test_rule_engine_deny_overrides(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Allow reading from /data */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add allow rule");

    /* Deny reading /data/secret */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add deny rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_READ,
        .src_path = "/data/secret",
        .dst_path = NULL,
        .subject = NULL,
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(ret, -13, "deny overrides allow");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Recursive wildcards                                                */
/* ------------------------------------------------------------------ */

static void test_rule_engine_recursive_wildcard(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/home/user/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add recursive rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_READ,
        .src_path = "/home/user/docs/deep/nested/file.txt",
        .dst_path = NULL,
        .subject = NULL,
        .uid = 1000
    };

    int ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT(ret > 0, "recursive wildcard matches deep path");

    /* Should not match /home/other */
    ctx.src_path = "/home/other/file.txt";
    ret = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(ret, -13, "recursive wildcard doesn't match sibling dir");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Null inputs                                                        */
/* ------------------------------------------------------------------ */

static void test_rule_engine_null_inputs(void)
{
    TEST_ASSERT(soft_ruleset_new() != NULL, "ruleset_new succeeds");
    soft_ruleset_free(NULL);  /* Should not crash */

    soft_ruleset_t *rs = soft_ruleset_new();

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(NULL, NULL, NULL), -13,
                   "check_ctx with NULL rs denied");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(NULL, "/x", 1, SOFT_OP_READ,
                                          NULL, NULL, 0, 0), -1,
                   "add_rule with NULL rs fails");
    TEST_ASSERT_EQ(soft_ruleset_check(rs, NULL, 0), -13,
                   "check with NULL path denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Audit log                                                          */
/* ------------------------------------------------------------------ */

static void test_rule_engine_audit_log(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add read rule");

    soft_access_ctx_t ctx = {
        .op = SOFT_OP_READ,
        .src_path = "/data/file.txt",
        .dst_path = NULL,
        .subject = NULL,
        .uid = 1000
    };

    soft_audit_log_t log;
    memset(&log, 0, sizeof(log));

    int ret = soft_ruleset_check_ctx(rs, &ctx, &log);
    TEST_ASSERT(ret > 0, "read allowed");
    TEST_ASSERT(log.result > 0, "audit log shows positive result");

    /* Test denied path */
    ctx.src_path = "/etc/shadow";
    ret = soft_ruleset_check_ctx(rs, &ctx, &log);
    TEST_ASSERT_EQ(ret, -13, "read denied");
    TEST_ASSERT_EQ(log.result, -13, "audit log shows denial");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_rule_engine_run(void)
{
    printf("=== Rule Engine Tests ===\n");
    RUN_TEST(test_rule_engine_unary_read);
    RUN_TEST(test_rule_engine_copy_allowed);
    RUN_TEST(test_rule_engine_copy_denied_wrong_src);
    RUN_TEST(test_rule_engine_copy_denied_wrong_dst);
    RUN_TEST(test_rule_engine_path_variables);
    RUN_TEST(test_rule_engine_subject_match);
    RUN_TEST(test_rule_engine_uid_constraint);
    RUN_TEST(test_rule_engine_expression_parser);
    RUN_TEST(test_rule_engine_expression_parser_errors);
    RUN_TEST(test_rule_engine_backward_compat);
    RUN_TEST(test_rule_engine_batch);
    RUN_TEST(test_rule_engine_deny_overrides);
    RUN_TEST(test_rule_engine_recursive_wildcard);
    RUN_TEST(test_rule_engine_null_inputs);
    RUN_TEST(test_rule_engine_audit_log);
}
