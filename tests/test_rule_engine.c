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
/*  Basic operations: READ, COPY, backward compat, null inputs         */
/* ------------------------------------------------------------------ */

static void test_rule_engine_basic_ops(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* READ rules */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add /usr/** rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/etc/shadow", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add deny /etc/shadow");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add /data/... rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add deny /data/secret");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/home/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add /home/... for backward compat");

    /* COPY rules */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/readonly/...", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add SRC read rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/scratch/...", SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                                          SOFT_OP_COPY, NULL, NULL, 0,
                                          SOFT_RULE_RECURSIVE),
                   0, "add DST write rule");

    /* READ check 1: allowed by /usr double-wildcard */
    soft_access_ctx_t ctx = { SOFT_OP_READ, "/usr/bin/bash", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "/usr/bin/bash grants READ");

    /* READ check 2: explicitly denied */
    ctx.src_path = "/etc/shadow";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "/etc/shadow denied");

    /* READ check 3: recursive wildcard */
    ctx.src_path = "/data/docs/deep/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "recursive wildcard grants READ");

    /* READ check 4: deny overrides allow */
    ctx.src_path = "/data/secret";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "deny overrides allow");

    /* COPY check 1: allowed */
    soft_access_ctx_t ctx2 = {
        SOFT_OP_COPY, "/readonly/file.txt", "/scratch/output.txt", NULL, 1000
    };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx2, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                   "copy grants READ|WRITE|CREATE");

    /* COPY check 2: denied when SRC has no read rule */
    ctx2.src_path = "/external/user/secret";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx2, NULL), -13,
                   "copy denied when SRC has no read rule");

    /* COPY check 3: denied when DST has no write rule */
    ctx2.src_path = "/readonly/file.txt";
    ctx2.dst_path = "/etc/output.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx2, NULL), -13,
                   "copy denied when DST has no write rule");

    /* Backward compat: legacy check() wrapper */
    TEST_ASSERT_EQ(soft_ruleset_check(rs, "/home/user/file.txt", 0), SOFT_ACCESS_READ,
                   "backward compat grants READ");
    TEST_ASSERT_EQ(soft_ruleset_check(rs, "/etc/shadow", 0), -13,
                   "backward compat denies unmatched");

    soft_ruleset_free(rs);

    /* Null inputs: should not crash, should return errors */
    soft_ruleset_t *rs1 = soft_ruleset_new();
    TEST_ASSERT_NOT_NULL(rs1, "ruleset_new succeeds");
    soft_ruleset_free(rs1);
    soft_ruleset_free(NULL);

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(NULL, NULL, NULL), -13,
                   "check_ctx with NULL rs denied");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(NULL, "/x", 1, SOFT_OP_READ,
                                          NULL, NULL, 0, 0), -1,
                   "add_rule with NULL rs fails");
    TEST_ASSERT_EQ(soft_ruleset_check(NULL, NULL, 0), -13,
                   "check with NULL rs denied");
}

/* ------------------------------------------------------------------ */
/*  Rule constraints: path variables, subject, UID                     */
/* ------------------------------------------------------------------ */

static void test_rule_engine_constraints(void)
{
    /* Test 1: Path variables */
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "${SRC}", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, "SRC", NULL, 0, 0),
                   0, "add SRC variable rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "${DST}", SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                                          SOFT_OP_COPY, "DST", NULL, 0, 0),
                   0, "add DST variable rule");
    soft_access_ctx_t ctx = {
        SOFT_OP_COPY, "/data/input.txt", "/tmp/output.txt", NULL, 1000
    };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                   "copy with path variables grants READ|WRITE|CREATE");
    soft_ruleset_free(rs);

    /* Test 2: Subject constraint */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, NULL,
                                          ".*cp$", 0, SOFT_RULE_RECURSIVE),
                   0, "add subject-constrained SRC rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/tmp/...", SOFT_ACCESS_WRITE,
                                          SOFT_OP_COPY, NULL,
                                          ".*cp$", 0, SOFT_RULE_RECURSIVE),
                   0, "add subject-constrained DST rule");

    ctx = (soft_access_ctx_t){ SOFT_OP_COPY, "/data/file.txt", "/tmp/out.txt", "/usr/bin/cp", 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "copy with matching subject grants READ|WRITE");

    ctx.subject = "/usr/bin/mv";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "copy denied when subject doesn't match");
    soft_ruleset_free(rs);

    /* Test 3: UID constraint */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/admin/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL,
                                          1000, SOFT_RULE_RECURSIVE),
                   0, "add UID-constrained rule");

    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/admin/config", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "read with UID>=min_uid grants READ");

    ctx.uid = 500;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "read denied when UID < min_uid");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Expression parser: happy path, errors, @layer, binary ops          */
/* ------------------------------------------------------------------ */

static void test_rule_engine_expression_parser(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Happy path: parse and evaluate */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs,
                   "cp::/etc/*:/tmp/ -> RW", NULL),
                   0, "parse copy expression");
    soft_access_ctx_t ctx = {
        SOFT_OP_COPY, "/etc/passwd", "/tmp/passwd", NULL, 1000
    };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "parsed expression grants READ|WRITE");

    /* Error cases */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs, "cp::/etc:/tmp ->", NULL),
                   0, "empty mode falls back to READ");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs, "::/data:/out -> R", NULL),
                   0, "empty operation defaults to READ");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs, "@bad:cp::/a:/b -> R", NULL),
                   -1, "invalid @layer prefix rejected");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs, "@99:cp::/a:/b -> R", NULL),
                   -1, "out-of-range @layer rejected");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs, "@-1:read::/data -> R", NULL),
                   -1, "negative @layer rejected");

    /* @layer DENY shadowing */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs,
                   "@0:read::/secret -> DENY", NULL),
                   0, "@0 layer deny");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs,
                   "@1:read::/secret -> R", NULL),
                   0, "@1 layer allow");
    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/secret", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "@0 layer DENY shadows @1 allow");

    /* Cross-layer binary COPY: @0=SRC READ, @1=DST WRITE */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs,
                   "@0:copy::/src/... -> R", NULL),
                   0, "@0 copy SRC");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_str(rs,
                   "@1:copy::/dst/... -> W", NULL),
                   0, "@1 copy DST");
    ctx = (soft_access_ctx_t){ SOFT_OP_COPY, "/src/file.txt", "/dst/file.txt", NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "cross-layer copy: SRC read at layer 0, DST write at layer 1");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Audit log: result, deny_layer, matched_rule (allow + deny paths)   */
/* ------------------------------------------------------------------ */

static void test_rule_engine_audit_log(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Setup: allow rule + deny rule */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0,
                   SOFT_RULE_RECURSIVE),
                   0, "add allow rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/secret",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add deny rule");

    soft_audit_log_t log;
    soft_access_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.op = SOFT_OP_READ;
    ctx.dst_path = NULL;
    ctx.subject = NULL;
    ctx.uid = 1000;

    /* Check 1: allow path — result, deny_layer, matched_rule */
    memset(&log, 0, sizeof(log));
    ctx.src_path = "/data/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, &log), SOFT_ACCESS_READ,
                   "read allowed");
    TEST_ASSERT_EQ(log.result, SOFT_ACCESS_READ, "audit result matches");
    TEST_ASSERT_EQ(log.deny_layer, -1, "deny_layer is -1 on allow");
    TEST_ASSERT(log.matched_rule != NULL, "matched_rule set on allow");
    TEST_ASSERT_STR_EQ(log.matched_rule, "/data/...",
                       "matched_rule is the recursive pattern");

    /* Check 2: deny path — result, deny_layer, matched_rule */
    memset(&log, 0, sizeof(log));
    ctx.src_path = "/secret";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, &log), -13,
                   "read denied");
    TEST_ASSERT_EQ(log.result, -13, "audit result matches denial");
    TEST_ASSERT_EQ(log.deny_layer, 0, "deny_layer is 0 (layer 0 DENY)");
    TEST_ASSERT(log.matched_rule != NULL, "matched_rule set on deny");
    TEST_ASSERT_STR_EQ(log.matched_rule, "/secret",
                       "matched_rule is /secret");

    /* Check 3: no-match path — result, deny_layer when nothing matches */
    memset(&log, 0, sizeof(log));
    ctx.src_path = "/etc/shadow";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, &log), -13,
                   "no-match denied");
    TEST_ASSERT_EQ(log.result, -13, "audit result matches denial");
    TEST_ASSERT_EQ(log.deny_layer, -1, "deny_layer is -1 when no match");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer behavior: PRECEDENCE + SPECIFICITY integration               */
/* ------------------------------------------------------------------ */

static void test_rule_engine_layer_behavior(void)
{
    /* Part 1: PRECEDENCE layer mechanics */
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 0,
                   "initial layer count is 0");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/data",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule at layer 1");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 2,
                   "layer count is 2 after adding at layer 1");

    /* Empty layer 0 doesn't constrain */
    soft_access_ctx_t ctx = { SOFT_OP_READ, "/data", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "empty layer 0 allows layer 1 rule");

    /* Part 2: PRECEDENCE static DENY shadows template ALLOW */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/etc/shadow",
                   SOFT_ACCESS_DENY, SOFT_OP_COPY, NULL, NULL, 0, 0),
                   0, "static deny /etc/shadow");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "${SRC}",
                   SOFT_ACCESS_READ, SOFT_OP_COPY, "SRC", NULL, 0,
                   SOFT_RULE_TEMPLATE),
                   0, "template ${SRC} read");
    ctx.op = SOFT_OP_COPY;
    ctx.src_path = "/etc/shadow";
    ctx.dst_path = "/tmp/shadow";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "static DENY shadows template ${SRC}");

    /* Part 3: linked_path_var validation */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, "DST", NULL, 0, 0),
                   -1, "linked_path_var with non-template rejected");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "${SRC}", SOFT_ACCESS_READ,
                                          SOFT_OP_COPY, "SRC", NULL, 0, 0),
                   0, "linked_path_var with ${SRC} accepted");

    /* Part 4: PRECEDENCE layer shadowing — Layer 0 DENY shadows Layer 1 ALLOW */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/secret",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 0 deny /secret");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/secret",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 1 allow /secret");

    /* Part 5: PRECEDENCE mode intersection — READ ∩ WRITE = 0 */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/intersect",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 0 read /intersect");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/intersect",
                   SOFT_ACCESS_WRITE, SOFT_OP_WRITE, NULL, NULL, 0, 0),
                   0, "layer 1 write /intersect");

    /* Part 6: PRECEDENCE mode intersection — READ ∩ READ = READ */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/both",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 0 read /both");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/both",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 1 read /both");

    /* Part 7: PRECEDENCE three layers, bottom DENY short-circuits */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/triple",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 0 read /triple");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/triple",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 1 read /triple");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 2, "/triple",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 2 deny /triple");

    /* Check 1: shadowed path */
    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/secret", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "layer 0 DENY shadows layer 1 allow");

    /* Check 2: intersection denies */
    ctx.src_path = "/intersect";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "layer intersection READ ∩ WRITE = 0");

    /* Check 3: intersection allows */
    ctx.src_path = "/both";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "both layers allow READ");

    /* Check 4: three-layer DENY short-circuits */
    ctx.src_path = "/triple";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "layer 2 DENY short-circuits despite layers 0,1");

    /* Check 5: layer count */
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 3,
                   "3 layers exist");

    /* Part 7b: PRECEDENCE compiled — verify identical results */
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "PRECEDENCE compile succeeds");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(rs), true, "PRECEDENCE compiled");

    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/secret", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "compiled: layer 0 DENY shadows layer 1 allow");

    ctx.src_path = "/intersect";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "compiled: layer intersection READ ∩ WRITE = 0");

    ctx.src_path = "/both";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "compiled: both layers allow READ");

    ctx.src_path = "/triple";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "compiled: layer 2 DENY short-circuits despite layers 0,1");

    /* Audit log on compiled PRECEDENCE */
    soft_audit_log_t log;
    memset(&log, 0, sizeof(log));
    ctx.src_path = "/both";
    int ret = soft_ruleset_check_ctx(rs, &ctx, &log);
    TEST_ASSERT_EQ(ret, SOFT_ACCESS_READ, "compiled PRECEDENCE allow with audit");
    TEST_ASSERT_EQ(log.result, SOFT_ACCESS_READ, "compiled audit result matches");
    TEST_ASSERT_EQ(log.deny_layer, -1, "compiled deny_layer is -1");
    TEST_ASSERT(log.matched_rule != NULL, "compiled matched_rule set");

    /* Add rule invalidates, recompile works */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/new",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add rule after compile");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(rs), false, "add invalidates compiled");
    ctx.src_path = "/new";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "invalidated: new path allowed");
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "recompile succeeds");
    ctx.src_path = "/new";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "recompiled: new path still allowed");

    /* Part 7c: PRECEDENCE compiled — subject and UID constraints */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/secure/...",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL,
                   ".*admin$", 1000, SOFT_RULE_RECURSIVE),
                   0, "add subject+UID constrained rule");
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "recompile with subject+UID succeeds");

    soft_access_ctx_t su_ctx = {
        SOFT_OP_READ, "/secure/config", NULL, "/usr/bin/admin", 2000
    };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &su_ctx, NULL), SOFT_ACCESS_READ,
                   "compiled: subject+UID match grants access");

    su_ctx.subject = "/usr/bin/user";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &su_ctx, NULL), -13,
                   "compiled: subject mismatch denies");

    su_ctx.subject = "/usr/bin/admin";
    su_ctx.uid = 500;
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &su_ctx, NULL), -13,
                   "compiled: UID below threshold denies");

    /* Part 7d: backward compat check() on compiled ruleset */
    TEST_ASSERT_EQ(soft_ruleset_check(rs, "/both", 0), SOFT_ACCESS_READ,
                   "compiled: backward compat check() works");
    TEST_ASSERT_EQ(soft_ruleset_check(rs, "/nonexistent", 0), -13,
                   "compiled: backward compat check() denies unmatched");

    /* Part 7e: PRECEDENCE compiled batch with mixed allow/deny */
    const char *b_paths[] = {
        "/both", "/secret", "/intersect", "/new", "/both",
    };
    const int b_expected[] = {
        SOFT_ACCESS_READ, -13, -13, SOFT_ACCESS_READ, SOFT_ACCESS_READ,
    };
    soft_access_ctx_t b_ctx[5];
    const soft_access_ctx_t *b_ctxs[5];
    int b_results[5];
    for (int i = 0; i < 5; i++) {
        memset(&b_ctx[i], 0, sizeof(soft_access_ctx_t));
        b_ctx[i].op = SOFT_OP_READ;
        b_ctx[i].src_path = b_paths[i];
        b_ctx[i].uid = 1000;
        b_ctxs[i] = &b_ctx[i];
    }
    /* Verify batch results match individual results */
    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, b_ctxs, b_results, 5), 0,
                   "PRECEDENCE compiled batch succeeds");
    for (int i = 0; i < 5; i++) {
        soft_access_ctx_t ind = *b_ctxs[i];
        int ind_ret = soft_ruleset_check_ctx(rs, &ind, NULL);
        TEST_ASSERT_EQ(b_results[i], ind_ret, "PRECEDENCE batch matches individual");
        TEST_ASSERT_EQ(b_results[i], b_expected[i], "PRECEDENCE batch expected value");
    }

    soft_ruleset_free(rs);

    /* Part 8: SPECIFICITY basic override */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/data/...",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0,
                   SOFT_RULE_RECURSIVE),
                   0, "PRECEDENCE deny /data/...");
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/data/project/**",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY /data/project/**");

    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/data/project/file.txt", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "SPECIFICITY overrides PRECEDENCE DENY");

    ctx.src_path = "/data/other/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "no SPECIFICITY match -> PRECEDENCE DENY");

    /* Part 9: SPECIFICITY mask */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/data",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "PRECEDENCE deny /data");
    soft_ruleset_set_layer_type(rs, 2, LAYER_SPECIFICITY, SOFT_ACCESS_READ);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 2, "/data",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY /data READ mask");

    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/data", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "SPECIFICITY mask covers READ");

    /* Part 10: SPECIFICITY deny overrides PRECEDENCE allow */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/data/**",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "PRECEDENCE allow /data/**");
    soft_ruleset_set_layer_type(rs, 3, LAYER_SPECIFICITY, 0);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 3, "/data/secret",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY deny /data/secret");

    ctx.src_path = "/data/secret";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "SPECIFICITY deny overrides PRECEDENCE allow");

    soft_ruleset_free(rs);

    /* Part 11: SPECIFICITY recursive wildcard `...` */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/data/project/**",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "PRECEDENCE deny /data/project/**");
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/data/project/subdir/...",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0,
                   SOFT_RULE_RECURSIVE),
                   0, "SPECIFICITY /data/project/subdir/...");

    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/data/project/subdir/deep/file.txt", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "SPECIFICITY recursive overrides PRECEDENCE wildcard");

    ctx.src_path = "/data/project/other/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "PRECEDENCE wildcard denies non-SPECIFICITY path");

    /* Part 12: SPECIFICITY single-star `*` */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/data/*",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY /data/*");
    ctx.src_path = "/data/secret";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "SPECIFICITY single-star overrides PRECEDENCE exact deny");

    soft_ruleset_free(rs);

    /* Part 13: SPECIFICITY same path, different modes */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/data",
                   SOFT_ACCESS_WRITE, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "PRECEDENCE /data WRITE");
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/data",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY /data READ");

    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/data", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "SPECIFICITY READ overrides PRECEDENCE WRITE");

    soft_ruleset_free(rs);

    /* Part 14: SPECIFICITY-only ruleset */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/data/**",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY /data/**");

    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/data/any/path/file.txt", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "SPECIFICITY-only allows matching path");

    ctx.src_path = "/other/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "SPECIFICITY-only denies non-matching path");

    soft_ruleset_free(rs);

    /* Part 15: SPECIFICITY compiled + invalidate + recompile */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/data/...",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0,
                   SOFT_RULE_RECURSIVE),
                   0, "PRECEDENCE deny /data/...");
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/data/project/**",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY /data/project/**");
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "compile succeeds");

    ctx = (soft_access_ctx_t){ SOFT_OP_READ, "/data/project/file.txt", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "compiled: SPECIFICITY overrides PRECEDENCE");

    ctx.src_path = "/data/other/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "compiled: non-matching -> PRECEDENCE DENY");

    /* Add rule invalidates compiled state */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/data/project/deep/**",
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY /data/project/deep/**");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(rs), false, "add rule invalidates compiled");

    /* Still works via layered evaluation */
    ctx.src_path = "/data/project/deep/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "invalidated: SPECIFICITY deep path grants READ|WRITE");

    /* Recompile works */
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "recompile succeeds");
    TEST_ASSERT_EQ(soft_ruleset_is_compiled(rs), true, "recompiled");
    ctx.src_path = "/data/project/deep/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "recompiled: SPECIFICITY deep path grants READ|WRITE");

    /* SPECIFICITY compiled batch evaluation */
    const char *paths[] = {
        "/data/project/a.txt",
        "/data/other/b.txt",
        "/data/project/c.txt",
    };
    const int expected[] = { SOFT_ACCESS_READ, -13, SOFT_ACCESS_READ };
    soft_access_ctx_t ctx_array[3];
    const soft_access_ctx_t *ctxs[3];
    int results[3];
    for (int i = 0; i < 3; i++) {
        memset(&ctx_array[i], 0, sizeof(soft_access_ctx_t));
        ctx_array[i].op = SOFT_OP_READ;
        ctx_array[i].src_path = paths[i];
        ctx_array[i].uid = 1000;
        ctxs[i] = &ctx_array[i];
    }
    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, ctxs, results, 3), 0,
                   "SPECIFICITY compiled batch succeeds");
    for (int i = 0; i < 3; i++) {
        if (results[i] != expected[i]) {
            TEST_ASSERT_EQ(results[i], expected[i], "batch entry mismatch");
        }
    }

    /* SPECIFICITY compiled audit log */
    soft_audit_log_t slog;
    memset(&slog, 0, sizeof(slog));
    soft_access_ctx_t sctx = { SOFT_OP_READ, "/data/project/file.txt", NULL, NULL, 1000 };
    int sret = soft_ruleset_check_ctx(rs, &sctx, &slog);
    TEST_ASSERT_EQ(sret, SOFT_ACCESS_READ, "compiled SPECIFICITY allow with audit");
    TEST_ASSERT_EQ(slog.result, SOFT_ACCESS_READ, "compiled SPECIFICITY audit result matches");
    TEST_ASSERT_EQ(slog.deny_layer, -1, "compiled SPECIFICITY deny_layer is -1");
    TEST_ASSERT(slog.matched_rule != NULL, "compiled SPECIFICITY matched_rule set");

    memset(&slog, 0, sizeof(slog));
    sctx.src_path = "/data/other/file.txt";
    sret = soft_ruleset_check_ctx(rs, &sctx, &slog);
    TEST_ASSERT_EQ(sret, -13, "compiled SPECIFICITY deny with audit");
    TEST_ASSERT_EQ(slog.result, -13, "compiled SPECIFICITY audit result matches denial");
    TEST_ASSERT_EQ(slog.deny_layer, 0, "compiled SPECIFICITY deny_layer is 0 (PRECEDENCE)");

    soft_ruleset_free(rs);
}



/* ------------------------------------------------------------------ */
/*  Uncovered operations: MOVE, LINK, EXEC, MOUNT, CUSTOM               */
/* ------------------------------------------------------------------ */

static void test_rule_engine_uncovered_ops(void)
{
    /* Test 1: MOVE — requires SRC WRITE|UNLINK, DST WRITE */
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/src/...", SOFT_ACCESS_WRITE | SOFT_ACCESS_UNLINK,
                                          SOFT_OP_MOVE, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add MOVE SRC rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/dst/...", SOFT_ACCESS_WRITE,
                                          SOFT_OP_MOVE, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add MOVE DST rule");
    soft_access_ctx_t ctx = { SOFT_OP_MOVE, "/src/old.txt", "/dst/new.txt", NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_WRITE | SOFT_ACCESS_UNLINK,
                   "MOVE grants WRITE|UNLINK");

    /* MOVE denied: SRC lacks UNLINK */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/readonly/...", SOFT_ACCESS_READ,
                                          SOFT_OP_MOVE, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add MOVE SRC read-only rule");
    ctx.src_path = "/readonly/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "MOVE denied: SRC lacks WRITE|UNLINK");

    /* MOVE denied: DST lacks WRITE */
    ctx.src_path = "/src/old.txt";
    ctx.dst_path = "/protected/new.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "MOVE denied: DST lacks WRITE");
    soft_ruleset_free(rs);

    /* Test 2: LINK — requires SRC READ|LINK, DST WRITE|CREATE */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/src/...", SOFT_ACCESS_READ | SOFT_ACCESS_LINK,
                                          SOFT_OP_LINK, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add LINK SRC rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/dst/...", SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                                          SOFT_OP_LINK, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add LINK DST rule");
    ctx = (soft_access_ctx_t){ SOFT_OP_LINK, "/src/lib.so", "/dst/link.so", NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_LINK | SOFT_ACCESS_WRITE | SOFT_ACCESS_CREATE,
                   "LINK grants READ|LINK|WRITE|CREATE");
    soft_ruleset_free(rs);

    /* Test 3: EXEC — requires EXEC mode */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/bin/**", SOFT_ACCESS_EXEC,
                                          SOFT_OP_EXEC, NULL, NULL, 0, 0),
                   0, "add EXEC rule");
    ctx = (soft_access_ctx_t){ SOFT_OP_EXEC, "/bin/bash", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_EXEC,
                   "EXEC grants EXEC");

    ctx.src_path = "/bin/unauthorized";
    /* Still matches /bin double-wildcard - should be allowed */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_EXEC,
                   "EXEC: /bin/** matches any file");

    ctx.src_path = "/usr/bin/bash";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "EXEC denied: /usr/bin not covered by /bin/**");
    soft_ruleset_free(rs);

    /* Test 4: CHMOD_CHOWN — requires WRITE on target */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_WRITE,
                                          SOFT_OP_CHMOD_CHOWN, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add CHMOD_CHOWN rule");
    ctx = (soft_access_ctx_t){ SOFT_OP_CHMOD_CHOWN, "/data/file.txt", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_WRITE,
                   "CHMOD_CHOWN grants WRITE");

    ctx.src_path = "/readonly/file.txt";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "CHMOD_CHOWN denied: /readonly not covered");
    soft_ruleset_free(rs);

    /* Test 5: CUSTOM operation with custom mode registration */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_set_custom_op_modes(rs, SOFT_OP_CUSTOM,
                   SOFT_ACCESS_READ | SOFT_ACCESS_CREATE, SOFT_ACCESS_WRITE | SOFT_ACCESS_MKDIR),
                   0, "register CUSTOM modes");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/src/...", SOFT_ACCESS_READ | SOFT_ACCESS_CREATE,
                                          SOFT_OP_CUSTOM, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add CUSTOM SRC rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/dst/...", SOFT_ACCESS_WRITE | SOFT_ACCESS_MKDIR,
                                          SOFT_OP_CUSTOM, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add CUSTOM DST rule");
    ctx = (soft_access_ctx_t){ SOFT_OP_CUSTOM, "/src/item", "/dst/item", NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_CREATE | SOFT_ACCESS_WRITE | SOFT_ACCESS_MKDIR,
                   "CUSTOM with registered modes grants all");
    soft_ruleset_free(rs);

    /* Test 6: MOUNT — requires SRC READ|MOUNT_SRC, DST WRITE */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/dev/sd*", SOFT_ACCESS_READ | SOFT_ACCESS_MOUNT_SRC,
                                          SOFT_OP_MOUNT, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add MOUNT SRC rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/mnt/...", SOFT_ACCESS_WRITE,
                                          SOFT_OP_MOUNT, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add MOUNT DST rule");
    ctx = (soft_access_ctx_t){ SOFT_OP_MOUNT, "/dev/sda1", "/mnt/usb", NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_MOUNT_SRC | SOFT_ACCESS_WRITE,
                   "MOUNT grants READ|MOUNT_SRC|WRITE");

    ctx.src_path = "/dev/nvme0";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "MOUNT denied: SRC /dev/nvme0 not covered by /dev/sd*");

    ctx.src_path = "/dev/sda1";
    ctx.dst_path = "/sys/mount";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "MOUNT denied: DST /sys not covered by /mnt/...");
    soft_ruleset_free(rs);

    /* Test 7: MOVE + EXEC compiled evaluation */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/src/...", SOFT_ACCESS_WRITE | SOFT_ACCESS_UNLINK,
                                          SOFT_OP_MOVE, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add MOVE SRC");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/dst/...", SOFT_ACCESS_WRITE,
                                          SOFT_OP_MOVE, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add MOVE DST");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/bin/**", SOFT_ACCESS_EXEC,
                                          SOFT_OP_EXEC, NULL, NULL, 0, 0),
                   0, "add EXEC rule");
    TEST_ASSERT_EQ(soft_ruleset_compile(rs), 0, "compile succeeds");

    ctx = (soft_access_ctx_t){ SOFT_OP_MOVE, "/src/old.txt", "/dst/new.txt", NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_WRITE | SOFT_ACCESS_UNLINK,
                   "compiled MOVE grants WRITE|UNLINK");

    ctx = (soft_access_ctx_t){ SOFT_OP_EXEC, "/bin/bash", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_EXEC,
                   "compiled EXEC grants EXEC");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Query cache: verify cached results match fresh evaluation          */
/* ------------------------------------------------------------------ */

static void test_rule_engine_query_cache(void)
{
    /* Build a ruleset with varied rules to exercise cache thoroughly */
    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/data/...",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0,
                   SOFT_RULE_RECURSIVE),
                   0, "PRECEDENCE deny /data/...");
    soft_ruleset_add_rule_at_layer(rs, 0, "/public",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/bin/**", SOFT_ACCESS_EXEC,
                   SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/data/project/**",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "SPECIFICITY /data/project/**");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/tmp/...",
                   SOFT_ACCESS_WRITE, SOFT_OP_COPY, NULL, NULL, 0,
                   SOFT_RULE_RECURSIVE),
                   0, "SPECIFICITY /tmp/... COPY WRITE");

    /* Build a set of test queries */
    typedef struct {
        soft_access_ctx_t ctx;
        int expected;
    } query_t;

    query_t queries[] = {
        /* READ queries */
        { {SOFT_OP_READ, "/public", NULL, NULL, 1000}, SOFT_ACCESS_READ },
        { {SOFT_OP_READ, "/data/project/a.txt", NULL, NULL, 1000}, SOFT_ACCESS_READ },
        { {SOFT_OP_READ, "/data/other/x.txt", NULL, NULL, 1000}, -13 },
        { {SOFT_OP_READ, "/data/project/deep/file.txt", NULL, NULL, 1000}, SOFT_ACCESS_READ },

        /* EXEC queries */
        { {SOFT_OP_EXEC, "/bin/bash", NULL, NULL, 1000}, SOFT_ACCESS_EXEC },
        { {SOFT_OP_EXEC, "/bin/ls", NULL, NULL, 1000}, SOFT_ACCESS_EXEC },
        { {SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, -13 },

        /* COPY queries */
        { {SOFT_OP_COPY, "/data/project/a.txt", "/tmp/x.txt", NULL, 1000}, SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
        { {SOFT_OP_COPY, "/data/other/x.txt", "/tmp/y.txt", NULL, 1000}, -13 },
        { {SOFT_OP_COPY, "/data/project/a.txt", "/tmp/y.txt", NULL, 1000}, SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
        { {SOFT_OP_COPY, "/data/project/b.txt", "/tmp/x.txt", NULL, 1000}, SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },

        /* WRITE queries */
        { {SOFT_OP_WRITE, "/tmp/x.txt", NULL, NULL, 1000}, SOFT_ACCESS_WRITE },
        { {SOFT_OP_WRITE, "/tmp/y.txt", NULL, NULL, 1000}, SOFT_ACCESS_WRITE },
    };

    const int N = sizeof(queries) / sizeof(queries[0]);

    /* Phase 1: Warm up cache by running each query once */
    for (int i = 0; i < N; i++) {
        soft_ruleset_check_ctx(rs, &queries[i].ctx, NULL);
        TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &queries[i].ctx, NULL), queries[i].expected, "cache query match");
    }

    /* Phase 2: Re-run every query — all should hit cache and produce identical results */
    for (int i = 0; i < N; i++) {
        soft_ruleset_check_ctx(rs, &queries[i].ctx, NULL);
        TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &queries[i].ctx, NULL), queries[i].expected, "cache query match");
    }

    /* Phase 3: Cross-query reuse tests */

    /* Test: READ warms cache with eval=READ, then COPY reuses SRC */
    soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_READ, "/data/project/r1.txt", NULL, NULL, 1000}, NULL);
    /* Now COPY uses same SRC — should reuse cached READ result for SRC */
    int r1 = soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_COPY, "/data/project/r1.txt", "/tmp/z.txt", NULL, 1000}, NULL);
    TEST_ASSERT_EQ(r1, SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "COPY reuses READ-cached SRC");

    /* Test: COPY warms cache with eval=ALL, then READ reuses */
    soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_COPY, "/data/project/r2.txt", "/tmp/r2.txt", NULL, 1000}, NULL);
    int r2 = soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_READ, "/data/project/r2.txt", NULL, NULL, 1000}, NULL);
    TEST_ASSERT_EQ(r2, SOFT_ACCESS_READ,
                   "READ reuses COPY-cached entry (eval=ALL covers READ)");

    /* Test: COPY warms cache with eval=ALL, then WRITE reuses */
    int r3 = soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_WRITE, "/tmp/r2.txt", NULL, NULL, 1000}, NULL);
    TEST_ASSERT_EQ(r3, SOFT_ACCESS_WRITE,
                   "WRITE reuses COPY-cached entry (eval=ALL covers WRITE)");

    /* Test: Cross-path reuse — both paths individually cached but never together */
    soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_COPY, "/data/project/a.txt", "/tmp/w1.txt", NULL, 1000}, NULL);
    soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_COPY, "/data/project/b.txt", "/tmp/w2.txt", NULL, 1000}, NULL);
    int r4 = soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_COPY, "/data/project/a.txt", "/tmp/w2.txt", NULL, 1000}, NULL);
    TEST_ASSERT_EQ(r4, SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "COPY reuses SRC from query 1, DST from query 2");

    /* Test: Denied path cached */
    int d1 = soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_READ, "/data/denied/x.txt", NULL, NULL, 1000}, NULL);
    int d2 = soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_READ, "/data/denied/x.txt", NULL, NULL, 1000}, NULL);
    TEST_ASSERT_EQ(d1, -13, "denied path first eval");
    TEST_ASSERT_EQ(d2, -13, "denied path cached");

    /* Test: Batch after cache warm */
    const char *batch_paths[] = {
        "/public", "/data/project/batch.txt", "/data/other/batch.txt",
    };
    const int batch_expected[] = {
        SOFT_ACCESS_READ, SOFT_ACCESS_READ, -13,
    };
    soft_access_ctx_t batch_ctx[3];
    const soft_access_ctx_t *batch_ctxs[3];
    int batch_results[3];
    for (int i = 0; i < 3; i++) {
        memset(&batch_ctx[i], 0, sizeof(batch_ctx[i]));
        batch_ctx[i].op = SOFT_OP_READ;
        batch_ctx[i].src_path = batch_paths[i];
        batch_ctx[i].uid = 1000;
        batch_ctxs[i] = &batch_ctx[i];
    }
    TEST_ASSERT_EQ(soft_ruleset_check_batch_ctx(rs, batch_ctxs, batch_results, 3), 0,
                   "batch after cache warm succeeds");
    for (int i = 0; i < 3; i++) {
        if (batch_results[i] != batch_expected[i]) {
            TEST_ASSERT_EQ(batch_results[i], batch_expected[i],
                           "batch result mismatch");
        }
    }

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Query cache: verify lookup logic correctness                       */
/* ------------------------------------------------------------------ */

static void test_rule_engine_query_cache_lookup(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Build a simple ruleset */
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "add READ/WRITE rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/exec/**", SOFT_ACCESS_EXEC,
                                          SOFT_OP_EXEC, NULL, NULL, 0, 0),
                   0, "add EXEC rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/secret", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add DENY rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/admin/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE),
                   0, "add subject-constrained rule");
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/uid/...", SOFT_ACCESS_READ,
                                          SOFT_OP_READ, NULL, NULL, 1000, SOFT_RULE_RECURSIVE),
                   0, "add UID-constrained rule");

    /* Test 1: Subject differentiation — same path, different subject */
    soft_access_ctx_t ctx = { SOFT_OP_READ, "/admin/config", NULL, "/usr/bin/admin", 1000 };
    int r1 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    ctx.subject = "/usr/bin/user";
    int r2 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(r1, SOFT_ACCESS_READ, "admin subject allowed");
    TEST_ASSERT_EQ(r2, -13, "non-admin subject denied");

    /* Test 2: UID differentiation — same path, different UID */
    ctx.subject = NULL;
    ctx.src_path = "/uid/config";
    ctx.uid = 1000;
    int r3 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    ctx.uid = 500;
    int r4 = soft_ruleset_check_ctx(rs, &ctx, NULL);
    TEST_ASSERT_EQ(r3, SOFT_ACCESS_READ, "UID>=1000 allowed");
    TEST_ASSERT_EQ(r4, -13, "UID<1000 denied");

    /* Test 3: Direct-mapped cache — 500 queries with varying hash slots, all correct */
    int collision_count = 0;
    for (int i = 0; i < 500; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/data/coll_%04d.txt", i);
        soft_access_ctx_t c = { SOFT_OP_READ, path, NULL, NULL, 1000 };
        int ret = soft_ruleset_check_ctx(rs, &c, NULL);
        /* All /data/coll_*.txt paths match /data/... READ|WRITE rule */
        int expected = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
        if (ret != expected) collision_count++;
    }
    TEST_ASSERT_EQ(collision_count, 0, "all 500 cache queries produce correct results");

    /* Test 4: eval mask — READ cached (eval=READ), EXEC query needs EXEC → miss */
    soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_READ, "/exec/bash", NULL, NULL, 1000}, NULL);
    int r5 = soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_EXEC, "/exec/bash", NULL, NULL, 1000}, NULL);
    TEST_ASSERT_EQ(r5, SOFT_ACCESS_EXEC, "EXEC evaluates independently (eval=READ does not cover EXEC)");

    /* Test 5: Cache invalidation on rule addition */
    soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_READ, "/data/cached.txt", NULL, NULL, 1000}, NULL);
    TEST_ASSERT_EQ(soft_ruleset_add_rule(rs, "/data/cached.txt", SOFT_ACCESS_DENY,
                                          SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "add deny for cached path");
    int r6 = soft_ruleset_check_ctx(rs, &(soft_access_ctx_t){SOFT_OP_READ, "/data/cached.txt", NULL, NULL, 1000}, NULL);
    TEST_ASSERT_EQ(r6, -13, "cache invalidated: new DENY takes effect");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Query cache: large-scale warmup stress test                        */
/* ------------------------------------------------------------------ */

static void test_rule_engine_query_cache_stress(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/deny/...", SOFT_ACCESS_DENY,
                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "deny layer");
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/allow/**", SOFT_ACCESS_READ,
                   SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "allow SPECIFICITY");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/tmp/...", SOFT_ACCESS_WRITE,
                   SOFT_OP_COPY, NULL, NULL, 0, SOFT_RULE_RECURSIVE),
                   0, "COPY write rule");

    /* Phase 1: Warm cache with 200 unique queries */
    char src_paths[200][64];
    char dst_paths[200][64];
    int first_results[200];

    for (int i = 0; i < 200; i++) {
        snprintf(src_paths[i], sizeof(src_paths[i]), "/allow/file_%04d.txt", i);
        snprintf(dst_paths[i], sizeof(dst_paths[i]), "/tmp/out_%04d.txt", i);
        if (i % 3 == 0) {
            first_results[i] = soft_ruleset_check_ctx(rs,
                &(soft_access_ctx_t){SOFT_OP_READ, src_paths[i], NULL, NULL, 1000}, NULL);
        } else {
            first_results[i] = soft_ruleset_check_ctx(rs,
                &(soft_access_ctx_t){SOFT_OP_COPY, src_paths[i], dst_paths[i], NULL, 1000}, NULL);
        }
    }

    /* Phase 2: Re-run — all must match */
    int mismatch = 0;
    for (int i = 0; i < 200; i++) {
        int second;
        if (i % 3 == 0) {
            second = soft_ruleset_check_ctx(rs,
                &(soft_access_ctx_t){SOFT_OP_READ, src_paths[i], NULL, NULL, 1000}, NULL);
        } else {
            second = soft_ruleset_check_ctx(rs,
                &(soft_access_ctx_t){SOFT_OP_COPY, src_paths[i], dst_paths[i], NULL, 1000}, NULL);
        }
        if (second != first_results[i]) mismatch++;
    }
    TEST_ASSERT_EQ(mismatch, 0, "all 200 warmed queries produce identical cached results");

    /* Phase 3: Denied paths still denied after cache warm */
    int deny_mismatch = 0;
    for (int i = 0; i < 50; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/deny/file_%04d.txt", i);
        int r = soft_ruleset_check_ctx(rs,
            &(soft_access_ctx_t){SOFT_OP_READ, path, NULL, NULL, 1000}, NULL);
        if (r != -13) deny_mismatch++;
    }
    TEST_ASSERT_EQ(deny_mismatch, 0, "all 50 denied paths still denied after cache warm");

    /* Phase 4: Cross-query reuse — shared SRC across many COPY queries */
    int cross_mismatch = 0;
    for (int i = 0; i < 100; i++) {
        char shared_src[64], unique_dst[64];
        snprintf(shared_src, sizeof(shared_src), "/allow/shared_%02d.txt", i / 10);
        snprintf(unique_dst, sizeof(unique_dst), "/tmp/unique_%04d.txt", i);

        /* READ shared_src first → caches with eval=READ */
        soft_ruleset_check_ctx(rs,
            &(soft_access_ctx_t){SOFT_OP_READ, shared_src, NULL, NULL, 1000}, NULL);

        /* COPY with same SRC → reuses cached READ for SRC */
        int r = soft_ruleset_check_ctx(rs,
            &(soft_access_ctx_t){SOFT_OP_COPY, shared_src, unique_dst, NULL, 1000}, NULL);
        if (r != (SOFT_ACCESS_READ | SOFT_ACCESS_WRITE)) cross_mismatch++;
    }
    TEST_ASSERT_EQ(cross_mismatch, 0, "all 100 cross-query reuse tests correct");

    soft_ruleset_free(rs);
}


void test_rule_engine_run(void)
{
    printf("=== Rule Engine Tests ===\n");
    RUN_TEST(test_rule_engine_basic_ops);
    RUN_TEST(test_rule_engine_expression_parser);
    RUN_TEST(test_rule_engine_constraints);
    RUN_TEST(test_rule_engine_audit_log);
    RUN_TEST(test_rule_engine_layer_behavior);
    RUN_TEST(test_rule_engine_uncovered_ops);
    RUN_TEST(test_rule_engine_query_cache);
    RUN_TEST(test_rule_engine_query_cache_lookup);
    RUN_TEST(test_rule_engine_query_cache_stress);
}
