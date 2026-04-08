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

    /* READ check 1: allowed by /usr/** */
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
/*  Layer behavior: mechanics, shadowing, intersection, constraints    */
/* ------------------------------------------------------------------ */

static void test_rule_engine_layer_behavior(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Part 1: Layer mechanics — initial state, layer creation */
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

    /* Part 2: Static DENY shadows template ALLOW */
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

    /* Part 4: Layer shadowing — Layer 0 DENY shadows Layer 1 ALLOW */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/secret",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 0 deny /secret");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/secret",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 1 allow /secret");

    /* Part 5: Mode intersection — READ ∩ WRITE = 0 → denied */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/intersect",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 0 read /intersect");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/intersect",
                   SOFT_ACCESS_WRITE, SOFT_OP_WRITE, NULL, NULL, 0, 0),
                   0, "layer 1 write /intersect");

    /* Part 6: Mode intersection — READ ∩ READ = READ */
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 0, "/both",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 0 read /both");
    TEST_ASSERT_EQ(soft_ruleset_add_rule_at_layer(rs, 1, "/both",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0),
                   0, "layer 1 read /both");

    /* Part 7: Three layers, bottom DENY short-circuits */
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
                   "layer intersection READ ∩ WRITE = 0 → denied");

    /* Check 3: intersection allows */
    ctx.src_path = "/both";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), SOFT_ACCESS_READ,
                   "both layers allow READ → intersection grants");

    /* Check 4: three-layer DENY short-circuits */
    ctx.src_path = "/triple";
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "layer 2 DENY short-circuits despite layers 0,1");

    /* Check 5: layer count */
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 3,
                   "3 layers exist after adding rules at layers 0,1,2");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_rule_engine_run(void)
{
    printf("=== Rule Engine Tests ===\n");
    RUN_TEST(test_rule_engine_basic_ops);
    RUN_TEST(test_rule_engine_expression_parser);
    RUN_TEST(test_rule_engine_constraints);
    RUN_TEST(test_rule_engine_audit_log);
    RUN_TEST(test_rule_engine_layer_behavior);
}
