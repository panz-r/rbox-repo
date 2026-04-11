/**
 * @file test_policy_parser.c
 * @brief Tests for the text-based policy parser and serializer.
 */

#include "test_framework.h"
#include "policy_parser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/*  Basic parsing                                                      */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Basic rule parsing and comments                                    */
/* ------------------------------------------------------------------ */

static void test_parser_basic_rules(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Case 1: Basic rule with EXEC operation */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs,
                   "/usr/** -> RW /exec\n",
                   &line, &err), 0, "basic: parse EXEC rule");
    soft_access_ctx_t ctx = { SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "basic: RW rule doesn't satisfy EXEC");
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_EXEC | SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "basic: EXEC rule grants EXEC for exec");
    soft_ruleset_free(rs);

    /* Case 2: Comments and blank lines */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text =
        "# This is a comment\n"
        "\n"
        "/data/** -> R\n"
        "  \n"
        "# Another comment\n"
        "/tmp/... -> RW recursive\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "basic: parse with comments and blanks");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "basic: commented rule works");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/tmp/deep/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE, "basic: recursive rule works");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer declarations and implicit layer state                        */
/* ------------------------------------------------------------------ */

static void test_parser_layer_declaration(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Case 1: Explicit layer declarations */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text =
        "@0 PRECEDENCE\n"
        "/data/... -> RW recursive\n"
        "@1 SPECIFICITY\n"
        "/data/secret -> D\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "layer: explicit declarations");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 2, "layer: 2 layers created");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE, "layer: file.txt allowed");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL, 1000}, NULL),
                   -13, "layer: secret denied");
    soft_ruleset_free(rs);

    /* Case 2: Implicit layer state — rules without @N inherit current layer */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text2 =
        "/usr/** -> R\n"           /* Implicit @0 */
        "@1 SPECIFICITY\n"
        "/data/** -> RW\n"         /* Explicit @1 */
        "/tmp/** -> R\n";          /* Implicit @1 (inherits context) */
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text2, &line, &err), 0,
                   "layer: implicit state");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 2, "layer: 2 layers created");
    soft_ruleset_free(rs);
}

static void test_parser_layer_mask(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Case 1: SPECIFICITY layer with mask R, rule grants RW → fail */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@1 SPECIFICITY:R\n/data/** -> RW\n", &line, &err), -1,
                   "mask: SPECIFICITY rule exceeds mask rejected");
    TEST_ASSERT(line != 0, "mask: error line set");
    soft_ruleset_free(rs);

    /* Case 2: Empty layer mask rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 SPECIFICITY:\n/data/** -> R\n", &line, &err), -1,
                   "mask: empty mask rejected");
    soft_ruleset_free(rs);

    /* Case 3: Rule within layer mask accepted */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@1 SPECIFICITY:R\n/data/** -> R\n", NULL, NULL), 0,
                   "mask: rule within mask accepted");
    soft_ruleset_free(rs);

    /* Case 4: DENY-only layer mask — DENY accepted, RW rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 SPECIFICITY:D\n/data/** -> D\n", &line, &err), 0,
                   "mask: DENY-only mask accepted");
    soft_ruleset_free(rs);
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@1 SPECIFICITY:D\n@1 /data/** -> RW\n", &line, &err), -1,
                   "mask: RW exceeds DENY-only mask rejected");
    soft_ruleset_free(rs);

    /* Case 5: DENY mode with R mask rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 SPECIFICITY:R\n/data/** -> D\n", &line, &err), -1,
                   "mask: DENY exceeds R mask rejected");
    TEST_ASSERT(line == 2, "mask: error on line 2");
    soft_ruleset_free(rs);

    /* Case 6: PRECEDENCE layer mask R, rule grants RW → fail */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 PRECEDENCE:R\n/data/** -> RW\n", &line, &err), -1,
                   "mask: PRECEDENCE rule exceeds mask rejected");
    TEST_ASSERT(line == 2, "mask: error on line 2");
    soft_ruleset_free(rs);

    /* Case 7: PRECEDENCE layer mask RW, rule grants RW → succeed */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 PRECEDENCE:RW\n/data/** -> RW\n", NULL, NULL), 0,
                   "mask: PRECEDENCE rule within mask accepted");
    soft_ruleset_free(rs);

    /* Case 8: PRECEDENCE explicit @0 rule with mask R, grants RW → fail */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 PRECEDENCE:R\n@0 /data/** -> RW\n", &line, &err), -1,
                   "mask: explicit @0 rule respects mask rejected");
    TEST_ASSERT(line == 2, "mask: error on line 2");
    soft_ruleset_free(rs);

    /* Case 9: Explicit layer 1 rule ignores implicit layer 0 mask */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 PRECEDENCE:R\n@1 SPECIFICITY\n/data/** -> RW\n", &line, &err), 0,
                   "mask: layer 1 rule ignores layer 0 mask");
    soft_ruleset_free(rs);

    /* Case 10: Explicit layer 1 rule with mask R, grants RW → fail */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@1 SPECIFICITY:R\n@1 /data/** -> RW\n", &line, &err), -1,
                   "mask: explicit layer 1 rule respects own mask rejected");
    TEST_ASSERT(line == 2, "mask: error on line 2");
    soft_ruleset_free(rs);

    /* Case 11: Rule on undeclared layer creates layers automatically */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text = "@5 /data/** -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "mask: undeclared layer 5 accepted");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 6, "mask: 6 layers created (0-5)");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 1, "mask: 1 rule added");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "mask: rule on layer 5 works");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Macro definition, expansion, and validation                       */
/* ------------------------------------------------------------------ */

static void test_parser_macros(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Case 1: Macro definitions with EXEC and READ operations */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text1 =
        "[BIN] /usr/bin/**\n"
        "[LIB] /usr/lib/**\n"
        "((BIN)) -> X /exec\n"
        "((LIB)) -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text1, &line, &err), 0,
                   "macro: parse definitions");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_EXEC,
                   "macro: BIN rule grants EXEC");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/usr/lib/libfoo.so", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ,
                   "macro: LIB rule grants READ");
    soft_ruleset_free(rs);

    /* Case 2: Nested macro expansion */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text2 =
        "[BASE] /usr\n"
        "[BIN] ((BASE))/bin/**\n"
        "((BIN)) -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text2, &line, &err), 0,
                   "macro: nested expansion works");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/usr/bin/gcc", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "macro: nested macro expanded correctly");
    soft_ruleset_free(rs);

    /* Case 3: Same macro used in multiple rules */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text3 =
        "[BIN] /usr/bin/**\n"
        "((BIN)) -> R /read\n"
        "((BIN)) -> X /exec\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text3, &line, &err), 0,
                   "macro: multiple uses work");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/usr/bin/gcc", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "macro: first rule with macro works");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/gcc", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_EXEC, "macro: EXEC rule matches too");
    soft_ruleset_free(rs);

    /* Case 4: Deep macro nesting (6 levels) */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text4 = "[A] ((B))/a\n[B] ((C))/b\n[C] ((D))/c\n[D] ((E))/d\n[E] ((F))/e\n[F] /base\n((A)) -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text4, &line, &err), 0,
                   "macro: deep nesting (6 levels) works");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Serialization: all roundtrip scenarios                             */
/* ------------------------------------------------------------------ */

static void test_serializer_roundtrip(void)
{
    char *text;

    /* Case 1: Basic serialization roundtrip */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "ser: serialize");
    TEST_ASSERT(text != NULL, "ser: output not NULL");
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "ser: parse");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, NULL),
                   "ser: rules produce same result");
    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 2: Layered ruleset roundtrip */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "ser: layered");
    TEST_ASSERT(strstr(text, "SPECIFICITY") != NULL, "ser: contains SPECIFICITY");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "ser: parse layered");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   "ser: layered rules match");
    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 3: Subject and UID constraints roundtrip */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, ".*admin$", 1000, 0);
    text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "ser: subject/uid");
    TEST_ASSERT(strstr(text, "subject:") != NULL, "ser: contains subject");
    TEST_ASSERT(strstr(text, "uid:") != NULL, "ser: contains uid");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "ser: parse subject/uid");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000}, NULL),
                   "ser: constraints match");
    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 4: Full features roundtrip (PRECEDENCE + SPECIFICITY) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
        SOFT_OP_COPY, "SRC", ".*cp$", 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/tmp/...", SOFT_ACCESS_READ,
        SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/tmp/secret", SOFT_ACCESS_DENY,
        SOFT_OP_READ, NULL, NULL, 0, 0);
    text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "ser: full features");
    TEST_ASSERT(text != NULL, "ser: output not NULL");
    TEST_ASSERT(strstr(text, "PRECEDENCE") != NULL, "ser: contains PRECEDENCE");
    TEST_ASSERT(strstr(text, "SPECIFICITY") != NULL, "ser: contains SPECIFICITY");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "ser: parse full");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), soft_ruleset_layer_count(rs2),
                   "ser: layer count matches");
    soft_access_ctx_t ctx1 = {SOFT_OP_COPY, "/data/file.txt", "/tmp/out.txt", "/usr/bin/cp", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx1, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx1, NULL),
                   "ser: COPY query matches");
    soft_access_ctx_t ctx2 = {SOFT_OP_READ, "/tmp/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx2, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx2, NULL),
                   "ser: DENY query matches");
    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 5: Ruleset with layer masks roundtrip */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, SOFT_ACCESS_READ | SOFT_ACCESS_WRITE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
        SOFT_OP_COPY, NULL, NULL, 0, 0);
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/secret", SOFT_ACCESS_DENY,
        SOFT_OP_READ, NULL, NULL, 0, 0);
    text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "ser: masks");
    TEST_ASSERT(text != NULL, "ser: masks output not NULL");
    TEST_ASSERT(strstr(text, ":") != NULL, "ser: masks contains separator");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "ser: parse masks");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs2), 2, "ser: 2 layers after parse");
    soft_access_ctx_t ctx3 = {SOFT_OP_COPY, "/data/file.txt", "/tmp/out.txt", NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx3, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx3, NULL),
                   "ser: COPY rule matches");
    soft_access_ctx_t ctx4 = {SOFT_OP_READ, "/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx4, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx4, NULL),
                   "ser: DENY rule matches");
    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 6: Deny-only ruleset roundtrip */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/secret", SOFT_ACCESS_DENY,
        SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/forbidden/**", SOFT_ACCESS_DENY,
        SOFT_OP_READ, NULL, NULL, 0, 0);
    text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "ser: deny-only");
    TEST_ASSERT(text != NULL, "ser: deny output not NULL");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "ser: parse deny-only");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/secret", NULL, NULL, 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/secret", NULL, NULL, 1000}, NULL),
                   "ser: deny rule matches");
    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 7: Empty ruleset roundtrip */
    rs = soft_ruleset_new();
    text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "ser: empty");
    TEST_ASSERT(text != NULL, "ser: empty output not NULL");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "ser: parse empty");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs2), 0, "ser: 0 rules after parse");
    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  File I/O: valid file, error, empty/whitespace                      */
/* ------------------------------------------------------------------ */

static void test_parser_file_io(void)
{
    const char *test_file = "/tmp/test_policy.tmp";
    const char *text = "[BIN] /usr/bin/**\n((BIN)) -> X /exec\n";
    FILE *f;

    /* Case 1: Write and parse valid file */
    f = fopen(test_file, "w");
    TEST_ASSERT(f != NULL, "file: open temp file for write");
    fprintf(f, "%s", text);
    fclose(f);
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_file(rs, test_file, &line, &err), 0,
                   "file: parse policy file");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_EXEC,
                   "file: parsed file grants EXEC");
    soft_ruleset_free(rs);
    unlink(test_file);

    /* Case 2: Non-existent file rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_file(rs, "/nonexistent/path/file.txt", &line, &err), -1,
                   "file: non-existent file rejected");
    soft_ruleset_free(rs);

    /* Case 3: Empty file parsed successfully */
    const char *empty_file = "/tmp/test_empty_policy.txt";
    f = fopen(empty_file, "w");
    TEST_ASSERT(f != NULL, "file: create empty file");
    fclose(f);
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_file(rs, empty_file, &line, &err), 0,
                   "file: empty file accepted");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 0, "file: no rules from empty file");
    soft_ruleset_free(rs);
    unlink(empty_file);

    /* Case 4: Whitespace-only file parsed successfully */
    const char *ws_file = "/tmp/test_ws_policy.txt";
    f = fopen(ws_file, "w");
    TEST_ASSERT(f != NULL, "file: create whitespace file");
    fprintf(f, "   \n  \n\t\n");
    fclose(f);
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_file(rs, ws_file, &line, &err), 0,
                   "file: whitespace-only file accepted");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 0, "file: no rules from whitespace-only file");
    soft_ruleset_free(rs);
    unlink(ws_file);
}

/* ------------------------------------------------------------------ */
/*  Subject regex round-trip with special characters                   */
/* ------------------------------------------------------------------ */

static void test_parser_subject_roundtrip(void)
{
    char *out_text;
    soft_ruleset_t *rs, *rs2;
    int line;
    const char *err;

    /* Case 1: Parse quoted subject with spaces */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text1 =
        "/data/** -> R subject:\".*admin user$\"\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text1, &line, &err), 0,
                   "subj: parse quoted subject with spaces");
    out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "subj: serialize");
    TEST_ASSERT(out_text != NULL, "subj: output not NULL");
    TEST_ASSERT(strstr(out_text, "\"") != NULL, "subj: contains quotes");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, NULL, NULL), 0,
                   "subj: parse serialized");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin user", 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin user", 1000}, NULL),
                   "subj: round-trip matches");
    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 2: Subject with double quotes */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
        SOFT_OP_READ, NULL, ".*\\\"admin\\\"$", 1000, 0);
    out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "subj: serialize quotes");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, NULL, NULL), 0,
                   "subj: parse quotes");
    soft_access_ctx_t ctx1 = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/\\\"admin\\\"", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx1, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx1, NULL),
                   "subj: quotes round-trip matches");
    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 3: Subject with # character */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
        SOFT_OP_READ, NULL, ".*admin#1$", 1000, 0);
    out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "subj: serialize hash");
    TEST_ASSERT(strstr(out_text, "\"") != NULL, "subj: hash output contains quotes");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, NULL, NULL), 0,
                   "subj: parse hash");
    soft_access_ctx_t ctx2 = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin#1", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx2, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx2, NULL),
                   "subj: hash round-trip matches");
    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);

    /* Case 4: Subject with backslash */
    rs = soft_ruleset_new();
    const char *subject_regex = ".*admin\\\\user$";
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
        SOFT_OP_READ, NULL, subject_regex, 1000, 0);
    out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "subj: serialize backslash");
    TEST_ASSERT(strstr(out_text, "\"") != NULL, "subj: backslash output contains quotes");
    rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, NULL, NULL), 0,
                   "subj: parse backslash");
    const char *test_subject = "/usr/bin/admin\\\\user";
    soft_access_ctx_t ctx3 = {SOFT_OP_READ, "/data/file.txt", NULL, test_subject, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx3, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx3, NULL),
                   "subj: backslash round-trip matches");
    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  Mode and operation type parsing                                    */
/* ------------------------------------------------------------------ */

static void test_parser_mode_and_operation_types(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Case 1: All mode characters uppercase — parse and verify access */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> RWXCU\n", &line, &err), 0,
                   "mode: all uppercase chars accepted");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC | SOFT_ACCESS_CREATE | SOFT_ACCESS_UNLINK,
                   "mode: all modes granted");
    soft_ruleset_free(rs);

    /* Case 2: Lowercase mode chars */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> rwxcu\n", NULL, NULL), 0,
                   "mode: lowercase chars accepted");
    soft_ruleset_free(rs);

    /* Case 3: Mixed case mode chars */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> RwXcU\n", NULL, NULL), 0,
                   "mode: mixed-case chars accepted");
    soft_ruleset_free(rs);

    /* Case 4: Invalid mode char rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> RZ\n", &line, &err), -1,
                   "mode: invalid char rejected");
    soft_ruleset_free(rs);

    /* Case 5: DENY alone */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/secret -> D\n", &line, &err), 0,
                   "mode: DENY alone accepted");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL, 1000}, NULL),
                   -13, "mode: DENY denies access");
    soft_ruleset_free(rs);

    /* Case 6: DENY with other modes still results in DENY */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> DRWX\n", &line, &err), 0,
                   "mode: DENY with other modes accepted");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   -13, "mode: DENY with other modes still denies");
    soft_ruleset_free(rs);

    /* Case 7: All operation types accepted (lowercase, uppercase, mixed) */
    const char *ops[] = {"read", "write", "exec", "copy", "move", "link", "mount", "chmod", "custom", NULL};
    const char *ops_upper[] = {"READ", "WRITE", "EXEC", "COPY", "MOVE", "LINK", "MOUNT", "CHMOD", "CUSTOM", NULL};
    const char *ops_mixed[] = {"ReAd", "WrItE", "ExEc", "CoPy", "MoVe", "LiNk", "MoUnT", "ChMoD", "CuStOm", NULL};

    for (int i = 0; ops[i]; i++) {
        /* Lowercase */
        rs = soft_ruleset_new();
        char text1[64];
        snprintf(text1, sizeof(text1), "/data/** -> R /%s\n", ops[i]);
        TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text1, NULL, NULL), 0,
                       "op: lowercase accepted");
        soft_ruleset_free(rs);

        /* Uppercase */
        rs = soft_ruleset_new();
        char text2[64];
        snprintf(text2, sizeof(text2), "/data/** -> R /%s\n", ops_upper[i]);
        TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text2, NULL, NULL), 0,
                       "op: uppercase accepted");
        soft_ruleset_free(rs);

        /* Mixed case */
        rs = soft_ruleset_new();
        char text3[64];
        snprintf(text3, sizeof(text3), "/data/** -> R /%s\n", ops_mixed[i]);
        TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text3, NULL, NULL), 0,
                       "op: mixed-case accepted");
        soft_ruleset_free(rs);
    }
}

/* ------------------------------------------------------------------ */
/*  Layer and macro syntax edge cases                                 */
/* ------------------------------------------------------------------ */

static void test_parser_layer_macro_edge_cases(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Case 1: Layer boundary minimum (0) */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 PRECEDENCE\n/data/** -> R\n", &line, &err), 0,
                   "edge: layer 0 accepted");
    soft_ruleset_free(rs);

    /* Case 2: Layer boundary maximum (63) */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@63 PRECEDENCE\n/data/** -> R\n", &line, &err), 0,
                   "edge: layer 63 accepted");
    soft_ruleset_free(rs);

    /* Case 3: Layer out of range (64) */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@64 PRECEDENCE\n/data/** -> R\n", &line, &err), -1,
                   "edge: layer 64 rejected");
    TEST_ASSERT(line == 1, "edge: error on line 1");
    soft_ruleset_free(rs);

    /* Case 4: Negative layer */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@-1 PRECEDENCE\n/data/** -> R\n", &line, &err), -1,
                   "edge: negative layer rejected");
    soft_ruleset_free(rs);

    /* Case 5: recursiveX should not match recursive */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/... -> R recursiveX\n", &line, &err), -1,
                   "edge: recursiveX rejected");
    TEST_ASSERT(line == 1, "edge: error on line 1");
    soft_ruleset_free(rs);

    /* Case 6: Macro ID starting with digit rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[1BIN] /usr/bin/**\n", &line, &err), -1,
                   "edge: macro ID starting with digit rejected");
    soft_ruleset_free(rs);

    /* Case 7: Unmatched macro reference rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[BIN] /usr/bin/**\n((BIN) -> R\n", &line, &err), -1,
                   "edge: unmatched (( in macro reference rejected");
    TEST_ASSERT(line == 2, "edge: error on line 2");
    soft_ruleset_free(rs);

    /* Case 8: @0 /PRECEDENCE -> R parses as rule with pattern /PRECEDENCE */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text1 = "@0 /PRECEDENCE -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text1, &line, &err), 0,
                   "edge: pattern /PRECEDENCE accepted");
    TEST_ASSERT_EQ(line, 0, "edge: no error");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 1, "edge: layer 0 created");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 1, "edge: rule added");
    soft_ruleset_free(rs);

    /* Case 9: @0PRECEDENCE (no space) parsed as layer declaration */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text2 = "@0PRECEDENCE\n/data/** -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text2, &line, &err), 0,
                   "edge: decl without space accepted");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Macro ID validation                                                */
/* ------------------------------------------------------------------ */

static void test_parser_macro_id_validation(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Macro ID starting with underscore is valid */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[_BIN] /usr/bin/**\n((_BIN)) -> R\n", &line, &err), 0,
                   "macro ID starting with underscore accepted");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/usr/bin/gcc", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "underscore macro works");
    soft_ruleset_free(rs);

    /* Macro ID with digits after first char is valid */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[BIN1] /usr/bin/**\n((BIN1)) -> R\n", &line, &err), 0,
                   "macro ID with digits after start accepted");
    soft_ruleset_free(rs);

    /* Macro ID at max length (63 chars) */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    char id63[64];
    memset(id63, 'a', 63);
    id63[63] = '\0';
    char text63[200];
    snprintf(text63, sizeof(text63), "[%s] /data/**\n((%s)) -> R\n", id63, id63);
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text63, &line, &err), 0,
                   "macro ID at max length accepted");
    soft_ruleset_free(rs);

    /* Macro ID too long (64 chars) */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    char id64[65];
    memset(id64, 'a', 64);
    id64[64] = '\0';
    char text64[200];
    snprintf(text64, sizeof(text64), "[%s] /data/**\n", id64);
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text64, &line, &err), -1,
                   "macro ID too long rejected");
    TEST_ASSERT(line == 1, "error on line 1");
    soft_ruleset_free(rs);

    /* Macro ID starting with digit is rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[1BIN] /usr/bin/**\n", &line, &err), -1,
                   "macro ID starting with digit rejected");
    TEST_ASSERT(line == 1, "error on line 1");
    soft_ruleset_free(rs);

    /* Empty macro ID is rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[] /data/**\n", &line, &err), -1,
                   "empty macro ID rejected");
    TEST_ASSERT(line == 1, "error on line 1");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Parsing edge cases: syntax errors, comments, whitespace, modes     */
/* ------------------------------------------------------------------ */

static void test_parser_parsing_edge_cases(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Syntax errors */

    /* Case 1: Missing '->' separator rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** R\n", &line, &err), -1,
                   "syntax: missing arrow rejected");
    soft_ruleset_free(rs);

    /* Case 2: Invalid mode character rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> Z\n", &line, &err), -1,
                   "syntax: invalid mode rejected");
    soft_ruleset_free(rs);

    /* Case 3: Unknown layer type rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 UNKNOWN\n", &line, &err), -1,
                   "syntax: unknown layer type rejected");
    soft_ruleset_free(rs);

    /* Case 4: Undefined macro reference rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "((UNDEFINED)) -> R\n", &line, &err), -1,
                   "syntax: undefined macro rejected");
    TEST_ASSERT(line != 0, "syntax: error line set");
    soft_ruleset_free(rs);

    /* Case 5: Circular macro reference detected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[A] ((B))\n[B] ((A))\n((A)) -> R\n", &line, &err), -1,
                   "syntax: circular reference detected");
    TEST_ASSERT(line == 3, "syntax: error on line 3");
    TEST_ASSERT(err != NULL, "syntax: error message set");
    soft_ruleset_free(rs);

    /* Case 6: Macro with whitespace-only pattern rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[EMPTY] \n((EMPTY)) -> R\n", &line, &err), -1,
                   "syntax: whitespace-only pattern rejected");
    soft_ruleset_free(rs);

    /* Valid edge cases */

    /* Case 7: Comment after rule accepted */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text1 = "/data/** -> R # this is a comment\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text1, &line, &err), 0,
                   "edge: comment after rule accepted");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "edge: rule with comment works");
    soft_ruleset_free(rs);

    /* Case 8: Extra whitespace between tokens accepted */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text2 = "/data/**   ->   R   /read   subject:.*cp$   uid:1000   recursive\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text2, &line, &err), 0,
                   "edge: extra whitespace accepted");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/cp", 1000}, NULL),
                   SOFT_ACCESS_READ, "edge: rule with extra whitespace works");
    soft_ruleset_free(rs);

    /* Case 9: Unknown operation type rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text3 = "/data/** -> R /readextra\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text3, &line, &err), -1,
                   "edge: unknown operation rejected");
    TEST_ASSERT(line == 1, "edge: error on line 1");
    soft_ruleset_free(rs);

    /* Case 10: Layer declaration with trailing whitespace */
    rs = soft_ruleset_new();
    const char *text4 = "@0 PRECEDENCE  \n/data/** -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text4, NULL, NULL), 0,
                   "edge: layer decl with trailing whitespace");
    soft_ruleset_free(rs);

    /* Case 11: DENY mode with other characters (DENY overrides) */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text5 = "/data/** -> DR\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text5, &line, &err), 0,
                   "edge: DR mode accepted (DENY overrides)");
    soft_ruleset_free(rs);

    /* Case 12: Empty mode after arrow rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text6 = "/data/** -> \n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text6, &line, &err), -1,
                   "edge: empty mode after arrow rejected");
    soft_ruleset_free(rs);

    /* Case 13: Empty string parsed successfully */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "", NULL, NULL), 0,
                   "edge: empty string accepted");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 0, "edge: no rules from empty");
    soft_ruleset_free(rs);

    /* Case 14: Whitespace-only parsed successfully */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "   \n  \n\t\n", NULL, NULL), 0,
                   "edge: whitespace only accepted");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs), 0, "edge: no rules from whitespace");
    soft_ruleset_free(rs);

    /* Case 15: NULL input rejected */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, NULL, NULL, NULL), -1,
                   "edge: NULL input rejected");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Constraint edge cases: subject, UID, pattern                      */
/* ------------------------------------------------------------------ */

static void test_parser_constraint_edge_cases(void)
{
    soft_ruleset_t *rs;
    int line;
    const char *err;

    /* Case 1: Subject and UID constraints — parse and verify */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text0 =
        "/data/** -> R /read subject:.*admin$ uid:1000\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text0, &line, &err), 0,
                   "constraint: subject and uid parsed");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000}, NULL),
                   SOFT_ACCESS_READ, "constraint: matching subject and UID allowed");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/user", 1000}, NULL),
                   -13, "constraint: non-matching subject denied");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 500}, NULL),
                   -13, "constraint: low UID denied");
    soft_ruleset_free(rs);

    /* Case 2: Empty quoted subject regex rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text1 = "/data/** -> R subject:\"\"\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text1, &line, &err), -1,
                   "constraint: empty quoted subject rejected");
    TEST_ASSERT(line == 1, "constraint: error on line 1");
    soft_ruleset_free(rs);

    /* Case 3: Unquoted subject without spaces accepted */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text2 = "/data/** -> R subject:.*admin$\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text2, &line, &err), 0,
                   "constraint: unquoted subject accepted");
    soft_ruleset_free(rs);

    /* Case 4: UID 0 accepted */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> R uid:0\n", NULL, NULL), 0,
                   "constraint: uid:0 accepted");
    soft_ruleset_free(rs);

    /* Case 5: Negative UID rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> R uid:-1\n", &line, &err), -1,
                   "constraint: negative uid rejected");
    soft_ruleset_free(rs);

    /* Case 6: Overflow UID rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> R uid:99999999999999\n", &line, &err), -1,
                   "constraint: overflow uid rejected");
    soft_ruleset_free(rs);

    /* Case 7: Non-numeric UID rejected */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> R uid:abc\n", &line, &err), -1,
                   "constraint: non-numeric uid rejected");
    soft_ruleset_free(rs);

    /* Case 8: Pattern with # in the middle accepted */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text3 = "/data/#temp/** -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text3, &line, &err), 0,
                   "constraint: # in pattern accepted");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/#temp/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "constraint: rule with # matches");
    soft_ruleset_free(rs);

    /* Case 9: Pattern with spaces (quoted) accepted */
    rs = soft_ruleset_new();
    line = 0; err = NULL;
    const char *text4 = "\"/path/with spaces/**\" -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text4, &line, &err), 0,
                   "constraint: quoted pattern with spaces accepted");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  API NULL argument handling                                          */
/* ------------------------------------------------------------------ */

static void test_parser_null_arguments(void)
{
    soft_ruleset_t *rs;
    char *out_text;
    int line;
    const char *err;

    /* soft_ruleset_parse_text NULL args */
    TEST_ASSERT_EQ(soft_ruleset_parse_text(NULL, "/data/** -> R\n", NULL, NULL), -1,
                   "null: parse_text NULL rs rejected");
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, NULL, NULL, NULL), -1,
                   "null: parse_text NULL text rejected");
    soft_ruleset_free(rs);

    /* soft_ruleset_parse_file NULL args */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_file(rs, NULL, NULL, NULL), -1,
                   "null: parse_file NULL path rejected");
    TEST_ASSERT_EQ(soft_ruleset_parse_file(NULL, "/tmp/test.txt", NULL, NULL), -1,
                   "null: parse_file NULL rs rejected");
    soft_ruleset_free(rs);

    /* soft_ruleset_write_text NULL args */
    out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(NULL, &out_text), -1,
                   "null: write_text NULL rs rejected");
    TEST_ASSERT(out_text == NULL, "null: no output for NULL rs");
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, NULL), -1,
                   "null: write_text NULL out rejected");
    soft_ruleset_free(rs);

    /* soft_ruleset_write_file NULL args */
    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_write_file(rs, NULL), -1,
                   "null: write_file NULL path rejected");
    TEST_ASSERT_EQ(soft_ruleset_write_file(NULL, "/tmp/test.txt"), -1,
                   "null: write_file NULL rs rejected");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */

void test_rule_engine_parser_run(void)
{
    printf("=== Policy Parser Tests ===\n");
    RUN_TEST(test_parser_basic_rules);
    RUN_TEST(test_parser_layer_declaration);
    RUN_TEST(test_parser_layer_mask);
    RUN_TEST(test_parser_macros);
    RUN_TEST(test_serializer_roundtrip);
    RUN_TEST(test_parser_file_io);
    RUN_TEST(test_parser_subject_roundtrip);
    RUN_TEST(test_parser_mode_and_operation_types);
    RUN_TEST(test_parser_layer_macro_edge_cases);
    RUN_TEST(test_parser_parsing_edge_cases);
    RUN_TEST(test_parser_macro_id_validation);
    RUN_TEST(test_parser_constraint_edge_cases);
    RUN_TEST(test_parser_null_arguments);
}
