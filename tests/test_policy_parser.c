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

static void test_parser_basic_rule(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Rule grants READ|WRITE for exec operations */
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs,
                   "/usr/** -> RW /exec\n",
                   &line, &err), 0, "parse basic rule");

    /* Exec operation requires EXEC mode - RW rule doesn't satisfy it */
    soft_access_ctx_t ctx = { SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000 };
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL), -13,
                   "RW rule doesn't satisfy EXEC requirement");

    /* But a rule with EXEC mode does satisfy it */
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   SOFT_ACCESS_EXEC | SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                   "EXEC rule grants EXEC for exec (OR with RW rule)");

    soft_ruleset_free(rs);
}

static void test_parser_comments_and_blanks(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    const char *text =
        "# This is a comment\n"
        "\n"
        "/data/** -> R\n"
        "  \n"
        "# Another comment\n"
        "/tmp/... -> RW recursive\n";

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "parse with comments and blanks");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "commented rule works");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/tmp/deep/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE, "recursive rule works");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer declarations                                                  */
/* ------------------------------------------------------------------ */

static void test_parser_layer_decl(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    const char *text =
        "@0 PRECEDENCE\n"
        "/data/... -> RW recursive\n"
        "@1 SPECIFICITY\n"
        "/data/secret -> D\n";

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "parse layer declarations");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 2, "2 layers created");

    /* Layer 0 grants RW, Layer 1 denies /data/secret → PRECEDENCE intersection:
     * For /data/file.txt: layer 0 grants RW, layer 1 has no rule → RW
     * For /data/secret: layer 0 grants RW, layer 1 denies → DENY
     */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE, "layer 0 allows /data/file.txt with RW");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL, 1000}, NULL),
                   -13, "layer 1 denies /data/secret");

    soft_ruleset_free(rs);
}

static void test_parser_layer_mask(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* SPECIFICITY layer with mask R: rule requesting RW should fail */
    const char *text =
        "@1 SPECIFICITY:R\n"
        "/data/** -> RW\n";

    int ret = soft_ruleset_parse_text(rs, text, &line, &err);
    TEST_ASSERT_EQ(ret, -1, "rule exceeding mask is rejected");
    TEST_ASSERT(line != 0, "error line number is set");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Implicit layer state                                                */
/* ------------------------------------------------------------------ */

static void test_parser_implicit_layer(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Rules without @N prefix should go to current layer */
    const char *text =
        "/usr/** -> R\n"           /* Implicit @0 */
        "@1 SPECIFICITY\n"
        "/data/** -> RW\n"         /* Explicit @1 */
        "/tmp/** -> R\n";          /* Implicit @1 (inherits context) */

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "parse with implicit layer state");
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), 2, "2 layers created");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Macros                                                              */
/* ------------------------------------------------------------------ */

static void test_parser_macro_def(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    const char *text =
        "[BIN] /usr/bin/**\n"
        "[LIB] /usr/lib/**\n"
        "((BIN)) -> X /exec\n"
        "((LIB)) -> R\n";

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "parse with macro definitions");

    /* /usr/bin/bash should match BIN macro expanded to /usr/bin/wildcard */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_EXEC,
                   "macro expanded BIN rule works");

    /* /usr/lib/libfoo.so should match LIB macro expanded to /usr/lib/wildcard */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/usr/lib/libfoo.so", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ,
                   "macro expanded LIB rule works");

    soft_ruleset_free(rs);
}

static void test_parser_macro_undefined(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    const char *text = "((UNDEFINED)) -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), -1,
                   "undefined macro is rejected");
    TEST_ASSERT(line != 0, "error line number is set");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Subject and UID constraints                                         */
/* ------------------------------------------------------------------ */

static void test_parser_subject_and_uid(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    const char *text =
        "/data/** -> R /read subject:.*admin$ uid:1000\n";

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "parse subject and uid");

    /* Matching subject and UID */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000}, NULL),
                   SOFT_ACCESS_READ, "matching subject and UID allowed");

    /* Non-matching subject */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/user", 1000}, NULL),
                   -13, "non-matching subject denied");

    /* Low UID */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 500}, NULL),
                   -13, "low UID denied");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Error handling                                                      */
/* ------------------------------------------------------------------ */

static void test_parser_missing_arrow(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** R\n", &line, &err), -1,
                   "missing '->' separator is rejected");

    soft_ruleset_free(rs);
}

static void test_parser_invalid_mode(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> Z\n", &line, &err), -1,
                   "invalid mode char is rejected");

    soft_ruleset_free(rs);
}

static void test_parser_invalid_layer_type(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@0 UNKNOWN\n", &line, &err), -1,
                   "unknown layer type is rejected");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Serialization                                                       */
/* ------------------------------------------------------------------ */

static void test_serializer_basic(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    char *text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "serialize to text");
    TEST_ASSERT(text != NULL, "output text is not NULL");

    /* Parse the serialized text back */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "parse serialized text");

    /* Verify rules are identical */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, NULL),
                   "serialized rules produce same result");

    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

static void test_serializer_layered(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/secret", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    char *text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "serialize layered ruleset");
    TEST_ASSERT(strstr(text, "SPECIFICITY") != NULL, "output contains SPECIFICITY");

    /* Parse back and verify behavior */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "parse serialized layered text");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   "serialized layered rules produce same result");

    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

static void test_serializer_subject_and_uid(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, ".*admin$", 1000, 0);

    char *text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &text), 0, "serialize with subject and uid");
    TEST_ASSERT(strstr(text, "subject:") != NULL, "output contains subject");
    TEST_ASSERT(strstr(text, "uid:") != NULL, "output contains uid");

    /* Parse back */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, text, NULL, NULL), 0,
                   "parse serialized text with subject and uid");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin", 1000}, NULL),
                   "serialized rules with constraints produce same result");

    free(text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  File I/O                                                            */
/* ------------------------------------------------------------------ */

static void test_parser_file_io(void)
{
    const char *test_file = "/tmp/test_policy.tmp";
    const char *text = "[BIN] /usr/bin/**\n((BIN)) -> X /exec\n";

    /* Write file */
    FILE *f = fopen(test_file, "w");
    TEST_ASSERT(f != NULL, "open temp file for write");
    fprintf(f, "%s", text);
    fclose(f);

    /* Parse file */
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_file(rs, test_file, &line, &err), 0,
                   "parse policy file");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/bash", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_EXEC,
                   "parsed file grants EXEC for exec");

    soft_ruleset_free(rs);
    unlink(test_file);
}

/* ------------------------------------------------------------------ */
/*  Quoted subject regex                                                */
/* ------------------------------------------------------------------ */

static void test_parser_quoted_subject(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Subject regex with spaces requires quoting */
    const char *text =
        "/data/** -> R subject:\".*admin user$\"\n";

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "parse quoted subject regex");

    /* Verify round-trip serialization */
    char *out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "serialize quoted subject");
    TEST_ASSERT(out_text != NULL, "serialized text is not NULL");
    TEST_ASSERT(strstr(out_text, "\"") != NULL, "output contains quotes for subject with spaces");

    /* Parse serialized text back */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, NULL, NULL), 0,
                   "parse serialized quoted subject");

    /* Verify behavior matches */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin user", 1000}, NULL),
                   soft_ruleset_check_ctx(rs2,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin user", 1000}, NULL),
                   "quoted subject round-trip produces same result");

    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  Edge cases: empty/whitespace input                                  */
/* ------------------------------------------------------------------ */

static void test_parser_empty_input(void)
{
    /* Empty string */
    soft_ruleset_t *rs1 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs1, "", NULL, NULL), 0, "parse empty string");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs1), 0, "no rules from empty string");
    soft_ruleset_free(rs1);

    /* Whitespace only */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, "   \n  \n\t\n", NULL, NULL), 0, "parse whitespace only");
    TEST_ASSERT_EQ(soft_ruleset_rule_count(rs2), 0, "no rules from whitespace");
    soft_ruleset_free(rs2);

    /* NULL input */
    soft_ruleset_t *rs3 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs3, NULL, NULL, NULL), -1, "NULL input rejected");
    soft_ruleset_free(rs3);
}

/* ------------------------------------------------------------------ */
/*  Edge cases: macro expansion                                         */
/* ------------------------------------------------------------------ */

static void test_parser_macro_nested(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Macro using another macro in pattern */
    const char *text =
        "[BASE] /usr\n"
        "[BIN] ((BASE))/bin/**\n"
        "((BIN)) -> R\n";

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "parse nested macro expansion");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/usr/bin/gcc", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "nested macro expanded correctly");

    soft_ruleset_free(rs);
}

static void test_parser_macro_multiple_uses(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Same macro used in multiple rules */
    const char *text =
        "[BIN] /usr/bin/**\n"
        "((BIN)) -> R /read\n"
        "((BIN)) -> X /exec\n";

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "parse multiple uses of same macro");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/usr/bin/gcc", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "first rule with macro works");
    /* EXEC operation matches both READ and EXEC rules (READ rules match EXEC ops) */
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_EXEC, "/usr/bin/gcc", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_EXEC, "second rule with macro works");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Edge cases: all mode characters                                     */
/* ------------------------------------------------------------------ */

static void test_parser_all_modes(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* All mode characters in one rule */
    const char *text = "/data/** -> RWXCU\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0, "parse all mode chars");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC | SOFT_ACCESS_CREATE | SOFT_ACCESS_UNLINK,
                   "all modes granted");

    soft_ruleset_free(rs);
}

static void test_parser_deny_mode(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* DENY alone */
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/secret -> D\n", &line, &err), 0, "parse DENY alone");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/secret", NULL, NULL, 1000}, NULL),
                   -13, "DENY denies access");

    soft_ruleset_free(rs);
}

static void test_parser_lowercase_modes(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Lowercase mode chars */
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/** -> rw\n", &line, &err), 0, "parse lowercase modes");
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ | SOFT_ACCESS_WRITE, "lowercase modes work");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Edge cases: all operation types                                     */
/* ------------------------------------------------------------------ */

static void test_parser_all_operations(void)
{
    const char *ops[] = {"read", "write", "exec", "copy", "move", "link", "mount", "chmod", "custom", NULL};

    for (int i = 0; ops[i]; i++) {
        soft_ruleset_t *rs = soft_ruleset_new();
        char text[64];
        snprintf(text, sizeof(text), "/data/** -> R /%s\n", ops[i]);

        TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, NULL, NULL), 0,
                       "parse operation");

        soft_ruleset_free(rs);
    }
}

/* ------------------------------------------------------------------ */
/*  Edge cases: layer boundaries                                        */
/* ------------------------------------------------------------------ */

static void test_parser_layer_boundaries(void)
{
    /* Layer 0 (minimum) */
    soft_ruleset_t *rs1 = soft_ruleset_new();
    int line1 = 0;
    const char *err1 = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs1, "@0 PRECEDENCE\n/data/** -> R\n", &line1, &err1), 0,
                   "parse layer 0");
    soft_ruleset_free(rs1);

    /* Layer 63 (maximum) */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    int line2 = 0;
    const char *err2 = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, "@63 PRECEDENCE\n/data/** -> R\n", &line2, &err2), 0,
                   "parse layer 63");
    soft_ruleset_free(rs2);

    /* Layer 64 (out of range) */
    soft_ruleset_t *rs3 = soft_ruleset_new();
    int line3 = 0;
    const char *err3 = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs3, "@64 PRECEDENCE\n/data/** -> R\n", &line3, &err3), -1,
                   "layer 64 rejected");
    soft_ruleset_free(rs3);

    /* Negative layer */
    soft_ruleset_t *rs4 = soft_ruleset_new();
    int line4 = 0;
    const char *err4 = NULL;
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs4, "@-1 PRECEDENCE\n/data/** -> R\n", &line4, &err4), -1,
                   "negative layer rejected");
    soft_ruleset_free(rs4);
}

/* ------------------------------------------------------------------ */
/*  Round-trip: full features                                           */
/* ------------------------------------------------------------------ */

static void test_serializer_roundtrip_full(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Layer 0: PRECEDENCE with various features */
    soft_ruleset_add_rule_at_layer(rs, 0, "${SRC}", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
        SOFT_OP_COPY, "SRC", ".*cp$", 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/tmp/...", SOFT_ACCESS_READ,
        SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);

    /* Layer 1: SPECIFICITY */
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/tmp/secret", SOFT_ACCESS_DENY,
        SOFT_OP_READ, NULL, NULL, 0, 0);

    /* Serialize */
    char *out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "serialize full ruleset");
    TEST_ASSERT(out_text != NULL, "serialized text is not NULL");
    TEST_ASSERT(strstr(out_text, "PRECEDENCE") != NULL, "output contains PRECEDENCE");
    TEST_ASSERT(strstr(out_text, "SPECIFICITY") != NULL, "output contains SPECIFICITY");

    /* Parse back */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, NULL, NULL), 0,
                   "parse serialized full ruleset");

    /* Verify layer counts match */
    TEST_ASSERT_EQ(soft_ruleset_layer_count(rs), soft_ruleset_layer_count(rs2),
                   "layer count matches after round-trip");

    /* Verify behavior matches for several queries */
    soft_access_ctx_t ctx1 = {SOFT_OP_COPY, "/data/file.txt", "/tmp/out.txt", "/usr/bin/cp", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx1, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx1, NULL),
                   "COPY query matches after round-trip");

    soft_access_ctx_t ctx2 = {SOFT_OP_READ, "/tmp/secret", NULL, NULL, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx2, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx2, NULL),
                   "DENY query matches after round-trip");

    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  Edge cases: error handling                                         */
/* ------------------------------------------------------------------ */

static void test_parser_macro_id_start_digit(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[1BIN] /usr/bin/**\n", &line, &err), -1,
                   "macro ID starting with digit rejected");

    soft_ruleset_free(rs);
}

static void test_parser_unmatched_macro_ref(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[BIN] /usr/bin/**\n((BIN) -> R\n", &line, &err), -1,
                   "unmatched (( in macro reference rejected");
    TEST_ASSERT(line == 2, "error on line 2");

    soft_ruleset_free(rs);
}

static void test_parser_invalid_layer_index(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "@64 PRECEDENCE\n/data/** -> R\n", &line, &err), -1,
                   "layer 64 rejected");
    TEST_ASSERT(line == 1, "error on line 1");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Escaping and quoting                                                */
/* ------------------------------------------------------------------ */

static void test_parser_subject_backslash(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Subject regex with backslash (needs quoting in serialization) */
    const char *subject_regex = ".*admin\\\\user$";
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
        SOFT_OP_READ, NULL, subject_regex, 1000, 0);

    char *out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "serialize subject with backslash");

    /* Verify the serialized output contains quotes */
    int has_quote = 0;
    for (const char *p = out_text; *p; p++) {
        if (*p == '"') { has_quote = 1; break; }
    }
    TEST_ASSERT(has_quote, "output contains quotes for backslash");

    /* Parse back and verify round-trip */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, &line, &err), 0,
                   "parse serialized backslash subject");

    /* Verify behavior matches */
    const char *test_subject = "/usr/bin/admin\\\\user";
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, test_subject, 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx, NULL),
                   "backslash subject round-trip produces same result");

    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  Parsing edge cases                                                  */
/* ------------------------------------------------------------------ */

static void test_parser_recursive_prefix(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* recursiveX should not match recursive */
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "/data/... -> R recursiveX\n", &line, &err), -1,
                   "recursiveX rejected as unknown token");
    TEST_ASSERT(line == 1, "error on line 1");

    soft_ruleset_free(rs);
}

static void test_parser_precedence_layer_mask_violation(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* PRECEDENCE layer mask R, but rule grants RW - should fail */
    const char *text = "@0 PRECEDENCE:R\n/data/** -> RW\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), -1,
                   "PRECEDENCE rule exceeding layer mask rejected");
    TEST_ASSERT(line == 2, "error on line 2");

    soft_ruleset_free(rs);
}

static void test_parser_precedence_layer_mask_ok(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* PRECEDENCE layer mask RW, rule grants RW - should succeed */
    const char *text = "@0 PRECEDENCE:RW\n/data/** -> RW\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, NULL, NULL), 0,
                   "PRECEDENCE rule within layer mask accepted");

    soft_ruleset_free(rs);
}

static void test_parser_subject_hash_roundtrip(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Subject regex with # character */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
        SOFT_OP_READ, NULL, ".*admin#1$", 1000, 0);

    char *out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "serialize subject with hash");

    /* Verify the serialized output contains quotes */
    int has_quote = 0;
    for (const char *p = out_text; *p; p++) {
        if (*p == '"') { has_quote = 1; break; }
    }
    TEST_ASSERT(has_quote, "output contains quotes for subject with hash");

    /* Parse back and verify round-trip */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, NULL, NULL), 0,
                   "parse serialized subject with hash");

    /* Verify behavior matches */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/admin#1", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx, NULL),
                   "subject with hash round-trip produces same result");

    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  Cross-layer mask handling                                         */
/* ------------------------------------------------------------------ */

static void test_parser_explicit_layer_ignores_current_mask(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Current layer (implicit 0) has mask R, but explicit @1 rule grants RW
     * Layer 1 has no mask, so RW should be accepted */
    const char *text = "@0 PRECEDENCE:R\n@1 SPECIFICITY\n/data/** -> RW\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "explicit layer 1 rule ignores layer 0 mask");

    soft_ruleset_free(rs);
}

static void test_parser_explicit_layer_respects_own_mask(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Explicit @1 rule with mask R, but grants RW -> should fail */
    const char *text = "@1 SPECIFICITY:R\n@1 /data/** -> RW\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), -1,
                   "explicit layer 1 rule respects layer 1 mask");
    TEST_ASSERT(line == 2, "error on line 2");

    soft_ruleset_free(rs);
}

static void test_parser_macro_id_with_underscore(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Macro ID starting with underscore is valid */
    const char *text = "[_BIN] /usr/bin/**\n((_BIN)) -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "macro ID starting with underscore accepted");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/usr/bin/gcc", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "underscore macro works");

    soft_ruleset_free(rs);
}

static void test_parser_macro_id_with_digits_after_start(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Macro ID with digits after first char is valid */
    const char *text = "[BIN1] /usr/bin/**\n((BIN1)) -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "macro ID with digits after start accepted");

    soft_ruleset_free(rs);
}

static void test_parser_comment_after_rule(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Comment after a rule on same line */
    const char *text = "/data/** -> R # this is a comment\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "comment after rule accepted");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, NULL, 1000}, NULL),
                   SOFT_ACCESS_READ, "rule with trailing comment works");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Circular macro detection                                            */
/* ------------------------------------------------------------------ */

static void test_parser_circular_macro_reference(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Circular macro references: A -> B -> A */
    const char *text = "[A] ((B))\n[B] ((A))\n((A)) -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), -1,
                   "circular macro reference detected");
    TEST_ASSERT(line == 3, "error on line 3");
    TEST_ASSERT(err != NULL, "error message set");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Operation type validation                                           */
/* ------------------------------------------------------------------ */

static void test_parser_unknown_operation_type(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Unknown operation type should be rejected */
    const char *text = "/data/** -> R /readextra\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), -1,
                   "unknown operation type rejected");
    TEST_ASSERT(line == 1, "error on line 1");

    soft_ruleset_free(rs);
}

static void test_parser_all_valid_operation_types(void)
{
    const char *ops[] = {"read", "write", "exec", "copy", "move", "link", "mount", "chmod", "custom", NULL};

    for (int i = 0; ops[i]; i++) {
        soft_ruleset_t *rs = soft_ruleset_new();
        char text[64];
        snprintf(text, sizeof(text), "/data/** -> R /%s\n", ops[i]);

        TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, NULL, NULL), 0,
                       "valid operation type");

        soft_ruleset_free(rs);
    }
}

/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Layer mask validation                                               */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */

static void test_parser_layer_mask_violation(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Layer mask R, but rule grants RW - should fail */
    const char *text = "@1 SPECIFICITY:R\n/data/** -> RW\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), -1,
                   "rule exceeding layer mask rejected");
    TEST_ASSERT(line == 2, "error on line 2");
    TEST_ASSERT(err != NULL, "error message set");

    soft_ruleset_free(rs);
}

static void test_parser_layer_mask_ok(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Layer mask R, rule grants R → should succeed */
    const char *text = "@1 SPECIFICITY:R\n/data/** -> R\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, NULL, NULL), 0,
                   "rule within layer mask accepted");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Escaping edge cases                                                 */
/* ------------------------------------------------------------------ */

static void test_parser_subject_with_quotes(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Subject regex with quotes */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
        SOFT_OP_READ, NULL, ".*\\\"admin\\\"$", 1000, 0);

    char *out_text = NULL;
    TEST_ASSERT_EQ(soft_ruleset_write_text(rs, &out_text), 0, "serialize subject with quotes");

    /* Parse back and verify round-trip */
    soft_ruleset_t *rs2 = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs2, out_text, NULL, NULL), 0,
                   "parse serialized subject with quotes");

    /* Verify behavior matches */
    soft_access_ctx_t ctx = {SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/\\\"admin\\\"", 1000};
    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs, &ctx, NULL),
                   soft_ruleset_check_ctx(rs2, &ctx, NULL),
                   "subject with quotes round-trip produces same result");

    free(out_text);
    soft_ruleset_free(rs);
    soft_ruleset_free(rs2);
}

/* ------------------------------------------------------------------ */
/*  Whitespace and formatting                                           */
/* ------------------------------------------------------------------ */

static void test_parser_extra_whitespace(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    /* Extra whitespace between tokens */
    const char *text = "/data/**   ->   R   /read   subject:.*cp$   uid:1000   recursive\n";
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, &line, &err), 0,
                   "extra whitespace between tokens");

    TEST_ASSERT_EQ(soft_ruleset_check_ctx(rs,
                   &(soft_access_ctx_t){SOFT_OP_READ, "/data/file.txt", NULL, "/usr/bin/cp", 1000}, NULL),
                   SOFT_ACCESS_READ, "rule with extra whitespace works");

    soft_ruleset_free(rs);
}

static void test_parser_empty_macro_id(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    int line = 0;
    const char *err = NULL;

    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, "[] /data/**\n", &line, &err), -1,
                   "empty macro ID rejected");
    TEST_ASSERT(line == 1, "error on line 1");

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */

void test_rule_engine_parser_run(void)
{
    printf("=== Policy Parser Tests ===\n");
    RUN_TEST(test_parser_basic_rule);
    RUN_TEST(test_parser_comments_and_blanks);
    RUN_TEST(test_parser_layer_decl);
    RUN_TEST(test_parser_layer_mask);
    RUN_TEST(test_parser_implicit_layer);
    RUN_TEST(test_parser_macro_def);
    RUN_TEST(test_parser_macro_undefined);
    RUN_TEST(test_parser_subject_and_uid);
    RUN_TEST(test_parser_missing_arrow);
    RUN_TEST(test_parser_invalid_mode);
    RUN_TEST(test_parser_invalid_layer_type);
    RUN_TEST(test_serializer_basic);
    RUN_TEST(test_serializer_layered);
    RUN_TEST(test_serializer_subject_and_uid);
    RUN_TEST(test_parser_file_io);
    RUN_TEST(test_parser_quoted_subject);
    RUN_TEST(test_parser_empty_input);
    RUN_TEST(test_parser_macro_nested);
    RUN_TEST(test_parser_macro_multiple_uses);
    RUN_TEST(test_parser_all_modes);
    RUN_TEST(test_parser_deny_mode);
    RUN_TEST(test_parser_lowercase_modes);
    RUN_TEST(test_parser_all_operations);
    RUN_TEST(test_parser_layer_boundaries);
    RUN_TEST(test_parser_empty_macro_id);
    RUN_TEST(test_parser_macro_id_start_digit);
    RUN_TEST(test_parser_unmatched_macro_ref);
    RUN_TEST(test_parser_invalid_layer_index);
    RUN_TEST(test_parser_subject_backslash);
    RUN_TEST(test_parser_layer_mask_violation);
    RUN_TEST(test_parser_layer_mask_ok);
    RUN_TEST(test_parser_subject_with_quotes);
    RUN_TEST(test_parser_extra_whitespace);
        RUN_TEST(test_parser_recursive_prefix);
        RUN_TEST(test_parser_precedence_layer_mask_violation);
        RUN_TEST(test_parser_precedence_layer_mask_ok);
        RUN_TEST(test_parser_subject_hash_roundtrip);
        RUN_TEST(test_parser_explicit_layer_ignores_current_mask);
        RUN_TEST(test_parser_explicit_layer_respects_own_mask);
        RUN_TEST(test_parser_macro_id_with_underscore);
        RUN_TEST(test_parser_macro_id_with_digits_after_start);
        RUN_TEST(test_parser_comment_after_rule);
        RUN_TEST(test_parser_circular_macro_reference);
        RUN_TEST(test_parser_unknown_operation_type);
        RUN_TEST(test_parser_all_valid_operation_types);
    RUN_TEST(test_serializer_roundtrip_full);
}
