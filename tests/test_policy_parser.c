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
}
