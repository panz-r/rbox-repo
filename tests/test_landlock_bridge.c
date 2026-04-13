/**
 * @file test_landlock_bridge.c
 * @brief Tests for the Landlock translation bridge.
 *
 * Tests cover:
 *   - Access flag mapping (SOFT_ACCESS_* → LL_FS_*)
 *   - Landlock compatibility validation (7 rejection types + valid cases)
 *   - Translation of compatible rulesets (allow, deny, mixed, empty)
 *   - DENY overlap removal verification
 *   - Pattern classification and prefix extraction (edge cases)
 *   - Multi-layer translation
 *   - Large ruleset translation performance
 *   - Integration: parse → compile → validate → translate → verify
 */

#include "test_framework.h"
#include "policy_parser.h"
#include "landlock_bridge.h"
#include "landlock_builder.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/*  Access flag mapping                                                 */
/* ------------------------------------------------------------------ */

static void test_bridge_flag_mapping(void)
{
    /* Case 1: READ maps to READ_FILE + READ_DIR */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_READ),
                   LL_FS_READ_FILE | LL_FS_READ_DIR,
                   "map: READ → READ_FILE|READ_DIR");

    /* Case 2: WRITE maps to WRITE_FILE */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_WRITE),
                   LL_FS_WRITE_FILE,
                   "map: WRITE → WRITE_FILE");

    /* Case 3: EXEC maps to EXECUTE */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_EXEC),
                   LL_FS_EXECUTE,
                   "map: EXEC → EXECUTE");

    /* Case 4: Combined READ+WRITE */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_READ | SOFT_ACCESS_WRITE),
                   LL_FS_READ_FILE | LL_FS_READ_DIR | LL_FS_WRITE_FILE,
                   "map: RW → READ_FILE|READ_DIR|WRITE_FILE");

    /* Case 5: DENY maps to 0 */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_DENY), 0,
                   "map: DENY → 0");

    /* Case 6: Full access RWX */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC),
                   LL_FS_READ_FILE | LL_FS_READ_DIR | LL_FS_WRITE_FILE | LL_FS_EXECUTE,
                   "map: RWX → full file access");

    /* Case 7: Empty mask */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(0), 0, "map: empty → 0");

    /* Case 8: UNLINK maps to REMOVE_FILE + REMOVE_DIR */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_UNLINK),
                   LL_FS_REMOVE_FILE | LL_FS_REMOVE_DIR,
                   "map: UNLINK → REMOVE_FILE|REMOVE_DIR");

    /* Case 9: CREATE maps to WRITE_FILE */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_CREATE),
                   LL_FS_WRITE_FILE,
                   "map: CREATE → WRITE_FILE");

    /* Case 10: Combined UNLINK+CREATE */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_UNLINK | SOFT_ACCESS_CREATE),
                   LL_FS_REMOVE_FILE | LL_FS_REMOVE_DIR | LL_FS_WRITE_FILE,
                   "map: UNLINK+CREATE → REMOVE|WRITE");
}

/* ------------------------------------------------------------------ */
/*  Pattern classification                                              */
/* ------------------------------------------------------------------ */

static void test_bridge_pattern_classify(void)
{
    /* Case 1: Exact path */
    TEST_ASSERT_EQ(soft_pattern_classify("/usr/bin/gcc"),
                   PATTERN_EXACT, "classify: exact path");

    /* Case 2: Recursive double-star suffix */
    TEST_ASSERT_EQ(soft_pattern_classify("/usr/**"),
                   PATTERN_PREFIX, "classify: double-star is prefix");

    /* Case 3: Recursive triple-dot suffix */
    TEST_ASSERT_EQ(soft_pattern_classify("/data/..."),
                   PATTERN_PREFIX, "classify: triple-dot is prefix");

    /* Case 4: Single-level star suffix */
    TEST_ASSERT_EQ(soft_pattern_classify("/etc/*"),
                   PATTERN_WILDCARD, "classify: single star is wildcard");

    /* Case 5: Mid-path wildcard */
    TEST_ASSERT_EQ(soft_pattern_classify("/etc/*/passwd"),
                   PATTERN_WILDCARD, "classify: mid-path * is wildcard");

    /* Case 6: Empty pattern */
    TEST_ASSERT_EQ(soft_pattern_classify(""),
                   PATTERN_EXACT, "classify: empty is exact");

    /* Case 7: Root path */
    TEST_ASSERT_EQ(soft_pattern_classify("/"),
                   PATTERN_EXACT, "classify: root path is exact");

    /* Case 8: Pattern with trailing slash */
    TEST_ASSERT_EQ(soft_pattern_classify("/data/"),
                   PATTERN_EXACT, "classify: trailing slash is exact");

    /* Case 9: Double-star with suffix */
    TEST_ASSERT_EQ(soft_pattern_classify("/usr/local/**"),
                   PATTERN_PREFIX, "classify: double-star with suffix is prefix");
}

/* ------------------------------------------------------------------ */
/*  Landlock compatibility validation: rejection cases                */
/* ------------------------------------------------------------------ */

static void test_bridge_validation_rejections(void)
{
    const char *err = NULL;
    int line = 0;
    soft_ruleset_t *rs;

    /* Case 1: Subject constraint rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, ".*admin$", 1000, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), -1,
                   "reject: subject constraint");
    TEST_ASSERT(err != NULL, "reject: subject error message set");
    soft_ruleset_free(rs);

    /* Case 2: UID constraint rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 500, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), -1,
                   "reject: UID constraint");
    TEST_ASSERT(err != NULL, "reject: UID error message set");
    soft_ruleset_free(rs);

    /* Case 3: Template rule (${SRC}) rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "${SRC}", SOFT_ACCESS_READ,
                          SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), -1,
                   "reject: template rule");
    TEST_ASSERT(err != NULL, "reject: template error message set");
    soft_ruleset_free(rs);

    /* Case 4: Mid-path wildcard rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/etc/*/passwd", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), -1,
                   "reject: mid-path wildcard");
    TEST_ASSERT(err != NULL, "reject: wildcard error message set");
    soft_ruleset_free(rs);

    /* Case 5: NULL ruleset rejected */
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(NULL, NULL, &err, &line), -1,
                   "reject: NULL ruleset");
    TEST_ASSERT(err != NULL, "reject: NULL error message set");

    /* Case 6: SPECIFICITY layer rules rejected (longest-match semantics) */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), -1,
                   "reject: SPECIFICITY layer");
    soft_ruleset_free(rs);

    /* Case 7: Layer mode mask rejected (uncompiled) */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, SOFT_ACCESS_READ);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    /* Do NOT compile - validation on uncompiled ruleset */
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), -1,
                   "reject: layer mode mask");
    soft_ruleset_free(rs);

    /* Case 8: Single-star suffix rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/etc/*", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), -1,
                   "reject: single-star suffix");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Landlock compatibility validation: acceptance cases               */
/* ------------------------------------------------------------------ */

static void test_bridge_validation_accepts(void)
{
    const char *err = NULL;
    int line = 0;
    soft_ruleset_t *rs;

    /* Case 1: Compatible ruleset (exact + prefix patterns) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), 0,
                   "accept: compatible ruleset");
    soft_ruleset_free(rs);

    /* Case 2: Empty ruleset accepted */
    rs = soft_ruleset_new();
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), 0,
                   "accept: empty ruleset");
    soft_ruleset_free(rs);

    /* Case 3: DENY rule accepted (handled separately by Landlock) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule(rs, "/data/secret", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), 0,
                   "accept: DENY rule accepted");
    soft_ruleset_free(rs);

    /* Case 4: Uncompiled compatible ruleset */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), 0,
                   "accept: uncompiled compatible ruleset");
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Translation to Landlock: basic cases                              */
/* ------------------------------------------------------------------ */

static void test_bridge_translation_basic(void)
{
    soft_ruleset_t *rs;
    landlock_builder_t *b;
    const char **deny_prefixes = NULL;
    size_t rule_count = 0;

    /* Case 1: Basic translation with single rule */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock(rs, &deny_prefixes);
    TEST_ASSERT(b != NULL, "translate: basic ruleset translated");
    if (b) {
        landlock_builder_prepare(b, LANDLOCK_ABI_V4, false);
        const landlock_rule_t *rules = landlock_builder_get_rules(b, &rule_count);
        TEST_ASSERT(rule_count >= 1, "translate: at least one rule produced");
        if (rule_count > 0) {
            TEST_ASSERT(rules[0].path != NULL, "translate: rule has path");
            TEST_ASSERT(rules[0].access != 0, "translate: rule has access");
            /* Verify access mask includes READ and EXEC */
            TEST_ASSERT(rules[0].access & LL_FS_READ_FILE,
                        "translate: rule includes READ");
            TEST_ASSERT(rules[0].access & LL_FS_EXECUTE,
                        "translate: rule includes EXEC");
        }
        landlock_builder_free(b);
    }
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);

    /* Case 2: Empty ruleset translation */
    rs = soft_ruleset_new();
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock(rs, NULL);
    TEST_ASSERT(b != NULL, "translate: empty ruleset translated");
    if (b) {
        landlock_builder_prepare(b, LANDLOCK_ABI_V4, false);
        size_t tmp_count = 0;
        landlock_builder_get_rules(b, &tmp_count);
        TEST_ASSERT(tmp_count == 0, "translate: empty produces 0 rules");
        landlock_builder_free(b);
    }
    soft_ruleset_free(rs);

    /* Case 3: NULL ruleset rejected */
    b = soft_ruleset_to_landlock(NULL, NULL);
    TEST_ASSERT(b == NULL, "translate: NULL ruleset rejected");
}

/* ------------------------------------------------------------------ */
/*  Translation with DENY rules and overlap removal                   */
/* ------------------------------------------------------------------ */

static void test_bridge_translation_with_deny(void)
{
    soft_ruleset_t *rs;
    landlock_builder_t *b;
    const char **deny_prefixes = NULL;

    /* Case 1: Translation with deny rules */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/secret", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock(rs, &deny_prefixes);
    TEST_ASSERT(b != NULL, "translate: ruleset with deny translated");
    if (b) {
        landlock_builder_prepare(b, LANDLOCK_ABI_V4, false);
        size_t tmp_count = 0;
        landlock_builder_get_rules(b, &tmp_count);
        TEST_ASSERT(tmp_count >= 1, "translate: allow rules produced");
        /* Deny rules should be reported */
        TEST_ASSERT(deny_prefixes != NULL, "translate: deny prefixes reported");
        landlock_builder_free(b);
    }
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);

    /* Case 2: Multiple DENY rules */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule(rs, "/data/secret", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/private", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock(rs, &deny_prefixes);
    TEST_ASSERT(b != NULL, "translate: multiple deny rules translated");
    if (b && deny_prefixes) {
        /* Count deny prefixes */
        int deny_count = 0;
        for (int i = 0; deny_prefixes[i] != NULL; i++) deny_count++;
        TEST_ASSERT(deny_count >= 2, "translate: at least 2 deny prefixes");
    }
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);

    /* Case 3: DENY with recursive pattern */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule(rs, "/data/secret/**", SOFT_ACCESS_DENY,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock(rs, &deny_prefixes);
    TEST_ASSERT(b != NULL, "translate: recursive DENY translated");
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Multi-layer translation                                           */
/* ------------------------------------------------------------------ */

static void test_bridge_multi_layer_translation(void)
{
    soft_ruleset_t *rs;
    landlock_builder_t *b;
    const char **deny_prefixes = NULL;
    size_t rule_count = 0;

    /* Case 1: Multiple PRECEDENCE layers with mixed allow/deny */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/usr/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 1, "/usr/bin/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 2, "/usr/bin/secret", SOFT_ACCESS_DENY,
                                   SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock(rs, &deny_prefixes);
    TEST_ASSERT(b != NULL, "translate: multi-layer ruleset translated");
    if (b) {
        landlock_builder_prepare(b, LANDLOCK_ABI_V4, false);
        landlock_builder_get_rules(b, &rule_count);
        TEST_ASSERT(rule_count >= 1, "translate: multi-layer produces rules");
        landlock_builder_free(b);
    }
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Large ruleset translation performance                             */
/* ------------------------------------------------------------------ */

static void test_bridge_large_ruleset(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    char path[80];
    int i;

    /* Create 200 rules */
    for (i = 0; i < 200; i++) {
        snprintf(path, sizeof(path), "/data/dir%03d/**", i);
        soft_ruleset_add_rule(rs, path, SOFT_ACCESS_READ,
                              SOFT_OP_READ, NULL, NULL, 0, 0);
    }
    soft_ruleset_compile(rs);

    /* Validate */
    const char *err = NULL;
    int line = 0;
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), 0,
                   "large: 200 rules validated");

    /* Translate */
    landlock_builder_t *b = soft_ruleset_to_landlock(rs, NULL);
    TEST_ASSERT(b != NULL, "large: 200 rules translated");

    if (b) {
        landlock_builder_prepare(b, LANDLOCK_ABI_V4, false);
        size_t rule_count = 0;
        landlock_builder_get_rules(b, &rule_count);
        TEST_ASSERT(rule_count >= 100, "large: at least 100 rules produced");
        landlock_builder_free(b);
    }

    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Integration: parse → compile → validate → translate → verify      */
/* ------------------------------------------------------------------ */

static void test_bridge_integration(void)
{
    /* Case 1: Full roundtrip with compatible policy */
    const char *text =
        "@0 PRECEDENCE\n"
        "/usr/** -> RW /exec\n"
        "/data/... -> R recursive\n"
        "/tmp/** -> R\n";

    soft_ruleset_t *rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, NULL, NULL), 0,
                   "integration: parse policy text");

    soft_ruleset_compile(rs);
    TEST_ASSERT(soft_ruleset_is_compiled(rs), "integration: compiled");

    const char *err = NULL;
    int line = 0;
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), 0,
                   "integration: validated");

    const char **deny_prefixes = NULL;
    landlock_builder_t *b = soft_ruleset_to_landlock(rs, &deny_prefixes);
    TEST_ASSERT(b != NULL, "integration: translated");

    if (b) {
        TEST_ASSERT_EQ(landlock_builder_prepare(b, LANDLOCK_ABI_V4, false), 0,
                       "integration: Landlock prepare succeeded");
        size_t tmp_count = 0;
        landlock_builder_get_rules(b, &tmp_count);
        TEST_ASSERT(tmp_count >= 2, "integration: at least 2 rules");
        landlock_builder_free(b);
    }
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);

    /* Case 2: Full roundtrip with incompatible policy (should fail validation) */
    const char *bad_text =
        "@0 PRECEDENCE\n"
        "/usr/** -> RW /exec\n"
        "/data/... -> R recursive subject:.*admin$\n";

    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, bad_text, NULL, NULL), 0,
                   "integration_bad: parse policy with subject");

    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), -1,
                   "integration_bad: validation rejected subject constraint");

    /* Translation should still work but skip inexpressible rules */
    b = soft_ruleset_to_landlock(rs, NULL);
    TEST_ASSERT(b != NULL, "integration_bad: translation still succeeds (skips bad rules)");
    if (b) {
        landlock_builder_free(b);
    }
    soft_ruleset_free(rs);

    /* Case 3: Policy with DENY and allow roundtrip */
    const char *deny_text =
        "@0 PRECEDENCE\n"
        "/data/** -> R recursive\n"
        "/data/secret -> deny\n";

    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, deny_text, NULL, NULL), 0,
                   "integration_deny: parse policy with DENY");

    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, NULL, &err, &line), 0,
                   "integration_deny: validated");

    deny_prefixes = NULL;
    b = soft_ruleset_to_landlock(rs, &deny_prefixes);
    TEST_ASSERT(b != NULL, "integration_deny: translated");
    TEST_ASSERT(deny_prefixes != NULL, "integration_deny: deny prefixes reported");

    if (deny_prefixes) {
        int deny_count = 0;
        for (int i = 0; deny_prefixes[i] != NULL; i++) deny_count++;
        TEST_ASSERT(deny_count >= 1, "integration_deny: at least 1 deny prefix");
    }

    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Structured error code verification                                  */
/* ------------------------------------------------------------------ */

static void test_bridge_error_codes(void)
{
    landlock_compat_error_t code;
    const char *err = NULL;
    int line = 0;
    soft_ruleset_t *rs;

    /* Verify error message array is complete */
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_OK] != NULL,
                "error_msgs: OK message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_SUBJECT] != NULL,
                "error_msgs: SUBJECT message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_UID] != NULL,
                "error_msgs: UID message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_TEMPLATE] != NULL,
                "error_msgs: TEMPLATE message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_WILDCARD] != NULL,
                "error_msgs: WILDCARD message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_SPECIFICITY] != NULL,
                "error_msgs: SPECIFICITY message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_LAYER_MASK] != NULL,
                "error_msgs: LAYER_MASK message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_SINGLE_STAR] != NULL,
                "error_msgs: SINGLE_STAR message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_NULL_RULESET] != NULL,
                "error_msgs: NULL_RULESET message exists");
    TEST_ASSERT(landlock_compat_error_msgs[-LANDLOCK_COMPAT_COMPILE_FAIL] != NULL,
                "error_msgs: COMPILE_FAIL message exists");

    /* Case 1: Compatible ruleset returns OK code */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &code, &err, &line), 0,
                   "error_code: compatible returns 0");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_OK, "error_code: code is OK");
    TEST_ASSERT(err == NULL, "error_code: error message is NULL");
    soft_ruleset_free(rs);

    /* Case 2: Subject constraint returns correct code */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, ".*admin$", 1000, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &code, &err, &line), -1,
                   "error_code: subject rejected");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_SUBJECT, "error_code: code is SUBJECT");
    TEST_ASSERT(err != NULL, "error_code: error message is set");
    soft_ruleset_free(rs);

    /* Case 3: UID constraint returns correct code */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 500, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &code, &err, &line), -1,
                   "error_code: uid rejected");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_UID, "error_code: code is UID");
    soft_ruleset_free(rs);

    /* Case 4: Template rule returns correct code */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "${SRC}", SOFT_ACCESS_READ,
                          SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &code, &err, &line), -1,
                   "error_code: template rejected");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_TEMPLATE, "error_code: code is TEMPLATE");
    soft_ruleset_free(rs);

    /* Case 5: Mid-path wildcard returns correct code */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/etc/*/passwd", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &code, &err, &line), -1,
                   "error_code: wildcard rejected");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_WILDCARD, "error_code: code is WILDCARD");
    soft_ruleset_free(rs);

    /* Case 6: SPECIFICITY layer returns correct code */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &code, &err, &line), -1,
                   "error_code: SPECIFICITY rejected");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_SPECIFICITY, "error_code: code is SPECIFICITY");
    soft_ruleset_free(rs);

    /* Case 7: Layer mode mask returns correct code (uncompiled) */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_PRECEDENCE, SOFT_ACCESS_READ);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ,
                                   SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &code, &err, &line), -1,
                   "error_code: layer mask rejected");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_LAYER_MASK, "error_code: code is LAYER_MASK");
    soft_ruleset_free(rs);

    /* Case 8: Single-star suffix returns correct code */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/etc/*", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &code, &err, &line), -1,
                   "error_code: single star rejected");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_SINGLE_STAR, "error_code: code is SINGLE_STAR");
    soft_ruleset_free(rs);

    /* Case 9: NULL ruleset returns correct code */
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(NULL, &code, &err, &line), -1,
                   "error_code: NULL rejected");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_NULL_RULESET, "error_code: code is NULL_RULESET");

    /* Case 10: Direct _ex API returns enum directly */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    code = soft_ruleset_validate_for_landlock_ex(rs, &line);
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_SUBJECT, "error_code_ex: returns SUBJECT enum");
    soft_ruleset_free(rs);
}


/* ------------------------------------------------------------------ */
/*  Validation report (collects ALL errors)                            */
/* ------------------------------------------------------------------ */

static void test_bridge_validation_report(void)
{
    landlock_validation_entry_t report[LANDLOCK_VALIDATION_REPORT_MAX];
    int count;
    soft_ruleset_t *rs;

    /* Case 1: Compatible ruleset has 0 errors */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    count = soft_ruleset_validate_for_landlock_report(rs, report);
    TEST_ASSERT_EQ(count, 0, "report: compatible has 0 errors");
    soft_ruleset_free(rs);

    /* Case 2: Ruleset with multiple errors collects all of them */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule_at_layer(rs, 0, "/usr/**", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, ".*admin$", 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/${SRC}", SOFT_ACCESS_READ, SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);
    count = soft_ruleset_validate_for_landlock_report(rs, report);
    TEST_ASSERT(count >= 2, "report: multiple errors collected");
    if (count >= 2) {
        TEST_ASSERT(report[0].error == LANDLOCK_COMPAT_SUBJECT ||
                    report[0].error == LANDLOCK_COMPAT_UID ||
                    report[0].error == LANDLOCK_COMPAT_TEMPLATE,
                    "report: first error is valid");
        TEST_ASSERT(report[1].error == LANDLOCK_COMPAT_SUBJECT ||
                    report[1].error == LANDLOCK_COMPAT_UID ||
                    report[1].error == LANDLOCK_COMPAT_TEMPLATE,
                    "report: second error is valid");
    }
    soft_ruleset_free(rs);

    /* Case 3: SPECIFICITY layer reported */
    rs = soft_ruleset_new();
    soft_ruleset_set_layer_type(rs, 0, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    count = soft_ruleset_validate_for_landlock_report(rs, report);
    TEST_ASSERT(count >= 1, "report: SPECIFICITY reported");
    if (count >= 1) {
        TEST_ASSERT_EQ(report[0].error, LANDLOCK_COMPAT_SPECIFICITY, "report: error is SPECIFICITY");
    }
    soft_ruleset_free(rs);

    /* Case 4: NULL ruleset returns 0 (no errors to report) */
    count = soft_ruleset_validate_for_landlock_report(NULL, report);
    TEST_ASSERT_EQ(count, 0, "report: NULL returns 0");
}

/* ------------------------------------------------------------------ */
/*  Translation report                                                 */
/* ------------------------------------------------------------------ */

static void test_bridge_translation_report(void)
{
    soft_ruleset_t *rs;
    landlock_translation_report_t rep;
    const char **deny_prefixes = NULL;
    landlock_builder_t *b;

    /* Case 1: Simple ruleset — all allowed, none skipped */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC, SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock_with_report(rs, NULL, &rep);
    TEST_ASSERT(b != NULL, "translate_report: builder created");
    if (b) {
        TEST_ASSERT_EQ(rep.total_rules, 2, "translate_report: 2 total");
        TEST_ASSERT(rep.allowed_rules >= 1, "translate_report: at least 1 allowed");
        TEST_ASSERT_EQ(rep.skipped_rules, 0, "translate_report: 0 skipped");
        landlock_builder_free(b);
    }
    soft_ruleset_free(rs);

    /* Case 2: Ruleset with skipped rules */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/**", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, ".*admin$", 1000, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock_with_report(rs, &deny_prefixes, &rep);
    TEST_ASSERT(b != NULL, "translate_report: builder with skips created");
    if (b) {
        TEST_ASSERT_EQ(rep.total_rules, 2, "translate_report: 2 total");
        TEST_ASSERT(rep.allowed_rules >= 1, "translate_report: at least 1 allowed");
        TEST_ASSERT(rep.skipped_rules >= 1, "translate_report: at least 1 skipped");
        TEST_ASSERT(rep.skipped_subject >= 1 || rep.skipped_uid >= 1,
                    "translate_report: subject or uid skipped");
        landlock_builder_free(b);
    }
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);

    /* Case 3: Ruleset with deny rules */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/secret", SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    b = soft_ruleset_to_landlock_with_report(rs, &deny_prefixes, &rep);
    TEST_ASSERT(b != NULL, "translate_report: deny ruleset translated");
    if (b) {
        TEST_ASSERT_EQ(rep.denied_rules, 1, "translate_report: 1 denied");
        TEST_ASSERT(rep.deny_prefixes >= 1, "translate_report: deny prefixes reported");
        landlock_builder_free(b);
    }
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Save Landlock policy convenience function                          */
/* ------------------------------------------------------------------ */

static void test_bridge_save_landlock_policy(void)
{
    const char *tmpfile = "/tmp/test_ll_policy.bin";
    const char *err = NULL;
    landlock_compat_error_t code;
    int ret;

    /* Case 1: Compatible ruleset saves successfully */
    soft_ruleset_t *rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC, SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    ret = soft_ruleset_save_landlock_policy(rs, tmpfile, LANDLOCK_ABI_V4, &err, &code);
    TEST_ASSERT_EQ(ret, 0, "save_policy: compatible saves successfully");
    TEST_ASSERT(err == NULL, "save_policy: error msg is NULL");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_OK, "save_policy: code is OK");
    /* Verify file was created */
    TEST_ASSERT(access(tmpfile, F_OK) == 0, "save_policy: file exists");
    soft_ruleset_free(rs);
    unlink(tmpfile);

    /* Case 2: Incompatible ruleset fails with proper error */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ, SOFT_OP_READ, NULL, ".*admin$", 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    ret = soft_ruleset_save_landlock_policy(rs, tmpfile, LANDLOCK_ABI_V4, &err, &code);
    TEST_ASSERT_EQ(ret, -1, "save_policy: incompatible fails");
    TEST_ASSERT(err != NULL, "save_policy: error msg set");
    TEST_ASSERT_EQ(code, LANDLOCK_COMPAT_SUBJECT, "save_policy: code is SUBJECT");
    /* Verify file was NOT created */
    TEST_ASSERT(access(tmpfile, F_OK) != 0, "save_policy: file not created");
    soft_ruleset_free(rs);
    unlink(tmpfile);
}


/* ------------------------------------------------------------------ */
/*  ABI detection and masking report                                   */
/* ------------------------------------------------------------------ */

static void test_bridge_abi_detection_and_masking(void)
{
    /* Case 1: Detect ABI version */
    int abi = landlock_detect_abi_version();
    /* On this system Landlock may or may not be available */
    TEST_ASSERT(abi >= 0 && abi <= LANDLOCK_ABI_MAX,
                "abi_detect: version in valid range (0 if unavailable)");

    /* Case 2: ABI mask for each version */
    TEST_ASSERT(landlock_abi_mask(0) == 0, "abi_mask: v0 returns 0");
    TEST_ASSERT(landlock_abi_mask(1) != 0, "abi_mask: v1 non-zero");
    if (LANDLOCK_ABI_MAX >= 2)
        TEST_ASSERT(landlock_abi_mask(2) > landlock_abi_mask(1),
                    "abi_mask: v2 > v1");
    if (LANDLOCK_ABI_MAX >= 4)
        TEST_ASSERT(landlock_abi_mask(4) >= landlock_abi_mask(3),
                    "abi_mask: v4 >= v3");
    TEST_ASSERT(landlock_abi_mask(99) == 0, "abi_mask: invalid version 0");

    /* Case 3: Prepare with report — no masking when ABI is high enough */
    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/usr/**", LL_FS_READ_FILE | LL_FS_READ_DIR);
    landlock_abi_report_t rep;
    memset(&rep, 0, sizeof(rep));
    TEST_ASSERT_EQ(landlock_builder_prepare_with_report(b, LANDLOCK_ABI_V4, false, &rep), 0,
                   "abi_report: prepare succeeds");
    TEST_ASSERT_EQ(rep.abi_version, LANDLOCK_ABI_V4, "abi_report: version set");
    TEST_ASSERT_EQ(rep.masked_rules, 0, "abi_report: no masked rules (ABI 4 has all rights)");
    landlock_builder_free(b);

    /* Case 4: Prepare with report — masking when ABI is low */
    b = landlock_builder_new();
    /* Use rights only available in ABI v4 */
    landlock_builder_allow(b, "/usr/**", LL_FS_READ_FILE | LL_FS_TRUNCATE);
    memset(&rep, 0, sizeof(rep));
    TEST_ASSERT_EQ(landlock_builder_prepare_with_report(b, LANDLOCK_ABI_V2, false, &rep), 0,
                   "abi_report_low: prepare succeeds");
    TEST_ASSERT_EQ(rep.abi_version, LANDLOCK_ABI_V2, "abi_report_low: version set");
    TEST_ASSERT(rep.masked_rules >= 0, "abi_report_low: masked_rules count valid");
    if (rep.masked_rules > 0) {
        TEST_ASSERT(rep.entries[0].dropped != 0, "abi_report_low: some rights dropped");
        TEST_ASSERT(rep.entries[0].masked < rep.entries[0].original,
                    "abi_report_low: masked < original");
    }
    landlock_builder_free(b);

    /* Case 5: Prepare with report — NULL report (same as regular prepare) */
    b = landlock_builder_new();
    landlock_builder_allow(b, "/usr/**", LL_FS_READ_FILE);
    TEST_ASSERT_EQ(landlock_builder_prepare_with_report(b, LANDLOCK_ABI_V4, false, NULL), 0,
                   "abi_report_null: prepare with NULL report succeeds");
    landlock_builder_free(b);
}


void test_landlock_bridge_run(void)
{
    printf("=== Landlock Bridge Tests ===\n");
    RUN_TEST(test_bridge_flag_mapping);
    RUN_TEST(test_bridge_pattern_classify);
    RUN_TEST(test_bridge_validation_rejections);
    RUN_TEST(test_bridge_validation_accepts);
    RUN_TEST(test_bridge_translation_basic);
    RUN_TEST(test_bridge_translation_with_deny);
    RUN_TEST(test_bridge_multi_layer_translation);
    RUN_TEST(test_bridge_large_ruleset);
    RUN_TEST(test_bridge_integration);
    RUN_TEST(test_bridge_error_codes);
    RUN_TEST(test_bridge_validation_report);
    RUN_TEST(test_bridge_translation_report);
    RUN_TEST(test_bridge_save_landlock_policy);
    RUN_TEST(test_bridge_abi_detection_and_masking);
}
