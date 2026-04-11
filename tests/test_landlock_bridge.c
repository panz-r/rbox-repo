/**
 * @file test_landlock_bridge.c
 * @brief Tests for the Landlock translation bridge.
 *
 * Tests cover:
 *   - Access flag mapping (SOFT_ACCESS_* → LL_FS_*)
 *   - Landlock compatibility validation
 *   - Translation of compatible rulesets
 *   - Rejection of incompatible rulesets
 *   - Pattern classification and prefix extraction
 *   - Binary search optimization on compiled static rules
 */

#include "test_framework.h"
#include "policy_parser.h"
#include "landlock_bridge.h"
#include "landlock_builder.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Flag mapping                                                        */
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
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_DENY),
                   0,
                   "map: DENY → 0");

    /* Case 6: Full access */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC),
                   LL_FS_READ_FILE | LL_FS_READ_DIR | LL_FS_WRITE_FILE | LL_FS_EXECUTE,
                   "map: RWX → full file access");

    /* Case 7: Empty mask */
    TEST_ASSERT_EQ(soft_access_to_ll_fs(0), 0, "map: empty → 0");
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
}

/* ------------------------------------------------------------------ */
/*  Landlock compatibility validation                                  */
/* ------------------------------------------------------------------ */

static void test_bridge_validation(void)
{
    soft_ruleset_t *rs;
    const char *err = NULL;
    int line = 0;

    /* Case 1: Compatible ruleset (no constraints, no templates) */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/usr/**", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC,
                          SOFT_OP_EXEC, NULL, NULL, 0, 0);
    soft_ruleset_add_rule(rs, "/data/...", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, SOFT_RULE_RECURSIVE);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &err, &line), 0,
                   "validate: compatible ruleset accepted");
    soft_ruleset_free(rs);

    /* Case 2: Subject constraint rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, ".*admin$", 1000, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &err, &line), -1,
                   "validate: subject constraint rejected");
    soft_ruleset_free(rs);

    /* Case 3: UID constraint rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/data/**", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 500, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &err, &line), -1,
                   "validate: UID constraint rejected");
    soft_ruleset_free(rs);

    /* Case 4: Template rule (${SRC}) rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "${SRC}", SOFT_ACCESS_READ,
                          SOFT_OP_COPY, "SRC", NULL, 0, SOFT_RULE_TEMPLATE);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &err, &line), -1,
                   "validate: template rule rejected");
    soft_ruleset_free(rs);

    /* Case 5: Mid-path wildcard rejected */
    rs = soft_ruleset_new();
    soft_ruleset_add_rule(rs, "/etc/*/passwd", SOFT_ACCESS_READ,
                          SOFT_OP_READ, NULL, NULL, 0, 0);
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &err, &line), -1,
                   "validate: mid-path wildcard rejected");

    /* Case 6: Empty ruleset accepted */
    rs = soft_ruleset_new();
    soft_ruleset_compile(rs);
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &err, &line), 0,
                   "validate: empty ruleset accepted");
    soft_ruleset_free(rs);

    /* Case 7: NULL ruleset rejected */
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(NULL, &err, &line), -1,
                   "validate: NULL ruleset rejected");
}

/* ------------------------------------------------------------------ */
/*  Translation to Landlock                                            */
/* ------------------------------------------------------------------ */

static void test_bridge_translation(void)
{
    soft_ruleset_t *rs;
    landlock_builder_t *b;
    const char **deny_prefixes = NULL;
    size_t rule_count = 0;

    /* Case 1: Basic translation */
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
        }
        landlock_builder_free(b);
    }
    soft_landlock_deny_prefixes_free(deny_prefixes);
    soft_ruleset_free(rs);

    /* Case 2: Translation with deny rules */
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

    /* Case 3: Empty ruleset */
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

    /* Case 4: NULL ruleset */
    b = soft_ruleset_to_landlock(NULL, NULL);
    TEST_ASSERT(b == NULL, "translate: NULL ruleset rejected");
}

/* ------------------------------------------------------------------ */
/*  Roundtrip: parse → compile → translate → Landlock prepare         */
/* ------------------------------------------------------------------ */

static void test_bridge_roundtrip(void)
{
    soft_ruleset_t *rs;
    const char *text =
        "@0 PRECEDENCE\n"
        "/usr/** -> RW /exec\n"
        "/data/... -> R recursive\n";

    rs = soft_ruleset_new();
    TEST_ASSERT_EQ(soft_ruleset_parse_text(rs, text, NULL, NULL), 0,
                   "roundtrip: parse policy text");
    soft_ruleset_compile(rs);

    /* Validate */
    const char *err = NULL;
    int line = 0;
    TEST_ASSERT_EQ(soft_ruleset_validate_for_landlock(rs, &err, &line), 0,
                   "roundtrip: validated for Landlock");

    /* Translate */
    landlock_builder_t *b = soft_ruleset_to_landlock(rs, NULL);
    TEST_ASSERT(b != NULL, "roundtrip: translated to Landlock builder");
    if (b) {
        /* Prepare for ABI v4 */
        TEST_ASSERT_EQ(landlock_builder_prepare(b, LANDLOCK_ABI_V4, false), 0,
                       "roundtrip: Landlock prepare succeeded");
        size_t tmp_count = 0;
        landlock_builder_get_rules(b, &tmp_count);
        TEST_ASSERT(tmp_count >= 1, "roundtrip: at least one Landlock rule");
        landlock_builder_free(b);
    }
    soft_ruleset_free(rs);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                              */
/* ------------------------------------------------------------------ */

void test_landlock_bridge_run(void)
{
    printf("=== Landlock Bridge Tests ===\n");
    RUN_TEST(test_bridge_flag_mapping);
    RUN_TEST(test_bridge_pattern_classify);
    RUN_TEST(test_bridge_validation);
    RUN_TEST(test_bridge_translation);
    RUN_TEST(test_bridge_roundtrip);
}
