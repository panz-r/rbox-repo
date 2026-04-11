/**
 * @file test_builder.c
 * @brief Unit tests for the public builder API (with mocked filesystem).
 */

#include "test_framework.h"
#include "mock_fs.h"
#include "landlock_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Basic allow / deny / multi / simplification                         */
/* ------------------------------------------------------------------ */

static void test_builder_basic_operations(void)
{
    /* Shared setup: build a single ruleset exercising all basic features */
    mock_fs_reset();
    mock_fs_create_dir("/home");
    mock_fs_create_dir("/home/secret");
    mock_fs_create_dir("/usr");
    mock_fs_create_dir("/usr/lib");
    mock_fs_create_dir("/usr/bin");
    mock_fs_create_dir("/etc");

    landlock_builder_t *b = landlock_builder_new();
    TEST_ASSERT_NOT_NULL(b, "builder creation");

    /* Single-path allow */
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/home", 7), 0, "allow /home");

    /* Allow + deny interaction */
    landlock_builder_deny(b, "/home/secret");

    /* Multiple paths */
    landlock_builder_allow(b, "/usr", 7);
    landlock_builder_allow(b, "/etc", 3);

    /* Simplification: /usr/lib and /usr/bin are subsets of /usr's mask */
    landlock_builder_allow(b, "/usr/lib", 3);
    landlock_builder_allow(b, "/usr/bin", 1);

    /* Verify no rules before prepare */
    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT(!rules || count == 0, "no rules before prepare");

    TEST_ASSERT_EQ(landlock_builder_prepare(b, 2, false), 0, "prepare");

    rules = landlock_builder_get_rules(b, &count);

    /* --- Assertions: different properties of the same result --- */

    /* Combined count check: replaces the scattered count==1 and count==2 assertions
     * from the original separate tests */
    TEST_ASSERT_EQ(count, 3, "three rules: /home, /usr, /etc after simplify and multi-path");

    /* From test_builder_allow_single_path: /home allowed */
    int found_home = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home") == 0) {
            found_home = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "/home access correct");
        }
    }
    TEST_ASSERT(found_home, "/home present after prepare");

    /* From test_builder_allow_and_deny: /home/secret denied */
    int found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home/secret") == 0)
            found_secret = 1;
    }
    TEST_ASSERT(!found_secret, "/home/secret denied and not in output");

    /* From test_builder_multiple_paths: /usr and /etc both present */
    int found_usr = 0, found_etc = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/usr") == 0) {
            found_usr = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "/usr access correct");
        }
        if (strcmp(rules[i].path, "/etc") == 0) {
            found_etc = 1;
            TEST_ASSERT_EQ(rules[i].access, 3, "/etc access correct");
        }
    }
    TEST_ASSERT(found_usr, "found /usr");
    TEST_ASSERT(found_etc, "found /etc");

    /* From test_builder_simplification: subset paths pruned */
    int found_lib = 0, found_bin = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/usr/lib") == 0) found_lib = 1;
        if (strcmp(rules[i].path, "/usr/bin") == 0) found_bin = 1;
    }
    TEST_ASSERT(!found_lib, "/usr/lib pruned (subset of /usr)");
    TEST_ASSERT(!found_bin, "/usr/bin pruned (subset of /usr)");

    /* No unexpected rules — all original tests assumed exact rule sets */
    int found_unexpected = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home") != 0 &&
            strcmp(rules[i].path, "/usr") != 0 &&
            strcmp(rules[i].path, "/etc") != 0) {
            found_unexpected = 1;
        }
    }
    TEST_ASSERT(!found_unexpected, "no unexpected rules in output");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  ABI masking: v1 strips bits, invalid values return 0               */
/* ------------------------------------------------------------------ */

static void test_abi_masking(void)
{
    landlock_builder_t *b;
    size_t count;

    /* Case 1: ABI v1 strips all non-EXECUTE bits */
    mock_fs_reset();
    mock_fs_create_dir("/home");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/home", 0xFF);  /* many rights */
    landlock_builder_prepare(b, 1, false);
    count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "v1: one rule");
    TEST_ASSERT_EQ(rules[0].access, 1, "v1: masked to EXECUTE only");
    landlock_builder_free(b);

    /* Case 2: Invalid ABI versions return 0 */
    TEST_ASSERT_EQ(landlock_abi_mask(0), 0, "v1: abi 0 returns 0");
    TEST_ASSERT_EQ(landlock_abi_mask(5), 0, "v1: abi 5 returns 0");

    /* Case 3: ABI v1 strips WRITE|READ to 0 */
    mock_fs_reset();
    mock_fs_create_dir("/data");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/data", LL_FS_WRITE_FILE | LL_FS_READ_FILE);
    landlock_builder_prepare(b, 1, false);
    count = 0;
    rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "v1_write: rule exists");
    TEST_ASSERT_EQ(rules[0].access, 0, "v1_write: all bits stripped");
    landlock_builder_free(b);

    /* Case 4: ABI v4 masks LL_FS_ALL to defined bits */
    mock_fs_reset();
    mock_fs_create_dir("/data");
    b = landlock_builder_new();
    uint64_t all_bits = LL_FS_ALL;
    landlock_builder_allow(b, "/data", all_bits);
    landlock_builder_prepare(b, 4, false);
    count = 0;
    rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "v4: rule exists");
    uint64_t expected = landlock_abi_mask(4);
    TEST_ASSERT_EQ(rules[0].access, expected, "v4: masks to defined bits");
    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Symlink expansion and loop termination                             */
/* ------------------------------------------------------------------ */

static void test_symlink_handling(void)
{
    landlock_builder_t *b;
    size_t count;

    /* Case 1: Symlink expansion adds target as rule */
    mock_fs_reset();
    mock_fs_create_dir("/var/data");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/link", "/var/data");

    b = landlock_builder_new();
    landlock_builder_allow(b, "/home", 7);
    landlock_builder_allow(b, "/home/user/link", 7);
    landlock_builder_prepare(b, 2, true /* expand symlinks */);

    count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    int found_home = 0, found_var = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home") == 0) {
            found_home = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "expand: /home access correct");
        }
        if (strcmp(rules[i].path, "/var/data") == 0) {
            found_var = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "expand: /var/data access correct");
        }
    }
    TEST_ASSERT(found_home, "expand: /home present after symlink expansion");
    TEST_ASSERT(found_var, "expand: symlink target /var/data added as rule");
    TEST_ASSERT_EQ(count, 2, "expand: exactly 2 rules after symlink expansion");

    landlock_builder_free(b);

    /* Case 2: Symlink loop terminates without corruption */
    mock_fs_reset();
    mock_fs_create_dir("/a");
    mock_fs_create_symlink("/a/link1", "/a/link2");
    mock_fs_create_symlink("/a/link2", "/a/link1");  /* Loop! */

    b = landlock_builder_new();
    landlock_builder_allow(b, "/a", 7);

    int ret = landlock_builder_prepare(b, 2, true);
    TEST_ASSERT_EQ(ret, 0, "loop: prepare with symlink loop succeeds");

    count = 0;
    rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "loop: exactly one rule after loop handling");
    TEST_ASSERT_STR_EQ(rules[0].path, "/a", "loop: /a is the only rule");
    TEST_ASSERT_EQ(rules[0].access, 7, "loop: /a access correct");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Serialisation: basic, multi-rule, append                           */
/* ------------------------------------------------------------------ */

static void test_save_load(void)
{
    landlock_builder_t *b1, *b2;
    size_t count;

    /* Case 1: Single-rule roundtrip */
    mock_fs_reset();
    mock_fs_create_dir("/tmp_test_policy");
    b1 = landlock_builder_new();
    landlock_builder_allow(b1, "/tmp_test_policy", 7);
    landlock_builder_prepare(b1, 2, false);
    TEST_ASSERT_EQ(landlock_builder_save(b1, "/tmp/test_policy.json"), 0,
                   "ser: save single rule");
    b2 = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b2, "/tmp/test_policy.json"), 0,
                   "ser: load single rule");
    count = 0;
    const landlock_rule_t *rules1 = landlock_builder_get_rules(b2, &count);
    TEST_ASSERT_EQ(count, 1, "ser: single rule count");
    TEST_ASSERT_NOT_NULL(rules1, "ser: rules pointer valid");
    TEST_ASSERT_STR_EQ(rules1[0].path, "/tmp_test_policy", "ser: path matches");
    TEST_ASSERT_EQ(rules1[0].access, 7, "ser: access matches");
    landlock_builder_free(b1);
    landlock_builder_free(b2);
    remove("/tmp/test_policy.json");

    /* Case 2: Multi-rule roundtrip with specific masks */
    mock_fs_reset();
    mock_fs_create_dir("/round/a");
    mock_fs_create_dir("/round/b");
    b1 = landlock_builder_new();
    landlock_builder_allow(b1, "/round/a", LL_FS_READ_FILE);
    landlock_builder_allow(b1, "/round/b", LL_FS_WRITE_FILE);
    landlock_builder_prepare(b1, 4, false);
    TEST_ASSERT_EQ(landlock_builder_save(b1, "/tmp/roundtrip.json"), 0,
                   "ser: save multi-rule");
    b2 = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b2, "/tmp/roundtrip.json"), 0,
                   "ser: load multi-rule");
    count = 0;
    const landlock_rule_t *rules2 = landlock_builder_get_rules(b2, &count);
    TEST_ASSERT(count >= 2, "ser: multi rule count");
    int found_a = 0, found_b = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules2[i].path, "/round/a") == 0) {
            found_a = 1;
            TEST_ASSERT_EQ(rules2[i].access, LL_FS_READ_FILE, "ser: /round/a access");
        }
        if (strcmp(rules2[i].path, "/round/b") == 0) {
            found_b = 1;
            TEST_ASSERT_EQ(rules2[i].access, LL_FS_WRITE_FILE, "ser: /round/b access");
        }
    }
    TEST_ASSERT(found_a, "ser: /round/a loaded");
    TEST_ASSERT(found_b, "ser: /round/b loaded");
    landlock_builder_free(b1);
    landlock_builder_free(b2);
    remove("/tmp/roundtrip.json");

    /* Case 3: Load appends to existing rules */
    mock_fs_reset();
    mock_fs_create_dir("/load_test/a");
    mock_fs_create_dir("/load_test/b");
    b1 = landlock_builder_new();
    landlock_builder_allow(b1, "/load_test/a", 7);
    landlock_builder_prepare(b1, 2, false);
    landlock_builder_save(b1, "/tmp/load_append.json");
    b2 = landlock_builder_new();
    landlock_builder_allow(b2, "/load_test/b", 3);
    landlock_builder_load(b2, "/tmp/load_append.json");
    count = 0;
    const landlock_rule_t *rules3 = landlock_builder_get_rules(b2, &count);
    found_a = 0; found_b = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules3[i].path, "/load_test/a") == 0) found_a = 1;
        if (strcmp(rules3[i].path, "/load_test/b") == 0) found_b = 1;
    }
    TEST_ASSERT(found_a, "ser: loaded rule present");
    TEST_ASSERT(found_b, "ser: pre-existing rule present");
    landlock_builder_free(b1);
    landlock_builder_free(b2);
    remove("/tmp/load_append.json");
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_builder_run(void)
{
    printf("=== Builder Tests ===\n");
    RUN_TEST(test_builder_basic_operations);
    RUN_TEST(test_abi_masking);
    RUN_TEST(test_symlink_handling);
    RUN_TEST(test_save_load);
}
