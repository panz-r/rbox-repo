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
/*  Basic allow / deny                                                  */
/* ------------------------------------------------------------------ */

static void test_builder_allow_single_path(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/home");

    landlock_builder_t *b = landlock_builder_new();
    TEST_ASSERT_NOT_NULL(b, "builder creation");

    TEST_ASSERT_EQ(landlock_builder_allow(b, "/home", 7), 0, "allow /home");

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT(!rules || count == 0, "no rules before prepare");

    TEST_ASSERT_EQ(landlock_builder_prepare(b, 2, false), 0, "prepare");

    rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "rule count after prepare");
    TEST_ASSERT_STR_EQ(rules[0].path, "/home", "rule path");
    TEST_ASSERT_EQ(rules[0].access, 7, "rule access");

    landlock_builder_free(b);
}

static void test_builder_allow_and_deny(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/home");
    mock_fs_create_dir("/home/secret");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/home", 7);
    landlock_builder_deny(b, "/home/secret");
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* Use exact path matching, not substring */
    int found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home/secret") == 0) {
            found_secret = 1;
        }
    }
    TEST_ASSERT(!found_secret, "secret path denied and not in output");

    /* Verify /home survived */
    int found_home = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home") == 0) found_home = 1;
    }
    TEST_ASSERT(found_home, "/home still present after deny");

    landlock_builder_free(b);
}

static void test_builder_multiple_paths(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/usr");
    mock_fs_create_dir("/etc");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/usr", 7);
    landlock_builder_allow(b, "/etc", 3);
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    TEST_ASSERT_EQ(count, 2, "two rules");

    int found_usr = 0, found_etc = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/usr") == 0) found_usr = 1;
        if (strcmp(rules[i].path, "/etc") == 0) found_etc = 1;
    }
    TEST_ASSERT(found_usr, "found /usr");
    TEST_ASSERT(found_etc, "found /etc");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Prefix simplification (end-to-end)                                 */
/* ------------------------------------------------------------------ */

static void test_builder_simplification(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/usr");
    mock_fs_create_dir("/usr/lib");
    mock_fs_create_dir("/usr/bin");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/usr", 7);
    landlock_builder_allow(b, "/usr/lib", 3);  /* subset of 7 */
    landlock_builder_allow(b, "/usr/bin", 1);  /* subset of 7 */
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* After simplification, only /usr should remain */
    TEST_ASSERT_EQ(count, 1, "simplified to single rule");
    TEST_ASSERT_STR_EQ(rules[0].path, "/usr", "remaining path");
    /* Verify ABI v2 masking was applied (7 = EXECUTE|WRITE|READ, all in v2) */
    TEST_ASSERT_EQ(rules[0].access, 7, "access masked correctly for ABI v2");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  ABI masking                                                        */
/* ------------------------------------------------------------------ */

static void test_abi_mask_v1(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/home");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/home", 0xFF);  /* many rights */
    landlock_builder_prepare(b, 1, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    TEST_ASSERT_EQ(count, 1, "one rule");
    /* ABI v1 only supports EXECUTE */
    TEST_ASSERT_EQ(rules[0].access, 1, "masked to EXECUTE only");

    landlock_builder_free(b);
}

static void test_abi_mask_invalid(void)
{
    TEST_ASSERT_EQ(landlock_abi_mask(0), 0, "abi 0 returns 0");
    TEST_ASSERT_EQ(landlock_abi_mask(5), 0, "abi 5 returns 0");
}

/* ------------------------------------------------------------------ */
/*  Symlink expansion                                                   */
/* ------------------------------------------------------------------ */

static void test_symlink_expansion(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/var/data");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/link", "/var/data");

    landlock_builder_t *b = landlock_builder_new();
    /* Allow /home — this path doesn't resolve through the symlink.
     * Then separately allow the symlink path, which resolves to /var/data.
     * Symlink expansion should also add /var/data's parent /var if not
     * already covered. */
    landlock_builder_allow(b, "/home", 7);
    landlock_builder_allow(b, "/home/user/link", 7);
    landlock_builder_prepare(b, 2, true /* expand symlinks */);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* After simplification, /home should cover /home/user and /home/user/link
     * resolves to /var/data which should also be present. */
    int found_home = 0, found_var = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home") == 0) {
            found_home = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "/home access correct");
        }
        if (strcmp(rules[i].path, "/var/data") == 0) {
            found_var = 1;
            TEST_ASSERT_EQ(rules[i].access, 7, "/var/data access correct");
        }
    }
    TEST_ASSERT(found_home, "/home present after symlink expansion");
    TEST_ASSERT(found_var, "symlink target /var/data added as rule");
    /* Verify no garbage rules — should be exactly 2 */
    TEST_ASSERT_EQ(count, 2, "exactly 2 rules after symlink expansion");

    landlock_builder_free(b);
}

static void test_symlink_loop_termination(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/a");
    mock_fs_create_symlink("/a/link1", "/a/link2");
    mock_fs_create_symlink("/a/link2", "/a/link1");  /* Loop! */

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/a", 7);

    /* Should not hang — loop detection terminates */
    int ret = landlock_builder_prepare(b, 2, true);
    TEST_ASSERT_EQ(ret, 0, "prepare with symlink loop succeeds");

    /* Verify /a is still present (loop shouldn't corrupt the tree) */
    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "exactly one rule after loop handling");
    TEST_ASSERT_STR_EQ(rules[0].path, "/a", "/a is the only rule");
    TEST_ASSERT_EQ(rules[0].access, 7, "/a access correct");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Serialisation                                                       */
/* ------------------------------------------------------------------ */

static void test_save_load(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/tmp_test_policy");

    landlock_builder_t *b1 = landlock_builder_new();
    landlock_builder_allow(b1, "/tmp_test_policy", 7);
    landlock_builder_prepare(b1, 2, false);

    TEST_ASSERT_EQ(landlock_builder_save(b1, "/tmp/test_policy.json"), 0,
                   "save policy");

    landlock_builder_t *b2 = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b2, "/tmp/test_policy.json"), 0,
                   "load policy");

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b2, &count);
    TEST_ASSERT_EQ(count, 1, "loaded rule count");
    TEST_ASSERT_NOT_NULL(rules, "rules pointer is valid");
    TEST_ASSERT_STR_EQ(rules[0].path, "/tmp_test_policy",
                       "loaded path matches");
    TEST_ASSERT_EQ(rules[0].access, 7, "loaded access matches");

    landlock_builder_free(b1);
    landlock_builder_free(b2);

    /* Clean up */
    remove("/tmp/test_policy.json");
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_builder_run(void)
{
    printf("=== Builder Tests ===\n");
    RUN_TEST(test_builder_allow_single_path);
    RUN_TEST(test_builder_allow_and_deny);
    RUN_TEST(test_builder_multiple_paths);
    RUN_TEST(test_builder_simplification);
    RUN_TEST(test_abi_mask_v1);
    RUN_TEST(test_abi_mask_invalid);
    RUN_TEST(test_symlink_expansion);
    RUN_TEST(test_symlink_loop_termination);
    RUN_TEST(test_save_load);
}
