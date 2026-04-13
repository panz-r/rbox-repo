/**
 * @file test_builder_extended.c
 * @brief Extended builder tests — regression tests for fixed bugs
 *        and additional edge case coverage.
 */

#include "test_framework.h"
#include "mock_fs.h"
#include "landlock_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/*  Deny on symlink: source path vs resolved target path              */
/* ------------------------------------------------------------------ */

static void test_deny_via_symlink(void)
{
    landlock_builder_t *b;
    size_t count;
    int found_user, found_secret;

    /* Case 1: Deny the symlink source path */
    mock_fs_reset();
    mock_fs_create_dir("/real/secret");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/secret_link", "/real/secret");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/home/user", 7);
    landlock_builder_deny(b, "/home/user/secret_link");
    landlock_builder_prepare(b, 2, true);
    count = 0;
    const landlock_rule_t *rules1 = landlock_builder_get_rules(b, &count);
    found_user = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules1[i].path, "/home/user") == 0) found_user = 1;
    }
    TEST_ASSERT(found_user, "deny source: /home/user present");
    found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules1[i].path, "secret")) found_secret = 1;
    }
    TEST_ASSERT(!found_secret, "deny source: symlink target not in rules");
    landlock_builder_free(b);

    /* Case 2: Deny the resolved target path */
    mock_fs_reset();
    mock_fs_create_dir("/real/secret");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/link", "/real/secret");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/home", 7);
    landlock_builder_allow(b, "/home/user/link", 7);
    landlock_builder_deny(b, "/real/secret");
    landlock_builder_prepare(b, 2, true);
    count = 0;
    const landlock_rule_t *rules2 = landlock_builder_get_rules(b, &count);
    found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules2[i].path, "/real/secret") == 0) found_secret = 1;
    }
    TEST_ASSERT(!found_secret, "deny target: resolved target not in rules");
    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Path handling: relative paths and symlink chains                   */
/* ------------------------------------------------------------------ */

static void test_path_handling(void)
{
    landlock_builder_t *b;
    size_t count;

    /* Case 1: Relative path normalized to absolute */
    mock_fs_reset();
    mock_fs_create_dir("/relative/path");
    b = landlock_builder_new();
    int ret = landlock_builder_allow(b, "relative/path", 7);
    TEST_ASSERT_EQ(ret, 0, "path: relative path accepted");
    landlock_builder_prepare(b, 2, false);
    count = 0;
    const landlock_rule_t *rules1 = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "path: one rule collected");
    TEST_ASSERT_STR_EQ(rules1[0].path, "/relative/path",
                       "path: relative path normalised to absolute");
    landlock_builder_free(b);

    /* Case 2: Symlink chain resolves through builder */
    mock_fs_reset();
    mock_fs_create_dir("/real/target");
    mock_fs_create_symlink("/link1", "/real/target");
    mock_fs_create_symlink("/link2", "/link1");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/link2", 7);
    landlock_builder_prepare(b, 2, true);
    count = 0;
    const landlock_rule_t *rules2 = landlock_builder_get_rules(b, &count);
    int found_target = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules2[i].path, "/real/target") == 0) found_target = 1;
    }
    TEST_ASSERT(found_target, "path: symlink chain resolves to final target");
    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Re-prepare with different ABI versions                             */
/* ------------------------------------------------------------------ */

static void test_reprepare_different_abi(void)
{
    landlock_builder_t *b;

    /* Case 1: Re-prepare in-place with different ABI */
    mock_fs_reset();
    mock_fs_create_dir("/data");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 0xFF);
    landlock_builder_prepare(b, 1, false);
    size_t count1 = 0;
    const landlock_rule_t *r1 = landlock_builder_get_rules(b, &count1);
    TEST_ASSERT_EQ(count1, 1, "inplace: prepare v1");
    uint64_t access_v1 = r1[0].access;
    landlock_builder_prepare(b, 4, false);
    size_t count4 = 0;
    const landlock_rule_t *r4 = landlock_builder_get_rules(b, &count4);
    TEST_ASSERT_EQ(count4, 1, "inplace: prepare v4");
    uint64_t access_v4 = r4[0].access;
    TEST_ASSERT(access_v1 <= access_v4, "inplace: v1 access <= v4 access");
    TEST_ASSERT(access_v1 != access_v4, "inplace: v1 and v4 access differ");
    landlock_builder_free(b);

    /* Case 2: Save → load → re-prepare with different ABI */
    mock_fs_reset();
    mock_fs_create_dir("/data");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 0xFF);
    landlock_builder_prepare(b, 4, false);
    size_t c1 = 0;
    const landlock_rule_t *r1b = landlock_builder_get_rules(b, &c1);
    TEST_ASSERT_EQ(c1, 1, "save: original has 1 rule");
    TEST_ASSERT_EQ(r1b[0].access, 0xFF, "save: original access masked to ABI v4");
    TEST_ASSERT_EQ(landlock_builder_save(b, "/tmp/reprepare.json"), 0,
                   "save: save succeeds");
    landlock_builder_t *b2 = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b2, "/tmp/reprepare.json"), 0,
                   "save: load succeeds");
    landlock_builder_prepare(b2, 1, false);
    size_t c2 = 0;
    const landlock_rule_t *r2 = landlock_builder_get_rules(b2, &c2);
    TEST_ASSERT_EQ(c2, 1, "save: re-prepared has 1 rule");
    TEST_ASSERT_STR_EQ(r2[0].path, "/data", "save: path preserved");
    TEST_ASSERT_EQ(r2[0].access, 1, "save: access re-masked to ABI v1");
    landlock_builder_free(b);
    landlock_builder_free(b2);
    remove("/tmp/reprepare.json");
}

/* ------------------------------------------------------------------ */
/*  Builder API edge cases                                            */
/* ------------------------------------------------------------------ */

static void test_null_builder(void)
{
    TEST_ASSERT_EQ(landlock_builder_allow(NULL, "/x", 1), -1, "allow on NULL");
    TEST_ASSERT_EQ(landlock_builder_deny(NULL, "/x"), -1, "deny on NULL");
    TEST_ASSERT_EQ(landlock_builder_prepare(NULL, 2, false), -1, "prepare NULL");
    TEST_ASSERT(landlock_builder_get_rules(NULL, NULL) == NULL, "get_rules NULL");
    TEST_ASSERT_EQ(landlock_builder_save(NULL, "/x"), -1, "save NULL");
    TEST_ASSERT_EQ(landlock_builder_load(NULL, "/x"), -1, "load NULL");

    landlock_builder_free(NULL);  /* should not crash */
}

/* ------------------------------------------------------------------ */
/*  Symlink expansion: child, single, multiple, deny                   */
/* ------------------------------------------------------------------ */

static void test_symlink_expansion(void)
{
    landlock_builder_t *b;
    size_t count;
    int found;

    /* Case 1: Full access mask (7) — target covers all children */
    mock_fs_reset();
    mock_fs_create_dir("/real");
    mock_fs_create_dir("/real/subdir");
    mock_fs_create_file("/real/file.txt");
    mock_fs_create_dir("/real/subdir/deep");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/real_link", "/real");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/home/user/real_link", 7);
    landlock_builder_prepare(b, 2, true);
    count = 0;
    const landlock_rule_t *rules1 = landlock_builder_get_rules(b, &count);
    found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules1[i].path, "/real") == 0) found = 1;
    }
    TEST_ASSERT(found, "child: symlink target /real added");
    TEST_ASSERT_EQ(count, 1, "child: simplify pruned children");
    landlock_builder_free(b);

    /* Case 2: Limited access mask (READ_FILE) — same mask on all children */
    mock_fs_reset();
    mock_fs_create_dir("/src");
    mock_fs_create_dir("/src/subdir");
    mock_fs_create_file("/src/file.txt");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/src_link", "/src");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/home/user/src_link", LL_FS_READ_FILE);
    landlock_builder_prepare(b, 2, true);
    count = 0;
    const landlock_rule_t *rules2 = landlock_builder_get_rules(b, &count);
    found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules2[i].path, "/src") == 0) found = 1;
    }
    TEST_ASSERT(found, "limited: /src added via expansion");
    TEST_ASSERT_EQ(count, 1, "limited: simplify prunes children");
    landlock_builder_free(b);

    /* Case 3: Single symlink → expand + simplify + ABI masking */
    mock_fs_reset();
    mock_fs_create_dir("/real");
    mock_fs_create_dir("/real/sub");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/link", "/real");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/home", 7);
    landlock_builder_allow(b, "/home/user/link", 7);
    landlock_builder_allow(b, "/real/sub", 3);  /* subset, should be pruned */
    landlock_builder_prepare(b, 3, true);  /* ABI v3 */
    count = 0;
    const landlock_rule_t *rules3 = landlock_builder_get_rules(b, &count);
    int found_home = 0, found_real = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules3[i].path, "/home") == 0) found_home = 1;
        if (strcmp(rules3[i].path, "/real") == 0) found_real = 1;
    }
    TEST_ASSERT(found_home, "single: /home present");
    TEST_ASSERT(found_real, "single: /real present after expansion");
    TEST_ASSERT_EQ(count, 2, "single: exactly 2 rules (children pruned)");
    /* Verify access masks */
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules3[i].path, "/home") == 0) {
            TEST_ASSERT_EQ(rules3[i].access, 7, "single: /home access correct");
        }
        if (strcmp(rules3[i].path, "/real") == 0) {
            TEST_ASSERT_EQ(rules3[i].access, 7, "single: /real access correct");
        }
    }
    landlock_builder_free(b);

    /* Case 4: Multiple symlinks to same target → dedup + simplify */
    mock_fs_reset();
    mock_fs_create_dir("/real");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/link1", "/real");
    mock_fs_create_symlink("/home/user/link2", "/real");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/home", 7);
    landlock_builder_allow(b, "/home/user/link1", 7);
    landlock_builder_allow(b, "/home/user/link2", 7);
    landlock_builder_prepare(b, 2, true);
    count = 0;
    const landlock_rule_t *rules4 = landlock_builder_get_rules(b, &count);
    found_home = 0; found_real = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules4[i].path, "/home") == 0) found_home = 1;
        if (strcmp(rules4[i].path, "/real") == 0) found_real = 1;
    }
    TEST_ASSERT(found_home, "multi: /home present");
    TEST_ASSERT(found_real, "multi: /real present (from symlink expansion)");
    TEST_ASSERT(count <= 2, "multi: at most 2 rules after simplify");
    landlock_builder_free(b);

    /* Case 5: Simplify + ABI masking with partial bit overlap */
    mock_fs_reset();
    mock_fs_create_dir("/usr");
    mock_fs_create_dir("/usr/lib");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/usr", 0xFF);
    landlock_builder_allow(b, "/usr/lib", 0x07);
    landlock_builder_prepare(b, 1, false);  /* ABI v1 */
    count = 0;
    const landlock_rule_t *rules5 = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "abi: simplified to one rule");
    TEST_ASSERT_STR_EQ(rules5[0].path, "/usr", "abi: remaining path is /usr");
    TEST_ASSERT_EQ(rules5[0].access, 1, "abi: access masked to ABI v1");
    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Interaction: allow → deny → re-allow same path                    */
/* ------------------------------------------------------------------ */

static void test_allow_deny_reallow(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 7);
    landlock_builder_deny(b, "/data");
    /* Re-allow the same path — should override the deny */
    landlock_builder_allow(b, "/data", 3);
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "one rule after re-allow");
    TEST_ASSERT_STR_EQ(rules[0].path, "/data", "path is /data");
    TEST_ASSERT_EQ(rules[0].access, 3, "access is 3 (re-allowed)");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_builder_extended_run(void)
{
    printf("=== Builder Extended Tests ===\n");
    RUN_TEST(test_deny_via_symlink);
    RUN_TEST(test_path_handling);
    RUN_TEST(test_reprepare_different_abi);
    RUN_TEST(test_null_builder);
    RUN_TEST(test_symlink_expansion);
    RUN_TEST(test_allow_deny_reallow);
}
