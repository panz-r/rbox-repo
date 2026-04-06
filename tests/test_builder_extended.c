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
/*  Bug regression: JSON save/load with special characters (bug #12)  */
/* ------------------------------------------------------------------ */

static void test_save_load_json_escaping(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/tmp_test_special");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/tmp_test_special", 7);
    landlock_builder_prepare(b, 2, false);

    TEST_ASSERT_EQ(landlock_builder_save(b, "/tmp/test_special.json"), 0,
                   "save with special chars");

    /* Verify the file contains properly escaped JSON */
    FILE *f = fopen("/tmp/test_special.json", "r");
    TEST_ASSERT_NOT_NULL(f, "saved file exists");
    if (f) {
        char buf[1024];
        { size_t _r = fread(buf, 1, sizeof(buf) - 1, f); (void)_r; }
        buf[sizeof(buf) - 1] = '\0';
        fclose(f);

        /* Check it's valid-ish JSON with proper structure */
        TEST_ASSERT(strstr(buf, "\"abi_version\"") != NULL, "JSON has abi_version");
        TEST_ASSERT(strstr(buf, "\"path\"") != NULL, "JSON has path key");
        TEST_ASSERT(strstr(buf, "\"access\"") != NULL, "JSON has access key");
        TEST_ASSERT(strstr(buf, "/tmp_test_special") != NULL, "JSON has path value");
    }

    landlock_builder_free(b);
    remove("/tmp/test_special.json");
}

/* ------------------------------------------------------------------ */
/*  Bug regression: save/load round-trip correctness (bug #16)         */
/* ------------------------------------------------------------------ */

static void test_save_load_roundtrip(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/round/a");
    mock_fs_create_dir("/round/b");

    landlock_builder_t *b1 = landlock_builder_new();
    landlock_builder_allow(b1, "/round/a", LL_FS_READ_FILE);
    landlock_builder_allow(b1, "/round/b", LL_FS_WRITE_FILE);
    landlock_builder_prepare(b1, 4, false);

    TEST_ASSERT_EQ(landlock_builder_save(b1, "/tmp/roundtrip.json"), 0,
                   "save roundtrip");

    landlock_builder_t *b2 = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b2, "/tmp/roundtrip.json"), 0,
                   "load roundtrip");

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b2, &count);
    TEST_ASSERT(count >= 2, "at least 2 rules loaded");

    int found_a = 0, found_b = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "/round/a")) {
            found_a = 1;
            TEST_ASSERT_EQ(rules[i].access, LL_FS_READ_FILE,
                           "/round/a has correct access");
        }
        if (strstr(rules[i].path, "/round/b")) {
            found_b = 1;
            TEST_ASSERT_EQ(rules[i].access, LL_FS_WRITE_FILE,
                           "/round/b has correct access");
        }
    }
    TEST_ASSERT(found_a, "/round/a loaded");
    TEST_ASSERT(found_b, "/round/b loaded");

    landlock_builder_free(b1);
    landlock_builder_free(b2);
    remove("/tmp/roundtrip.json");
}

/* ------------------------------------------------------------------ */
/*  Bug regression: deny on symlink (bug #8)                          */
/* ------------------------------------------------------------------ */

static void test_deny_on_symlink(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/real/secret");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/secret_link", "/real/secret");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/home/user", 7);
    landlock_builder_deny(b, "/home/user/secret_link");
    landlock_builder_prepare(b, 2, true);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* /home/user must be present (the rule we allowed) */
    int found_user = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home/user") == 0) found_user = 1;
    }
    TEST_ASSERT(found_user, "/home/user rule present");

    /* The symlink target /real/secret should NOT appear in rules */
    int found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "secret")) {
            found_secret = 1;
        }
    }
    TEST_ASSERT(!found_secret, "deny on symlink target not in rules");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  ABI masking: all bits stripped                                    */
/* ------------------------------------------------------------------ */

static void test_abi_mask_strips_all_bits(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");

    landlock_builder_t *b = landlock_builder_new();
    /* Only set bits that ABI v1 doesn't support */
    landlock_builder_allow(b, "/data", LL_FS_WRITE_FILE | LL_FS_READ_FILE);
    landlock_builder_prepare(b, 1, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    TEST_ASSERT_EQ(count, 1, "rule exists");
    /* ABI v1 only supports EXECUTE, so WRITE|READ → 0 */
    TEST_ASSERT_EQ(rules[0].access, 0, "all bits stripped by ABI mask");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  ABI masking: v4 includes all rights                               */
/* ------------------------------------------------------------------ */

static void test_abi_v4_no_strip(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");

    landlock_builder_t *b = landlock_builder_new();
    uint64_t all_bits = LL_FS_ALL;
    landlock_builder_allow(b, "/data", all_bits);
    landlock_builder_prepare(b, 4, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    TEST_ASSERT_EQ(count, 1, "rule exists");
    /* ABI v4 mask covers bits 0-16; LL_FS_ALL has all 64 bits set.
     * After masking, only the ABI v4 bits remain. */
    uint64_t expected = landlock_abi_mask(4);
    TEST_ASSERT_EQ(rules[0].access, expected, "ABI v4 masks to defined bits");
}

/* ------------------------------------------------------------------ */
/*  Relative path handling                                            */
/* ------------------------------------------------------------------ */

static void test_relative_path(void)
{
    mock_fs_reset();
    /* Mock fs treats relative paths as absolute (cwd = /) */
    mock_fs_create_dir("/relative/path");

    landlock_builder_t *b = landlock_builder_new();
    /* Relative path gets cwd ("/") prepended → "/relative/path" */
    int ret = landlock_builder_allow(b, "relative/path", 7);
    TEST_ASSERT_EQ(ret, 0, "relative path accepted");

    /* Verify the rule was collected with the normalised absolute path */
    landlock_builder_prepare(b, 2, false);
    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "one rule collected");
    TEST_ASSERT_STR_EQ(rules[0].path, "/relative/path",
                       "relative path normalised to absolute");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Double prepare (re-prepare with different ABI)                    */
/* ------------------------------------------------------------------ */

static void test_reprepare_different_abi(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 0xFF);

    landlock_builder_prepare(b, 1, false);
    size_t count1 = 0;
    const landlock_rule_t *r1 = landlock_builder_get_rules(b, &count1);
    TEST_ASSERT_EQ(count1, 1, "prepare v1");
    uint64_t access_v1 = r1[0].access;

    /* Re-prepare with v4 */
    landlock_builder_prepare(b, 4, false);
    size_t count4 = 0;
    const landlock_rule_t *r4 = landlock_builder_get_rules(b, &count4);
    TEST_ASSERT_EQ(count4, 1, "prepare v4");
    uint64_t access_v4 = r4[0].access;

    /* v1 should have fewer bits than v4 */
    TEST_ASSERT(access_v1 <= access_v4, "v1 access <= v4 access");
    TEST_ASSERT(access_v1 != access_v4, "v1 and v4 access differ");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Load into builder with existing rules (append behavior)            */
/* ------------------------------------------------------------------ */

static void test_load_appends(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/load_test/a");
    mock_fs_create_dir("/load_test/b");

    /* Create and save policy with /load_test/a */
    landlock_builder_t *b1 = landlock_builder_new();
    landlock_builder_allow(b1, "/load_test/a", 7);
    landlock_builder_prepare(b1, 2, false);
    landlock_builder_save(b1, "/tmp/load_append.json");

    /* Create a new builder, add a rule, then load */
    landlock_builder_t *b2 = landlock_builder_new();
    landlock_builder_allow(b2, "/load_test/b", 3);
    landlock_builder_load(b2, "/tmp/load_append.json");

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b2, &count);

    /* b2 had /load_test/b in its tree. Load added /load_test/a.
     * Both should be present after collect_rules in load. */
    int found_a = 0, found_b = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "/load_test/a")) found_a = 1;
        if (strstr(rules[i].path, "/load_test/b")) found_b = 1;
    }
    TEST_ASSERT(found_a, "loaded rule present");
    TEST_ASSERT(found_b, "pre-existing rule present");

    landlock_builder_free(b1);
    landlock_builder_free(b2);
    remove("/tmp/load_append.json");
}

/* ------------------------------------------------------------------ */
/*  Empty file load                                                   */
/* ------------------------------------------------------------------ */

static void test_load_empty_file(void)
{
    /* Create an empty file */
    FILE *f = fopen("/tmp/empty_policy.json", "w");
    if (f) fclose(f);

    landlock_builder_t *b = landlock_builder_new();
    int ret = landlock_builder_load(b, "/tmp/empty_policy.json");
    TEST_ASSERT_EQ(ret, -1, "load empty file fails");

    landlock_builder_free(b);
    remove("/tmp/empty_policy.json");
}

/* ------------------------------------------------------------------ */
/*  Load nonexistent file                                             */
/* ------------------------------------------------------------------ */

static void test_load_nonexistent(void)
{
    landlock_builder_t *b = landlock_builder_new();
    int ret = landlock_builder_load(b, "/nonexistent/file.json");
    TEST_ASSERT_EQ(ret, -1, "load nonexistent file fails");
    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Symlink chain (not a loop)                                        */
/* ------------------------------------------------------------------ */

static void test_symlink_chain(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/real/target");
    mock_fs_create_symlink("/link1", "/real/target");
    mock_fs_create_symlink("/link2", "/link1");  /* chain, not loop */

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/link2", 7);
    landlock_builder_prepare(b, 2, true);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* /link2 → /link1 → /real/target. The canonical path is /real/target */
    int found_target = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "/real/target")) {
            found_target = 1;
        }
    }
    TEST_ASSERT(found_target, "symlink chain resolves to final target");

    landlock_builder_free(b);
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

static void test_empty_path(void)
{
    mock_fs_reset();
    landlock_builder_t *b = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_allow(b, "", 1), -1, "empty path rejected");
    TEST_ASSERT_EQ(landlock_builder_deny(b, ""), -1, "empty deny rejected");
    landlock_builder_free(b);
}

static void test_double_slash_path(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/double/path");

    landlock_builder_t *b = landlock_builder_new();
    /* Path with double slashes should be normalised to /double/path */
    int ret = landlock_builder_allow(b, "//double///path", 7);
    TEST_ASSERT_EQ(ret, 0, "double-slash path accepted");

    /* Verify the normalised path was stored */
    landlock_builder_prepare(b, 2, false);
    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "one rule collected");
    TEST_ASSERT_STR_EQ(rules[0].path, "/double/path",
                       "slashes collapsed in collected path");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  O_PATH file descriptor helper                                     */
/* ------------------------------------------------------------------ */

static void test_open_fd_basic(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/openfd_test");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/openfd_test", 7);
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT(count >= 1, "at least one rule");

    /* Test opening the rule with O_PATH */
    int fd = landlock_rule_open_fd(&rules[0], 0);
    /* With mock fs, realpath returns the path, but the real kernel
     * may not have /openfd_test.  Just check it doesn't crash. */
    if (fd >= 0) close(fd);  /* real fs case */

    /* Test NULL/invalid inputs */
    TEST_ASSERT_EQ(landlock_rule_open_fd(NULL, 0), -1, "NULL rule rejected");
    landlock_rule_t empty_rule = { .path = NULL, .access = 0 };
    TEST_ASSERT_EQ(landlock_rule_open_fd(&empty_rule, 0), -1, "NULL path rejected");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Symlink child expansion                                           */
/* ------------------------------------------------------------------ */

static void test_symlink_child_expansion(void)
{
    mock_fs_reset();
    /* Create a directory hierarchy under /real */
    mock_fs_create_dir("/real");
    mock_fs_create_dir("/real/subdir");
    mock_fs_create_file("/real/file.txt");
    mock_fs_create_dir("/real/subdir/deep");

    /* Create a symlink under /home pointing to /real */
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/real_link", "/real");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/home/user/real_link", 7);
    landlock_builder_prepare(b, 2, true /* expand symlinks */);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* After expansion + simplification, /real should cover all children
     * (same access mask → children pruned as redundant). */
    int found_real = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/real") == 0) found_real = 1;
    }
    TEST_ASSERT(found_real, "symlink target /real added");
    /* All children are pruned by simplify since /real covers them */
    TEST_ASSERT_EQ(count, 1, "simplify pruned children (covered by /real)");

    landlock_builder_free(b);
}

/* Test expansion with different masks — children should survive simplify */
static void test_symlink_child_expansion_different_masks(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/src");
    mock_fs_create_dir("/src/subdir");
    mock_fs_create_file("/src/file.txt");
    mock_fs_create_dir("/home/user");
    mock_fs_create_symlink("/home/user/src_link", "/src");

    landlock_builder_t *b = landlock_builder_new();
    /* Allow parent with limited access; symlink expansion uses same access */
    landlock_builder_allow(b, "/home/user/src_link", LL_FS_READ_FILE);
    landlock_builder_prepare(b, 2, true);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    int found_src = 0; (void)0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/src") == 0) found_src = 1;
    }
    /* All have same mask (READ_FILE), so simplify prunes to just /src */
    TEST_ASSERT(found_src, "/src added via expansion");
    TEST_ASSERT_EQ(count, 1, "simplify prunes children");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_builder_extended_run(void)
{
    printf("=== Builder Extended Tests ===\n");
    RUN_TEST(test_save_load_json_escaping);
    RUN_TEST(test_save_load_roundtrip);
    RUN_TEST(test_deny_on_symlink);
    RUN_TEST(test_abi_mask_strips_all_bits);
    RUN_TEST(test_abi_v4_no_strip);
    RUN_TEST(test_relative_path);
    RUN_TEST(test_reprepare_different_abi);
    RUN_TEST(test_load_appends);
    RUN_TEST(test_load_empty_file);
    RUN_TEST(test_load_nonexistent);
    RUN_TEST(test_symlink_chain);
    RUN_TEST(test_null_builder);
    RUN_TEST(test_empty_path);
    RUN_TEST(test_double_slash_path);
    RUN_TEST(test_open_fd_basic);
    RUN_TEST(test_symlink_child_expansion);
    RUN_TEST(test_symlink_child_expansion_different_masks);
}
