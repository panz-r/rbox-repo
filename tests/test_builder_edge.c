/**
 * @file test_builder_edge.c
 * @brief Edge-case tests for the builder API.
 */

#define _GNU_SOURCE
#define MOCK_FS_INTERNAL
#include "test_framework.h"
#include "mock_fs.h"
#include "landlock_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* ------------------------------------------------------------------ */
/*  Save on unprepared builder                                         */
/* ------------------------------------------------------------------ */

static void test_save_unprepared(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 7);
    /* NOT calling prepare() */

    int ret = landlock_builder_save(b, "/tmp/unprepared.json");
    TEST_ASSERT_EQ(ret, -1, "save on unprepared builder fails");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Load empty file                                                    */
/* ------------------------------------------------------------------ */

static void test_load_empty_file(void)
{
    FILE *f = fopen("/tmp/empty.json", "w");
    if (f) fclose(f);

    landlock_builder_t *b = landlock_builder_new();
    int ret = landlock_builder_load(b, "/tmp/empty.json");
    TEST_ASSERT_EQ(ret, -1, "load empty file fails");

    landlock_builder_free(b);
    remove("/tmp/empty.json");
}

static void test_load_nonexistent(void)
{
    landlock_builder_t *b = landlock_builder_new();
    int ret = landlock_builder_load(b, "/nonexistent/path.json");
    TEST_ASSERT_EQ(ret, -1, "load nonexistent file fails");
    landlock_builder_free(b);
}

static void test_load_malformed_json(void)
{
    /* Write JSON missing the abi_version key — parser must fail */
    FILE *f = fopen("/tmp/malformed.json", "w");
    if (f) {
        fprintf(f, "{ \"rules\": [] }");
        fclose(f);
    }

    landlock_builder_t *b = landlock_builder_new();
    int ret = landlock_builder_load(b, "/tmp/malformed.json");
    TEST_ASSERT_EQ(ret, -1, "JSON without abi_version rejected");

    landlock_builder_free(b);
    remove("/tmp/malformed.json");
}

/* ------------------------------------------------------------------ */
/*  O_PATH fd with explicit flags                                      */
/* ------------------------------------------------------------------ */

static void test_open_fd_with_flags(void)
{
    /* Create a real temp directory so open() actually succeeds */
    char tmpl[] = "/tmp/llb_fd_test_XXXXXX";
    char *real_dir = mkdtemp(tmpl);
    TEST_ASSERT_NOT_NULL(real_dir, "mkdtemp creates real directory");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, real_dir, 7);
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT(count >= 1, "at least one rule");

    /* Default flags (O_PATH | O_CLOEXEC | O_NOFOLLOW) */
    int fd = landlock_rule_open_fd(&rules[0], 0);
    TEST_ASSERT(fd >= 0, "open_fd with default flags succeeds");
    close(fd);

    /* Explicit O_RDONLY */
    fd = landlock_rule_open_fd(&rules[0], O_RDONLY);
    TEST_ASSERT(fd >= 0, "open_fd with O_RDONLY succeeds");
    close(fd);

    /* Explicit O_PATH | O_CLOEXEC */
    fd = landlock_rule_open_fd(&rules[0], O_PATH | O_CLOEXEC);
    TEST_ASSERT(fd >= 0, "open_fd with O_PATH|O_CLOEXEC succeeds");
    close(fd);

    landlock_builder_free(b);
    rmdir(real_dir);
}

/* ------------------------------------------------------------------ */
/*  Prepare with ABI version 0 and > LANDLOCK_ABI_MAX                  */
/* ------------------------------------------------------------------ */

static void test_prepare_invalid_abi(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 7);

    TEST_ASSERT_EQ(landlock_builder_prepare(b, 0, false), -1,
                   "prepare ABI 0 fails");
    TEST_ASSERT_EQ(landlock_builder_prepare(b, -1, false), -1,
                   "prepare ABI -1 fails");
    TEST_ASSERT_EQ(landlock_builder_prepare(b, 99, false), -1,
                   "prepare ABI 99 fails");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Allow with LL_FS_ALL                                              */
/* ------------------------------------------------------------------ */

static void test_allow_all_access(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/data", LL_FS_ALL);
    landlock_builder_prepare(b, 4, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "one rule");

    /* ABI v4 mask should limit the access */
    uint64_t expected = landlock_abi_mask(4);
    TEST_ASSERT_EQ(rules[0].access, expected, "access masked to ABI v4");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  VFS relative path not filtered                                     */
/* ------------------------------------------------------------------ */

static void test_vfs_relative_path_not_filtered(void)
{
    /* Relative paths like "proc/bar" should NOT be filtered */
    TEST_ASSERT_EQ(landlock_path_is_vfs("proc/bar"), 0,
                   "relative 'proc/bar' is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("sys/foo"), 0,
                   "relative 'sys/foo' is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("./proc"), 0,
                   "relative './proc' is not VFS");
}

/* ------------------------------------------------------------------ */
/*  Prepare with expand_symlinks when no symlinks exist               */
/* ------------------------------------------------------------------ */

static void test_prepare_no_symlinks(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");
    mock_fs_create_dir("/data/sub");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 7);
    landlock_builder_allow(b, "/data/sub", 3);
    landlock_builder_prepare(b, 2, true /* expand_symlinks */);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* Both rules should be present; simplification may prune /data/sub */
    TEST_ASSERT(count >= 1, "at least one rule");
    int found_data = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "/data")) found_data = 1;
    }
    TEST_ASSERT(found_data, "/data present");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Re-prepare after allow clears prepared flag                        */
/* ------------------------------------------------------------------ */

static void test_reprepare_after_allow(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/a");
    mock_fs_create_dir("/b");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/a", 7);
    landlock_builder_prepare(b, 2, false);

    size_t c1 = 0;
    landlock_builder_get_rules(b, &c1);
    TEST_ASSERT_EQ(c1, 1, "first prepare: 1 rule");

    /* Adding a new rule should clear prepared state */
    landlock_builder_allow(b, "/b", 3);
    size_t c2 = 0;
    landlock_builder_get_rules(b, &c2);
    TEST_ASSERT_EQ(c2, 0, "after allow, rules cleared");

    /* Re-prepare */
    landlock_builder_prepare(b, 2, false);
    size_t c3 = 0;
    landlock_builder_get_rules(b, &c3);
    TEST_ASSERT(c3 >= 2, "re-prepare: both rules present");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  JSON escape roundtrip                                              */
/* ------------------------------------------------------------------ */

static void test_json_escape_roundtrip(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/round/data");

    landlock_builder_t *b1 = landlock_builder_new();
    landlock_builder_allow(b1, "/round/data", LL_FS_WRITE_FILE);
    landlock_builder_prepare(b1, 2, false);
    TEST_ASSERT_EQ(landlock_builder_save(b1, "/tmp/roundtrip.json"), 0,
                   "save succeeds");

    landlock_builder_t *b2 = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b2, "/tmp/roundtrip.json"), 0,
                   "load succeeds");

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b2, &count);
    TEST_ASSERT_EQ(count, 1, "one rule loaded");
    TEST_ASSERT_STR_EQ(rules[0].path, "/round/data", "path roundtrip");
    TEST_ASSERT_EQ(rules[0].access, LL_FS_WRITE_FILE, "access roundtrip");

    landlock_builder_free(b1);
    landlock_builder_free(b2);
    remove("/tmp/roundtrip.json");
}

/* ------------------------------------------------------------------ */
/*  Overlap removal: deny at intermediate path clears deeper allow    */
/* ------------------------------------------------------------------ */

static void test_deny_clears_deeper_allow(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/a");
    mock_fs_create_dir("/a/b");
    mock_fs_create_dir("/a/b/c");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/a/b/c", 7);
    landlock_builder_deny(b, "/a/b");
    landlock_builder_allow(b, "/a", 7);
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    int found_c = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "/a/b/c")) found_c = 1;
    }
    TEST_ASSERT(!found_c, "deeper allow cleared by intermediate deny");
    int found_a = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/a") == 0) found_a = 1;
    }
    TEST_ASSERT(found_a, "/a survives");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  expand_symlinks when source is NOT under any allowed rule          */
/* ------------------------------------------------------------------ */

static void test_symlink_expansion_no_matching_rule(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/real/target");
    mock_fs_create_dir("/other/place");
    mock_fs_create_symlink("/other/place/link", "/real/target");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/unrelated", 7);
    landlock_builder_prepare(b, 2, true);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* /unrelated must be present (the rule we allowed) */
    int found_unrelated = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/unrelated") == 0) found_unrelated = 1;
    }
    TEST_ASSERT(found_unrelated, "/unrelated rule present");

    /* /real/target should NOT appear — symlink source not under any rule */
    int found_target = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules[i].path, "/real/target")) found_target = 1;
    }
    TEST_ASSERT(!found_target,
                "symlink target not added when source has no matching rule");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Simplify with child that has a deny grandchild                     */
/* ------------------------------------------------------------------ */

static void test_simplify_deny_grandchild_blocks_pruning(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/a");
    mock_fs_create_dir("/a/b");
    mock_fs_create_dir("/a/b/secret");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/a", 7);
    landlock_builder_allow(b, "/a/b", 7);
    landlock_builder_deny(b, "/a/b/secret");
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    int found_b = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/a/b") == 0) found_b = 1;
    }
    TEST_ASSERT(found_b, "child with deny grandchild not pruned");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_builder_edge_run(void)
{
    printf("=== Builder Edge-Case Tests ===\n");
    RUN_TEST(test_save_unprepared);
    RUN_TEST(test_load_malformed_json);
    RUN_TEST(test_load_empty_file);
    RUN_TEST(test_load_nonexistent);
    RUN_TEST(test_open_fd_with_flags);
    RUN_TEST(test_prepare_invalid_abi);
    RUN_TEST(test_allow_all_access);
    RUN_TEST(test_vfs_relative_path_not_filtered);
    RUN_TEST(test_prepare_no_symlinks);
    RUN_TEST(test_reprepare_after_allow);
    RUN_TEST(test_json_escape_roundtrip);
    RUN_TEST(test_deny_clears_deeper_allow);
    RUN_TEST(test_symlink_expansion_no_matching_rule);
    RUN_TEST(test_simplify_deny_grandchild_blocks_pruning);
}
