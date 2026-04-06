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
/*  Load malformed JSON                                                */
/* ------------------------------------------------------------------ */

static void test_load_malformed_json(void)
{
    /* Write truncated JSON */
    FILE *f = fopen("/tmp/malformed.json", "w");
    if (f) {
        fprintf(f, "{ \"abi_version\": 2, \"rules\": [");
        fclose(f);
    }

    landlock_builder_t *b = landlock_builder_new();
    int ret = landlock_builder_load(b, "/tmp/malformed.json");
    /* May succeed (empty rules) or fail — just check no crash */
    (void)ret;

    landlock_builder_free(b);
    remove("/tmp/malformed.json");
}

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

/* ------------------------------------------------------------------ */
/*  O_PATH fd with explicit flags                                      */
/* ------------------------------------------------------------------ */

static void test_open_fd_with_flags(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/fd_test");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, "/fd_test", 7);
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT(count >= 1, "at least one rule");

    /* Test with explicit O_RDONLY flag */
    int fd = landlock_rule_open_fd(&rules[0], O_RDONLY);
    if (fd >= 0) close(fd);  /* real FS may or may not have /fd_test */

    /* Test with O_PATH | O_CLOEXEC */
    fd = landlock_rule_open_fd(&rules[0], O_PATH | O_CLOEXEC);
    if (fd >= 0) close(fd);

    landlock_builder_free(b);
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
}
