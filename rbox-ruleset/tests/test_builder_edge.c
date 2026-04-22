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
/*  Builder lifecycle: edge cases, re-prepare, deny behavior           */
/* ------------------------------------------------------------------ */

static void test_builder_lifecycle_and_deny(void)
{
    landlock_builder_t *b;

    /* ---- lifecycle edge cases ---- */

    /* Save on unprepared builder must fail */
    mock_fs_reset();
    mock_fs_create_dir("/data");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 7);
    TEST_ASSERT_EQ(landlock_builder_save(b, "/tmp/unprepared.json"), -1,
                   "save on unprepared builder fails");
    landlock_builder_free(b);

    /* Prepare with invalid ABI versions must fail */
    mock_fs_reset();
    mock_fs_create_dir("/data");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 7);
    TEST_ASSERT_EQ(landlock_builder_prepare(b, 0, false), -1,
                   "prepare ABI 0 fails");
    TEST_ASSERT_EQ(landlock_builder_prepare(b, -1, false), -1,
                   "prepare ABI -1 fails");
    TEST_ASSERT_EQ(landlock_builder_prepare(b, 99, false), 0,
                   "prepare ABI 99 succeeds (clamped to LANDLOCK_ABI_MAX)");
    landlock_builder_free(b);

    /* Allow with LL_FS_ALL gets masked to ABI v4 */
    mock_fs_reset();
    mock_fs_create_dir("/data");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/data", LL_FS_ALL);
    landlock_builder_prepare(b, 4, false);
    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "LL_FS_ALL: one rule");
    uint64_t expected = landlock_abi_mask(4);
    TEST_ASSERT_EQ(rules[0].access, expected, "LL_FS_ALL: access masked to ABI v4");
    landlock_builder_free(b);

    /* ---- re-prepare after allow ---- */
    mock_fs_reset();
    mock_fs_create_dir("/a");
    mock_fs_create_dir("/b");

    b = landlock_builder_new();
    landlock_builder_allow(b, "/a", 7);
    landlock_builder_prepare(b, 2, false);

    size_t c1 = 0;
    landlock_builder_get_rules(b, &c1);
    TEST_ASSERT_EQ(c1, 1, "reprepare: first prepare yields 1 rule");

    landlock_builder_allow(b, "/b", 3);
    size_t c2 = 0;
    landlock_builder_get_rules(b, &c2);
    TEST_ASSERT_EQ(c2, 0, "reprepare: after allow, rules cleared");

    landlock_builder_prepare(b, 2, false);
    size_t c3 = 0;
    const landlock_rule_t *r3 = landlock_builder_get_rules(b, &c3);
    TEST_ASSERT_EQ(c3, 2, "reprepare: both rules present");

    int found_a = 0, found_b = 0;
    for (size_t i = 0; i < c3; i++) {
        if (strcmp(r3[i].path, "/a") == 0) {
            found_a = 1;
            TEST_ASSERT_EQ(r3[i].access, 7, "reprepare: /a access correct");
        }
        if (strcmp(r3[i].path, "/b") == 0) {
            found_b = 1;
            TEST_ASSERT_EQ(r3[i].access, 3, "reprepare: /b access correct");
        }
    }
    TEST_ASSERT(found_a, "reprepare: found /a");
    TEST_ASSERT(found_b, "reprepare: found /b");
    landlock_builder_free(b);

    /* ---- deny behavior during overlap removal and simplify ---- */

    /* Intermediate deny clears deeper allow */
    mock_fs_reset();
    mock_fs_create_dir("/a");
    mock_fs_create_dir("/a/b");
    mock_fs_create_dir("/a/b/c");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/a/b/c", 7);
    landlock_builder_deny(b, "/a/b");
    landlock_builder_allow(b, "/a", 7);
    landlock_builder_prepare(b, 2, false);
    count = 0;
    const landlock_rule_t *rules1 = landlock_builder_get_rules(b, &count);
    int found_c = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules1[i].path, "/a/b/c")) found_c = 1;
    }
    TEST_ASSERT(!found_c, "deny: deeper allow cleared by intermediate deny");
    int found_a2 = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules1[i].path, "/a") == 0) found_a2 = 1;
    }
    TEST_ASSERT(found_a2, "deny: /a survives");

    /* Deny at same path clears allow */
    landlock_builder_free(b);
    mock_fs_reset();
    mock_fs_create_dir("/data");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/data", 7);
    landlock_builder_deny(b, "/data");
    landlock_builder_prepare(b, 2, false);
    count = 0;
    (void)landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 0, "deny: deny at same path clears allow");

    /* Simplify: child with deny grandchild not pruned */
    landlock_builder_free(b);
    mock_fs_reset();
    mock_fs_create_dir("/a");
    mock_fs_create_dir("/a/b");
    mock_fs_create_dir("/a/b/secret");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/a", 7);
    landlock_builder_allow(b, "/a/b", 7);
    landlock_builder_deny(b, "/a/b/secret");
    landlock_builder_prepare(b, 2, false);
    count = 0;
    const landlock_rule_t *rules3 = landlock_builder_get_rules(b, &count);
    int found_b2 = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules3[i].path, "/a/b") == 0) found_b2 = 1;
    }
    TEST_ASSERT(found_b2, "deny: child with deny grandchild not pruned");

    landlock_builder_free(b);

    /* ---- symlink expansion when source has no matching rule ---- */
    mock_fs_reset();
    mock_fs_create_dir("/real/target");
    mock_fs_create_dir("/other/place");
    mock_fs_create_symlink("/other/place/link", "/real/target");

    b = landlock_builder_new();
    landlock_builder_allow(b, "/unrelated", 7);
    landlock_builder_prepare(b, 2, true);

    count = 0;
    const landlock_rule_t *rules4 = landlock_builder_get_rules(b, &count);
    int found_unrelated = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules4[i].path, "/unrelated") == 0) found_unrelated = 1;
    }
    TEST_ASSERT(found_unrelated, "no-match: /unrelated rule present");

    int found_target = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(rules4[i].path, "/real/target")) found_target = 1;
    }
    TEST_ASSERT(!found_target,
                "no-match: symlink target not added when source has no matching rule");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Load failures: empty, nonexistent, malformed                        */
/* ------------------------------------------------------------------ */

static void test_load_failures(void)
{
    landlock_builder_t *b;
    FILE *f = fopen("/tmp/empty.json", "w");
    if (f) fclose(f);
    b = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b, "/tmp/empty.json"), -1,
                   "load empty file fails");
    landlock_builder_free(b);
    remove("/tmp/empty.json");

    b = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b, "/nonexistent/path.json"), -1,
                   "load nonexistent file fails");
    landlock_builder_free(b);

    f = fopen("/tmp/malformed.json", "w");
    if (f) {
        fprintf(f, "{ \"rules\": [] }");
        fclose(f);
    }
    b = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_load(b, "/tmp/malformed.json"), -1,
                   "JSON without abi_version rejected");
    landlock_builder_free(b);
    remove("/tmp/malformed.json");
}

/* ------------------------------------------------------------------ */
/*  O_PATH fd with explicit flags                                      */
/* ------------------------------------------------------------------ */

static void test_open_fd_with_flags(void)
{
    char tmpl[] = "/tmp/llb_fd_test_XXXXXX";
    char *real_dir = mkdtemp(tmpl);
    TEST_ASSERT_NOT_NULL(real_dir, "mkdtemp creates real directory");

    landlock_builder_t *b = landlock_builder_new();
    landlock_builder_allow(b, real_dir, 7);
    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "exactly one rule");
    TEST_ASSERT_STR_EQ(rules[0].path, real_dir, "rule path is temp dir");

    int fd = landlock_rule_open_fd(&rules[0], 0);
    TEST_ASSERT(fd >= 0, "open_fd with default flags succeeds");
    close(fd);

    fd = landlock_rule_open_fd(&rules[0], O_RDONLY);
    TEST_ASSERT(fd >= 0, "open_fd with O_RDONLY succeeds");
    close(fd);

    fd = landlock_rule_open_fd(&rules[0], O_PATH | O_CLOEXEC);
    TEST_ASSERT(fd >= 0, "open_fd with O_PATH|O_CLOEXEC succeeds");
    close(fd);

    landlock_builder_free(b);
    rmdir(real_dir);
}

/* ------------------------------------------------------------------ */
/*  VFS path classification                                             */
/* ------------------------------------------------------------------ */

static void test_vfs_path_classification(void)
{
    TEST_ASSERT_EQ(landlock_path_is_vfs("proc/bar"), 0,
                   "relative 'proc/bar' is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("sys/foo"), 0,
                   "relative 'sys/foo' is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("./proc"), 0,
                   "relative './proc' is not VFS");

    TEST_ASSERT_EQ(landlock_path_is_vfs("/pro"), 0, "/pro is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sy"), 0, "/sy is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc.bak"), 0, "/proc.bak is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sys.bak"), 0, "/sys.bak is not VFS");

    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc"), 1, "/proc is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sys"), 1, "/sys is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc/"), 1, "/proc/ is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sys/"), 1, "/sys/ is VFS");
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_builder_edge_run(void)
{
    printf("=== Builder Edge-Case Tests ===\n");
    RUN_TEST(test_builder_lifecycle_and_deny);
    RUN_TEST(test_load_failures);
    RUN_TEST(test_open_fd_with_flags);
    RUN_TEST(test_vfs_path_classification);
}
