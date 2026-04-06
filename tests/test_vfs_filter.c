/**
 * @file test_vfs_filter.c
 * @brief Unit tests for virtual filesystem path filtering.
 */

#include "test_framework.h"
#include "mock_fs.h"
#include "landlock_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  landlock_path_is_vfs() direct tests                                */
/* ------------------------------------------------------------------ */

static void test_is_vfs_proc(void)
{
    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc"), 1, "/proc is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc/"), 1, "/proc/ is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc/1"), 1, "/proc/1 is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc/1/fd"), 1, "/proc/1/fd is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc/self"), 1, "/proc/self is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/proc/cpuinfo"), 1,
                   "/proc/cpuinfo is VFS");
}

static void test_is_vfs_sys(void)
{
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sys"), 1, "/sys is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sys/"), 1, "/sys/ is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sys/kernel"), 1,
                   "/sys/kernel is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sys/fs/cgroup"), 1,
                   "/sys/fs/cgroup is VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sys/devices"), 1,
                   "/sys/devices is VFS");
}

static void test_is_vfs_not_vfs(void)
{
    TEST_ASSERT_EQ(landlock_path_is_vfs("/home"), 0, "/home is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/usr/lib"), 0, "/usr/lib is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/etc/passwd"), 0,
                   "/etc/passwd is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/dev/null"), 0,
                   "/dev/null is not VFS (devtmpfs is Landlock-compatible)");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/var/log"), 0,
                   "/var/log is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/"), 0, "root / is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/procurement"), 0,
                   "/procurement is not VFS (not /proc)");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/system"), 0,
                   "/system is not VFS (not /sys)");
    TEST_ASSERT_EQ(landlock_path_is_vfs("/sysadmin"), 0,
                   "/sysadmin is not VFS");
}

static void test_is_vfs_edge_cases(void)
{
    TEST_ASSERT_EQ(landlock_path_is_vfs(NULL), 0, "NULL path returns 0");
    TEST_ASSERT_EQ(landlock_path_is_vfs(""), 0, "empty path returns 0");
    TEST_ASSERT_EQ(landlock_path_is_vfs("proc"), 0,
                   "relative 'proc' is not VFS");
    TEST_ASSERT_EQ(landlock_path_is_vfs("sys"), 0,
                   "relative 'sys' is not VFS");
}

/* ------------------------------------------------------------------ */
/*  Builder allow/deny with VFS paths                                 */
/* ------------------------------------------------------------------ */

static void test_allow_vfs_silently_skipped(void)
{
    mock_fs_reset();
    /* Note: we don't need to create /proc or /sys in the mock fs
     * because the VFS check happens before canonicalisation. */

    landlock_builder_t *b = landlock_builder_new();

    /* Allow a real path first */
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/home", 7), 0,
                   "allow /home succeeds");

    /* Allow VFS paths — should return 0 (not -1) but add no rules */
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/proc", 7), 0,
                   "allow /proc returns 0 (skipped)");
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/proc/1", 7), 0,
                   "allow /proc/1 returns 0 (skipped)");
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/sys", 3), 0,
                   "allow /sys returns 0 (skipped)");
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/sys/kernel", 3), 0,
                   "allow /sys/kernel returns 0 (skipped)");

    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* Only /home should be present */
    TEST_ASSERT_EQ(count, 1, "only non-VFS rule present");
    if (count >= 1) {
        TEST_ASSERT_STR_EQ(rules[0].path, "/home", "rule is /home");
    }

    landlock_builder_free(b);
}

static void test_deny_vfs_silently_skipped(void)
{
    mock_fs_reset();

    landlock_builder_t *b = landlock_builder_new();

    landlock_builder_allow(b, "/home", 7);
    landlock_builder_deny(b, "/home/secret");

    /* Deny on VFS path — should be silently ignored */
    TEST_ASSERT_EQ(landlock_builder_deny(b, "/proc"), 0,
                   "deny /proc returns 0 (skipped)");
    TEST_ASSERT_EQ(landlock_builder_deny(b, "/sys"), 0,
                   "deny /sys returns 0 (skipped)");

    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* /home should survive; /home/secret should be denied */
    int found_home = 0, found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/home") == 0) found_home = 1;
        if (strstr(rules[i].path, "secret")) found_secret = 1;
    }
    TEST_ASSERT(found_home, "/home present");
    TEST_ASSERT(!found_secret, "/home/secret denied");

    landlock_builder_free(b);
}

static void test_vfs_subdirectories_all_denied(void)
{
    mock_fs_reset();

    landlock_builder_t *b = landlock_builder_new();

    /* Try to allow various /proc and /sys subpaths */
    landlock_builder_allow(b, "/proc/self/fd", 7);
    landlock_builder_allow(b, "/proc/1/cmdline", 7);
    landlock_builder_allow(b, "/sys/kernel/security", 7);
    landlock_builder_allow(b, "/sys/fs/cgroup/memory", 7);

    /* Also allow a real path */
    landlock_builder_allow(b, "/tmp", 7);

    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    /* Only /tmp should be present */
    TEST_ASSERT_EQ(count, 1, "only /tmp present after VFS filtering");
    if (count >= 1) {
        TEST_ASSERT_STR_EQ(rules[0].path, "/tmp", "rule is /tmp");
    }

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Integration: mixed VFS and non-VFS in single policy               */
/* ------------------------------------------------------------------ */

static void test_mixed_vfs_and_real_paths(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/data");
    mock_fs_create_dir("/config");

    landlock_builder_t *b = landlock_builder_new();

    /* Interleave VFS and real paths */
    landlock_builder_allow(b, "/proc/cpuinfo", 1);
    landlock_builder_allow(b, "/data", 7);
    landlock_builder_allow(b, "/sys/devices", 3);
    landlock_builder_allow(b, "/config", 3);
    landlock_builder_allow(b, "/proc/meminfo", 1);
    landlock_builder_deny(b, "/config/secret");
    landlock_builder_deny(b, "/sys");  /* VFS — should be skipped */

    landlock_builder_prepare(b, 2, false);

    size_t count = 0;
    const landlock_rule_t *rules = landlock_builder_get_rules(b, &count);

    int found_data = 0, found_config = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].path, "/data") == 0) found_data = 1;
        if (strcmp(rules[i].path, "/config") == 0) found_config = 1;
    }
    TEST_ASSERT(found_data, "/data present");
    TEST_ASSERT(found_config, "/config present");
    TEST_ASSERT_EQ(count, 2, "exactly 2 non-VFS rules");

    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_vfs_filter_run(void)
{
    printf("=== VFS Filter Tests ===\n");
    RUN_TEST(test_is_vfs_proc);
    RUN_TEST(test_is_vfs_sys);
    RUN_TEST(test_is_vfs_not_vfs);
    RUN_TEST(test_is_vfs_edge_cases);
    RUN_TEST(test_allow_vfs_silently_skipped);
    RUN_TEST(test_deny_vfs_silently_skipped);
    RUN_TEST(test_vfs_subdirectories_all_denied);
    RUN_TEST(test_mixed_vfs_and_real_paths);
}
