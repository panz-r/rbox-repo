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

static void test_is_vfs_all_cases(void)
{
    /* Table-driven test: { path, expected, description } */
    static const struct {
        const char *path;
        int expected;
        const char *desc;
    } cases[] = {
        /* /proc paths */
        { "/proc",            1, "/proc is VFS" },
        { "/proc/",           1, "/proc/ is VFS" },
        { "/proc/1",          1, "/proc/1 is VFS" },
        { "/proc/1/fd",       1, "/proc/1/fd is VFS" },
        { "/proc/self",       1, "/proc/self is VFS" },
        { "/proc/cpuinfo",    1, "/proc/cpuinfo is VFS" },

        /* /sys paths */
        { "/sys",             1, "/sys is VFS" },
        { "/sys/",            1, "/sys/ is VFS" },
        { "/sys/kernel",      1, "/sys/kernel is VFS" },
        { "/sys/fs/cgroup",   1, "/sys/fs/cgroup is VFS" },
        { "/sys/devices",     1, "/sys/devices is VFS" },

        /* Non-VFS paths */
        { "/home",            0, "/home is not VFS" },
        { "/usr/lib",         0, "/usr/lib is not VFS" },
        { "/etc/passwd",      0, "/etc/passwd is not VFS" },
        { "/dev/null",        0, "/dev/null is not VFS (devtmpfs is Landlock-compatible)" },
        { "/var/log",         0, "/var/log is not VFS" },
        { "/",                0, "root / is not VFS" },
        { "/procurement",     0, "/procurement is not VFS (not /proc)" },
        { "/system",          0, "/system is not VFS (not /sys)" },
        { "/sysadmin",        0, "/sysadmin is not VFS" },

        /* Edge cases */
        { NULL,               0, "NULL path returns 0" },
        { "",                 0, "empty path returns 0" },
        { "proc",             0, "relative 'proc' is not VFS" },
        { "sys",              0, "relative 'sys' is not VFS" },
    };

    const int n = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < n; i++) {
        TEST_ASSERT_EQ(landlock_path_is_vfs(cases[i].path), cases[i].expected, cases[i].desc);
    }
}

/* ------------------------------------------------------------------ */
/*  Builder VFS filtering: allow, deny, subdirs, mixed                 */
/* ------------------------------------------------------------------ */

static void test_vfs_filtering(void)
{
    landlock_builder_t *b;
    size_t count;
    int found;

    /* Case 1: Allow VFS paths silently skipped */
    mock_fs_reset();
    b = landlock_builder_new();
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/home", 7), 0,
                   "vfs: allow /home succeeds");
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/proc", 7), 0,
                   "vfs: allow /proc returns 0 (skipped)");
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/proc/1", 7), 0,
                   "vfs: allow /proc/1 returns 0 (skipped)");
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/sys", 3), 0,
                   "vfs: allow /sys returns 0 (skipped)");
    TEST_ASSERT_EQ(landlock_builder_allow(b, "/sys/kernel", 3), 0,
                   "vfs: allow /sys/kernel returns 0 (skipped)");
    landlock_builder_prepare(b, 2, false);
    count = 0;
    const landlock_rule_t *rules1 = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "vfs: only non-VFS rule present");
    if (count >= 1) {
        TEST_ASSERT_STR_EQ(rules1[0].path, "/home", "vfs: rule is /home");
    }
    landlock_builder_free(b);

    /* Case 2: Deny VFS paths silently skipped */
    mock_fs_reset();
    b = landlock_builder_new();
    landlock_builder_allow(b, "/home", 7);
    landlock_builder_deny(b, "/home/secret");
    TEST_ASSERT_EQ(landlock_builder_deny(b, "/proc"), 0,
                   "vfs: deny /proc returns 0 (skipped)");
    TEST_ASSERT_EQ(landlock_builder_deny(b, "/sys"), 0,
                   "vfs: deny /sys returns 0 (skipped)");
    landlock_builder_prepare(b, 2, false);
    count = 0;
    const landlock_rule_t *rules2 = landlock_builder_get_rules(b, &count);
    int found_home = 0, found_secret = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules2[i].path, "/home") == 0) found_home = 1;
        if (strstr(rules2[i].path, "secret")) found_secret = 1;
    }
    TEST_ASSERT(found_home, "vfs: /home present");
    TEST_ASSERT(!found_secret, "vfs: /home/secret denied");
    landlock_builder_free(b);

    /* Case 3: VFS subdirectories all denied */
    mock_fs_reset();
    b = landlock_builder_new();
    landlock_builder_allow(b, "/proc/self/fd", 7);
    landlock_builder_allow(b, "/proc/1/cmdline", 7);
    landlock_builder_allow(b, "/sys/kernel/security", 7);
    landlock_builder_allow(b, "/sys/fs/cgroup/memory", 7);
    landlock_builder_allow(b, "/tmp", 7);
    landlock_builder_prepare(b, 2, false);
    count = 0;
    const landlock_rule_t *rules3 = landlock_builder_get_rules(b, &count);
    TEST_ASSERT_EQ(count, 1, "vfs: only /tmp present after filtering");
    if (count >= 1) {
        TEST_ASSERT_STR_EQ(rules3[0].path, "/tmp", "vfs: rule is /tmp");
    }
    landlock_builder_free(b);

    /* Case 4: Mixed VFS and real paths in single policy */
    mock_fs_reset();
    mock_fs_create_dir("/data");
    mock_fs_create_dir("/config");
    b = landlock_builder_new();
    landlock_builder_allow(b, "/proc/cpuinfo", 1);
    landlock_builder_allow(b, "/data", 7);
    landlock_builder_allow(b, "/sys/devices", 3);
    landlock_builder_allow(b, "/config", 3);
    landlock_builder_allow(b, "/proc/meminfo", 1);
    landlock_builder_deny(b, "/config/secret");
    landlock_builder_deny(b, "/sys");  /* VFS — should be skipped */
    landlock_builder_prepare(b, 2, false);
    count = 0;
    const landlock_rule_t *rules4 = landlock_builder_get_rules(b, &count);
    found = 0;
    int found_config = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules4[i].path, "/data") == 0) found = 1;
        if (strcmp(rules4[i].path, "/config") == 0) found_config = 1;
    }
    TEST_ASSERT(found, "vfs: /data present");
    TEST_ASSERT(found_config, "vfs: /config present");
    TEST_ASSERT_EQ(count, 2, "vfs: exactly 2 non-VFS rules");
    landlock_builder_free(b);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_vfs_filter_run(void)
{
    printf("=== VFS Filter Tests ===\n");
    RUN_TEST(test_is_vfs_all_cases);
    RUN_TEST(test_vfs_filtering);
}
