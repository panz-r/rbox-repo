/**
 * @file test_mock_fs.c
 * @brief Unit tests for the mock filesystem itself.
 */

#define _DEFAULT_SOURCE
#include "test_framework.h"
#include "mock_fs.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/param.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <sys/stat.h>

/* ------------------------------------------------------------------ */

static void test_mock_create_dir(void)
{
    mock_fs_reset();
    TEST_ASSERT_EQ(mock_fs_create_dir("/home"), 0, "create /home");
    TEST_ASSERT_EQ(mock_fs_create_dir("/home/user"), 0, "create /home/user");

    /* Duplicate should fail */
    TEST_ASSERT_EQ(mock_fs_create_dir("/home"), -1, "duplicate dir fails");
}

static void test_mock_create_file(void)
{
    mock_fs_reset();
    TEST_ASSERT_EQ(mock_fs_create_file("/home/user/file.txt"), 0,
                   "create file");
}

static void test_mock_create_symlink(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/real");
    TEST_ASSERT_EQ(mock_fs_create_symlink("/link", "/real"), 0,
                   "create symlink");
}

static void test_mock_realpath_regular(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/usr/lib");

    char *resolved = realpath("/usr/lib", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath /usr/lib");
    TEST_ASSERT_STR_EQ(resolved, "/usr/lib", "resolved path");
    free(resolved);
}

static void test_mock_realpath_symlink(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/real/target");
    mock_fs_create_symlink("/mylink", "/real/target");

    char *resolved = realpath("/mylink", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath through symlink");
    TEST_ASSERT_STR_EQ(resolved, "/real/target", "symlink resolved");
    free(resolved);
}

static void test_mock_stat(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/test_dir");

    struct stat st;
    TEST_ASSERT_EQ(stat("/test_dir", &st), 0, "stat dir");
    TEST_ASSERT(S_ISDIR(st.st_mode), "stat reports dir");
}

static void test_mock_lstat_symlink(void)
{
    mock_fs_reset();
    mock_fs_create_symlink("/s", "/nowhere");

    struct stat st;
    TEST_ASSERT_EQ(lstat("/s", &st), 0, "lstat symlink");
    TEST_ASSERT(S_ISLNK(st.st_mode), "lstat reports symlink");
}

static void test_mock_readlink(void)
{
    mock_fs_reset();
    mock_fs_create_symlink("/mylink", "/some/target");

    char buf[PATH_MAX];
    ssize_t len = readlink("/mylink", buf, sizeof(buf));
    TEST_ASSERT(len > 0, "readlink returns length");
    buf[len] = '\0';
    TEST_ASSERT_STR_EQ(buf, "/some/target", "readlink target");
}

static void test_mock_nonexistent(void)
{
    mock_fs_reset();

    struct stat st;
    TEST_ASSERT_EQ(stat("/nonexistent", &st), -1, "stat nonexistent");
}

static void test_mock_dotdot_resolution(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/a/b/c");

    char *resolved = realpath("/a/b/../c", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath with ..");
    TEST_ASSERT_STR_EQ(resolved, "/a/c", "resolved .. correctly");
    free(resolved);
}

/* ------------------------------------------------------------------ */

void test_mock_fs_run(void)
{
    printf("=== Mock Filesystem Tests ===\n");
    RUN_TEST(test_mock_create_dir);
    RUN_TEST(test_mock_create_file);
    RUN_TEST(test_mock_create_symlink);
    RUN_TEST(test_mock_realpath_regular);
    RUN_TEST(test_mock_realpath_symlink);
    RUN_TEST(test_mock_stat);
    RUN_TEST(test_mock_lstat_symlink);
    RUN_TEST(test_mock_readlink);
    RUN_TEST(test_mock_nonexistent);
    RUN_TEST(test_mock_dotdot_resolution);
}
