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
    mock_fs_create_dir("/home/user");
    TEST_ASSERT_EQ(mock_fs_create_file("/home/user/file.txt"), 0,
                   "create file");

    /* Verify the file is accessible via stat */
    struct stat st;
    TEST_ASSERT_EQ(stat("/home/user/file.txt", &st), 0,
                   "stat created file succeeds");
    TEST_ASSERT(S_ISREG(st.st_mode), "stat reports regular file");
}

static void test_mock_create_symlink(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/real");
    TEST_ASSERT_EQ(mock_fs_create_symlink("/link", "/real"), 0,
                   "create symlink");

    /* Verify the symlink resolves via realpath */
    char *resolved = realpath("/link", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath through created symlink");
    TEST_ASSERT_STR_EQ(resolved, "/real", "symlink resolves correctly");
    free(resolved);
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
/*  list_children                                                      */
/* ------------------------------------------------------------------ */

static void test_mock_list_children(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/root");
    mock_fs_create_dir("/root/alpha");
    mock_fs_create_dir("/root/beta");
    mock_fs_create_file("/root/file.txt");

    const char *names[16];
    int n = mock_fs_list_children("/root", names, 16);
    TEST_ASSERT_EQ(n, 3, "3 children of /root");

    int found_alpha = 0, found_beta = 0, found_file = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(names[i], "alpha") == 0) found_alpha = 1;
        if (strcmp(names[i], "beta") == 0) found_beta = 1;
        if (strcmp(names[i], "file.txt") == 0) found_file = 1;
    }
    TEST_ASSERT(found_alpha, "alpha found");
    TEST_ASSERT(found_beta, "beta found");
    TEST_ASSERT(found_file, "file.txt found");
}

static void test_mock_list_children_empty(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/empty_dir");

    const char *names[16];
    int n = mock_fs_list_children("/empty_dir", names, 16);
    TEST_ASSERT_EQ(n, 0, "empty directory has 0 children");
}

static void test_mock_list_children_not_a_dir(void)
{
    mock_fs_reset();
    mock_fs_create_file("/a_file");

    const char *names[16];
    int n = mock_fs_list_children("/a_file", names, 16);
    TEST_ASSERT_EQ(n, -1, "listing file returns -1");
}

static void test_mock_list_children_nonexistent(void)
{
    mock_fs_reset();
    const char *names[16];
    int n = mock_fs_list_children("/no_such_dir", names, 16);
    TEST_ASSERT_EQ(n, -1, "listing nonexistent dir returns -1");
}

/* ------------------------------------------------------------------ */
/*  mock_fs_exists                                                     */
/* ------------------------------------------------------------------ */

static void test_mock_exists(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/adir");
    mock_fs_create_file("/afile");
    mock_fs_create_symlink("/alink", "/adir");

    TEST_ASSERT_EQ(mock_fs_exists("/adir"), 1, "dir exists returns 1");
    TEST_ASSERT_EQ(mock_fs_exists("/afile"), 2, "file exists returns 2");
    TEST_ASSERT_EQ(mock_fs_exists("/alink"), 3, "symlink exists returns 3");
    TEST_ASSERT_EQ(mock_fs_exists("/nope"), 0, "nonexistent returns 0");
}

/* ------------------------------------------------------------------ */
/*  Relative symlink resolution                                        */
/* ------------------------------------------------------------------ */

static void test_mock_relative_symlink(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/real");
    mock_fs_create_dir("/real/target");
    /* Symlink with relative target: /link -> ../real/target */
    mock_fs_create_symlink("/dir/link", "../real/target");
    mock_fs_create_dir("/dir");

    /* Re-order: create dir first, then symlink. Actually the mock
     * doesn't require parent dirs for symlinks, so this works. */
    /* Need to recreate in correct order */
    mock_fs_reset();
    mock_fs_create_dir("/dir");
    mock_fs_create_dir("/real/target");
    mock_fs_create_symlink("/dir/link", "../real/target");

    char *resolved = realpath("/dir/link", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "relative symlink resolves");
    TEST_ASSERT_STR_EQ(resolved, "/real/target",
                       "relative symlink resolves correctly");
    free(resolved);
}

/* ------------------------------------------------------------------ */
/*  Symlink chain (a -> b -> c -> real)                                */
/* ------------------------------------------------------------------ */

static void test_mock_symlink_chain(void)
{
    mock_fs_reset();
    mock_fs_create_dir("/final");
    mock_fs_create_symlink("/c", "/final");
    mock_fs_create_symlink("/b", "/c");
    mock_fs_create_symlink("/a", "/b");

    char *resolved = realpath("/a", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "chain resolves");
    TEST_ASSERT_STR_EQ(resolved, "/final", "chain resolves to final target");
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
    RUN_TEST(test_mock_list_children);
    RUN_TEST(test_mock_list_children_empty);
    RUN_TEST(test_mock_list_children_not_a_dir);
    RUN_TEST(test_mock_list_children_nonexistent);
    RUN_TEST(test_mock_exists);
    RUN_TEST(test_mock_relative_symlink);
    RUN_TEST(test_mock_symlink_chain);
}
