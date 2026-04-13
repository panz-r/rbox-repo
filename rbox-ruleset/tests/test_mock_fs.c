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
/*  Entry creation: dir, file, symlink, stat, realpath, query APIs     */
/* ------------------------------------------------------------------ */

static void test_mock_fs_all(void)
{
    struct stat st;

    /* ---- entry creation: dir, file, symlink ---- */
    mock_fs_reset();
    TEST_ASSERT_EQ(mock_fs_create_dir("/home"), 0, "create: create /home");
    TEST_ASSERT_EQ(mock_fs_create_dir("/home/user"), 0, "create: create /home/user");
    TEST_ASSERT_EQ(mock_fs_create_dir("/home"), -1, "create: duplicate dir fails");

    mock_fs_create_dir("/home/user");
    TEST_ASSERT_EQ(mock_fs_create_file("/home/user/file.txt"), 0,
                   "create: create file");
    TEST_ASSERT_EQ(stat("/home/user/file.txt", &st), 0,
                   "create: stat created file succeeds");
    TEST_ASSERT(S_ISREG(st.st_mode), "create: reports regular file");

    mock_fs_create_dir("/real");
    TEST_ASSERT_EQ(mock_fs_create_symlink("/link", "/real"), 0,
                   "create: create symlink");

    /* ---- stat / lstat on created entries ---- */
    mock_fs_reset();
    mock_fs_create_dir("/test_dir");
    TEST_ASSERT_EQ(stat("/test_dir", &st), 0, "stat: stat dir succeeds");
    TEST_ASSERT(S_ISDIR(st.st_mode), "stat: reports dir");

    mock_fs_create_symlink("/s", "/nowhere");
    TEST_ASSERT_EQ(lstat("/s", &st), 0, "lstat: lstat symlink succeeds");
    TEST_ASSERT(S_ISLNK(st.st_mode), "lstat: reports symlink");

    mock_fs_create_symlink("/mylink", "/some/target");
    char rdbuf[PATH_MAX];
    ssize_t rlen = readlink("/mylink", rdbuf, sizeof(rdbuf));
    TEST_ASSERT(rlen > 0, "readlink: returns length");
    rdbuf[rlen] = '\0';
    TEST_ASSERT_STR_EQ(rdbuf, "/some/target", "readlink: target matches");

    /* ---- realpath: direct, through symlink, .., nonexistent ---- */
    mock_fs_reset();
    mock_fs_create_dir("/usr/lib");
    char *resolved = realpath("/usr/lib", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath: direct /usr/lib resolves");
    TEST_ASSERT_STR_EQ(resolved, "/usr/lib", "realpath: direct path unchanged");
    free(resolved);

    mock_fs_create_dir("/real/target");
    mock_fs_create_symlink("/mylink", "/real/target");
    resolved = realpath("/mylink", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath: through symlink");
    TEST_ASSERT_STR_EQ(resolved, "/real/target", "realpath: symlink resolves to target");
    free(resolved);

    mock_fs_create_dir("/a/b/c");
    resolved = realpath("/a/b/../c", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath: with ..");
    TEST_ASSERT_STR_EQ(resolved, "/a/c", "realpath: .. resolved correctly");
    free(resolved);

    mock_fs_reset();
    TEST_ASSERT_EQ(stat("/nonexistent", &st), -1, "realpath: stat nonexistent fails");

    /* ---- query APIs: list_children, mock_fs_exists ---- */
    mock_fs_reset();
    mock_fs_create_dir("/root");
    mock_fs_create_dir("/root/alpha");
    mock_fs_create_dir("/root/beta");
    mock_fs_create_file("/root/file.txt");
    const char *names[16];
    int n = mock_fs_list_children("/root", names, 16);
    TEST_ASSERT_EQ(n, 3, "query: 3 children of /root");
    int found_alpha = 0, found_beta = 0, found_file = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(names[i], "alpha") == 0) found_alpha = 1;
        if (strcmp(names[i], "beta") == 0) found_beta = 1;
        if (strcmp(names[i], "file.txt") == 0) found_file = 1;
    }
    TEST_ASSERT(found_alpha, "query: alpha found");
    TEST_ASSERT(found_beta, "query: beta found");
    TEST_ASSERT(found_file, "query: file.txt found");

    mock_fs_create_dir("/adir");
    mock_fs_create_file("/afile");
    mock_fs_create_symlink("/alink", "/adir");
    TEST_ASSERT_EQ(mock_fs_exists("/adir"), 1, "query: dir exists returns 1");
    TEST_ASSERT_EQ(mock_fs_exists("/afile"), 2, "query: file exists returns 2");
    TEST_ASSERT_EQ(mock_fs_exists("/alink"), 3, "query: symlink exists returns 3");
    TEST_ASSERT_EQ(mock_fs_exists("/nope"), 0, "query: nonexistent returns 0");

    /* ---- symlink resolution: relative targets and chains ---- */
    mock_fs_reset();
    mock_fs_create_dir("/dir");
    mock_fs_create_dir("/real/target");
    mock_fs_create_symlink("/dir/link", "../real/target");
    resolved = realpath("/dir/link", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "relative symlink resolves");
    TEST_ASSERT_STR_EQ(resolved, "/real/target", "relative target resolved correctly");
    free(resolved);

    mock_fs_create_dir("/final");
    mock_fs_create_symlink("/c", "/final");
    mock_fs_create_symlink("/b", "/c");
    mock_fs_create_symlink("/a", "/b");
    resolved = realpath("/a", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "chain resolves");
    TEST_ASSERT_STR_EQ(resolved, "/final", "chain resolves to final target");
    free(resolved);

    /* ---- mock_fs_active lifecycle ---- */
    TEST_ASSERT(mock_fs_active(), "mock is active after setup");
    mock_fs_reset();
    TEST_ASSERT(mock_fs_active(), "mock remains active after reset");
}

/* ------------------------------------------------------------------ */

void test_mock_fs_run(void)
{
    printf("=== Mock Filesystem Tests ===\n");
    RUN_TEST(test_mock_fs_all);
}
