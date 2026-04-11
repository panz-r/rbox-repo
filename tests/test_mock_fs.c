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
/*  Create dir / file / symlink                                        */
/* ------------------------------------------------------------------ */

static void test_mock_create_entries(void)
{
    struct stat st;

    /* Case 1: Create directories */
    mock_fs_reset();
    TEST_ASSERT_EQ(mock_fs_create_dir("/home"), 0, "create: create /home");
    TEST_ASSERT_EQ(mock_fs_create_dir("/home/user"), 0, "create: create /home/user");
    TEST_ASSERT_EQ(mock_fs_create_dir("/home"), -1, "create: duplicate dir fails");

    /* Case 2: Create file and verify with stat */
    mock_fs_reset();
    mock_fs_create_dir("/home/user");
    TEST_ASSERT_EQ(mock_fs_create_file("/home/user/file.txt"), 0,
                   "create: create file");
    TEST_ASSERT_EQ(stat("/home/user/file.txt", &st), 0,
                   "create: stat created file succeeds");
    TEST_ASSERT(S_ISREG(st.st_mode), "create: reports regular file");

    /* Case 3: Create symlink and verify resolution */
    mock_fs_reset();
    mock_fs_create_dir("/real");
    TEST_ASSERT_EQ(mock_fs_create_symlink("/link", "/real"), 0,
                   "create: create symlink");
    char *resolved = realpath("/link", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "create: realpath through symlink");
    TEST_ASSERT_STR_EQ(resolved, "/real", "create: symlink resolves correctly");
    free(resolved);
}

/* ------------------------------------------------------------------ */
/*  realpath: direct, symlink, dotdot, nonexistent                     */
/* ------------------------------------------------------------------ */

static void test_mock_realpath(void)
{
    char *resolved;

    /* Case 1: Direct path (no symlink) */
    mock_fs_reset();
    mock_fs_create_dir("/usr/lib");
    resolved = realpath("/usr/lib", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath: direct /usr/lib resolves");
    TEST_ASSERT_STR_EQ(resolved, "/usr/lib", "realpath: direct path unchanged");
    free(resolved);

    /* Case 2: Path through symlink */
    mock_fs_reset();
    mock_fs_create_dir("/real/target");
    mock_fs_create_symlink("/mylink", "/real/target");
    resolved = realpath("/mylink", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath: through symlink");
    TEST_ASSERT_STR_EQ(resolved, "/real/target", "realpath: symlink resolves to target");
    free(resolved);

    /* Case 3: realpath with .. components */
    mock_fs_reset();
    mock_fs_create_dir("/a/b/c");
    resolved = realpath("/a/b/../c", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "realpath: with ..");
    TEST_ASSERT_STR_EQ(resolved, "/a/c", "realpath: .. resolved correctly");
    free(resolved);

    /* Case 4: stat on nonexistent path returns -1 */
    mock_fs_reset();
    struct stat st;
    TEST_ASSERT_EQ(stat("/nonexistent", &st), -1, "realpath: stat nonexistent fails");
}

/* ------------------------------------------------------------------ */
/*  stat / lstat / readlink on mock entries                            */
/* ------------------------------------------------------------------ */

static void test_mock_stat_family(void)
{
    struct stat st;

    /* Case 1: stat on directory */
    mock_fs_reset();
    mock_fs_create_dir("/test_dir");
    TEST_ASSERT_EQ(stat("/test_dir", &st), 0, "stat: stat dir succeeds");
    TEST_ASSERT(S_ISDIR(st.st_mode), "stat: reports dir");

    /* Case 2: lstat on symlink */
    mock_fs_reset();
    mock_fs_create_symlink("/s", "/nowhere");
    TEST_ASSERT_EQ(lstat("/s", &st), 0, "lstat: lstat symlink succeeds");
    TEST_ASSERT(S_ISLNK(st.st_mode), "lstat: reports symlink");

    /* Case 3: readlink on symlink */
    mock_fs_reset();
    mock_fs_create_symlink("/mylink", "/some/target");
    char buf[PATH_MAX];
    ssize_t len = readlink("/mylink", buf, sizeof(buf));
    TEST_ASSERT(len > 0, "readlink: returns length");
    buf[len] = '\0';
    TEST_ASSERT_STR_EQ(buf, "/some/target", "readlink: target matches");
}

/* ------------------------------------------------------------------ */
/*  list_children and mock_fs_exists                                   */
/* ------------------------------------------------------------------ */

static void test_mock_query_apis(void)
{
    /* Case 1: list_children returns all entries */
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

    /* Case 2: mock_fs_exists returns correct types */
    mock_fs_reset();
    mock_fs_create_dir("/adir");
    mock_fs_create_file("/afile");
    mock_fs_create_symlink("/alink", "/adir");
    TEST_ASSERT_EQ(mock_fs_exists("/adir"), 1, "query: dir exists returns 1");
    TEST_ASSERT_EQ(mock_fs_exists("/afile"), 2, "query: file exists returns 2");
    TEST_ASSERT_EQ(mock_fs_exists("/alink"), 3, "query: symlink exists returns 3");
    TEST_ASSERT_EQ(mock_fs_exists("/nope"), 0, "query: nonexistent returns 0");
}

/* ------------------------------------------------------------------ */
/*  Symlink resolution: relative targets and chains                    */
/* ------------------------------------------------------------------ */

static void test_mock_symlink_resolution(void)
{
    char *resolved;

    /* Case 1: Relative symlink target */
    mock_fs_reset();
    mock_fs_create_dir("/dir");
    mock_fs_create_dir("/real/target");
    mock_fs_create_symlink("/dir/link", "../real/target");
    resolved = realpath("/dir/link", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "relative symlink resolves");
    TEST_ASSERT_STR_EQ(resolved, "/real/target", "relative target resolved correctly");
    free(resolved);

    /* Case 2: Symlink chain (a -> b -> c -> real) */
    mock_fs_reset();
    mock_fs_create_dir("/final");
    mock_fs_create_symlink("/c", "/final");
    mock_fs_create_symlink("/b", "/c");
    mock_fs_create_symlink("/a", "/b");
    resolved = realpath("/a", NULL);
    TEST_ASSERT_NOT_NULL(resolved, "chain resolves");
    TEST_ASSERT_STR_EQ(resolved, "/final", "chain resolves to final target");
    free(resolved);
}

/* ------------------------------------------------------------------ */

void test_mock_fs_run(void)
{
    printf("=== Mock Filesystem Tests ===\n");
    RUN_TEST(test_mock_create_entries);
    RUN_TEST(test_mock_realpath);
    RUN_TEST(test_mock_stat_family);
    RUN_TEST(test_mock_query_apis);
    RUN_TEST(test_mock_symlink_resolution);
}
