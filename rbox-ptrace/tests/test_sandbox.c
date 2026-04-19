/*
 * test_sandbox.c - Unit tests for sandbox parsing logic
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <linux/landlock.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "../sandbox.h"
#include "test_utils.h"

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE 0
#endif

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static int test_##name(void)

#define RUN_TEST(name) do { \
    printf("  Running %s... ", #name); \
    fflush(stdout); \
    tests_run++; \
    if (test_##name() == 0) { \
        printf("PASSED\n"); \
        tests_passed++; \
    } else { \
        printf("FAILED\n"); \
        tests_failed++; \
    } \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        return 1; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT(((a) == (b)))
#define ASSERT_NE(a, b) ASSERT(((a) != (b)))
#define ASSERT_NULL(p) ASSERT(((p) == NULL))
#define ASSERT_NOT_NULL(p) ASSERT(((p) != NULL))
#define ASSERT_STR_EQ(a, b) ASSERT((strcmp((a), (b)) == 0))

static bool mock_always_valid(const char *path, void *ctx) {
    (void)path; (void)ctx;
    return true;
}

/* ==================== parse_access_mode tests ==================== */

TEST(access_mode_ro) {
    uint64_t result = sandbox_parse_access_mode("ro");
    ASSERT_EQ(result, LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
    return 0;
}

TEST(access_mode_rx) {
    uint64_t result = sandbox_parse_access_mode("rx");
    uint64_t expected = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    ASSERT_EQ(result, expected);
    return 0;
}

TEST(access_mode_rw) {
    uint64_t result = sandbox_parse_access_mode("rw");
    ASSERT(result & LANDLOCK_ACCESS_FS_READ_FILE);
    ASSERT(result & LANDLOCK_ACCESS_FS_READ_DIR);
    ASSERT(result & LANDLOCK_ACCESS_FS_WRITE_FILE);
    ASSERT(result & LANDLOCK_ACCESS_FS_REMOVE_DIR);
    ASSERT(result & LANDLOCK_ACCESS_FS_REMOVE_FILE);
    ASSERT(result & LANDLOCK_ACCESS_FS_MAKE_DIR);
    ASSERT(result & LANDLOCK_ACCESS_FS_MAKE_REG);
#if LANDLOCK_ACCESS_FS_TRUNCATE != 0
    ASSERT(result & LANDLOCK_ACCESS_FS_TRUNCATE);
#endif
    return 0;
}

TEST(access_mode_rwx) {
    uint64_t result = sandbox_parse_access_mode("rwx");
    uint64_t expected = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                        LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |
                        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_TRUNCATE |
                        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                        LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                        LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER;
    ASSERT_EQ(result, expected);
    return 0;
}

TEST(access_mode_unknown) {
    uint64_t result = sandbox_parse_access_mode("xyz");
    uint64_t expected = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    ASSERT_EQ(result, expected);
    return 0;
}

TEST(access_mode_empty) {
    uint64_t result = sandbox_parse_access_mode("");
    uint64_t expected = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    ASSERT_EQ(result, expected);
    return 0;
}

/* ==================== sandbox_parse_allow_list tests ==================== */

TEST(allow_list_null) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list(NULL, &count, mock_always_valid, NULL);
    ASSERT_NULL(result);
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(allow_list_empty) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list("", &count, mock_always_valid, NULL);
    ASSERT_NULL(result);
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(allow_list_single) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list("/tmp", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(result[0].original, "/tmp");
    sandbox_free_allow_entries(result, count);
    return 0;
}

TEST(allow_list_single_default_mode) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list("/tmp", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(result[0].access, sandbox_parse_access_mode("rx"));
    sandbox_free_allow_entries(result, count);
    return 0;
}

TEST(allow_list_multiple) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list("/tmp:ro,/usr:rw", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 2);
    ASSERT_EQ(result[0].access, sandbox_parse_access_mode("ro"));
    ASSERT_EQ(result[1].access, sandbox_parse_access_mode("rw"));
    sandbox_free_allow_entries(result, count);
    return 0;
}

TEST(allow_list_mode_suffix_parsing) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list("/tmp:ro,/usr:rw,/bin:rx,/lib:rwx", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 4);
    ASSERT_EQ(result[0].access, sandbox_parse_access_mode("ro"));
    ASSERT_EQ(result[1].access, sandbox_parse_access_mode("rw"));
    ASSERT_EQ(result[2].access, sandbox_parse_access_mode("rx"));
    ASSERT_EQ(result[3].access, sandbox_parse_access_mode("rwx"));
    sandbox_free_allow_entries(result, count);
    return 0;
}

/* ==================== sandbox_parse_deny_list tests ==================== */

TEST(deny_list_null) {
    int count = -1;
    struct denied_entry *result = sandbox_parse_deny_list(NULL, &count, mock_always_valid, NULL);
    ASSERT_NULL(result);
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(deny_list_empty) {
    int count = -1;
    struct denied_entry *result = sandbox_parse_deny_list("", &count, mock_always_valid, NULL);
    ASSERT_NULL(result);
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(deny_list_single) {
    int count = -1;
    struct denied_entry *result = sandbox_parse_deny_list("/tmp", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(result[0].original, "/tmp");
    sandbox_free_deny_entries(result, count);
    return 0;
}

TEST(deny_list_multiple) {
    int count = -1;
    struct denied_entry *result = sandbox_parse_deny_list("/tmp,/usr", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 2);
    sandbox_free_deny_entries(result, count);
    return 0;
}

/* ==================== Test suite runner ==================== */

void run_sandbox_tests(void) {
    printf("\n=== Sandbox Tests ===\n");
    tests_run = tests_passed = tests_failed = 0;

    RUN_TEST(access_mode_ro);
    RUN_TEST(access_mode_rx);
    RUN_TEST(access_mode_rw);
    RUN_TEST(access_mode_rwx);
    RUN_TEST(access_mode_unknown);
    RUN_TEST(access_mode_empty);

    RUN_TEST(allow_list_null);
    RUN_TEST(allow_list_empty);
    RUN_TEST(allow_list_single);
    RUN_TEST(allow_list_single_default_mode);
    RUN_TEST(allow_list_multiple);
    RUN_TEST(allow_list_mode_suffix_parsing);

    RUN_TEST(deny_list_null);
    RUN_TEST(deny_list_empty);
    RUN_TEST(deny_list_single);
    RUN_TEST(deny_list_multiple);

    printf("\n  Total: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
}

void get_sandbox_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run; *passed = tests_passed; *failed = tests_failed;
}

void reset_sandbox_test_stats(void) {
    tests_run = tests_passed = tests_failed = 0;
}
