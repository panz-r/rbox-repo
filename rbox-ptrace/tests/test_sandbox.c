/*
 * test_sandbox.c - Unit tests for sandbox rule-building logic
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <linux/landlock.h>

#include "../sandbox.h"

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
    uint64_t expected = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    ASSERT_EQ(result, expected);
    return 0;
}

TEST(access_mode_rx) {
    uint64_t result = sandbox_parse_access_mode("rx");
    ASSERT(result & LANDLOCK_ACCESS_FS_READ_FILE);
    ASSERT(result & LANDLOCK_ACCESS_FS_READ_DIR);
    ASSERT(result & LANDLOCK_ACCESS_FS_EXECUTE);
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
    ASSERT(result & LANDLOCK_ACCESS_FS_TRUNCATE);
    return 0;
}

TEST(access_mode_rwx) {
    uint64_t result = sandbox_parse_access_mode("rwx");
    ASSERT(result & LANDLOCK_ACCESS_FS_EXECUTE);
    ASSERT(result & LANDLOCK_ACCESS_FS_MAKE_SOCK);
    ASSERT(result & LANDLOCK_ACCESS_FS_MAKE_FIFO);
    ASSERT(result & LANDLOCK_ACCESS_FS_MAKE_BLOCK);
    ASSERT(result & LANDLOCK_ACCESS_FS_MAKE_SYM);
    ASSERT(result & LANDLOCK_ACCESS_FS_REFER);
    return 0;
}

TEST(access_mode_unknown) {
    uint64_t result = sandbox_parse_access_mode("xyz");
    uint64_t rx = sandbox_parse_access_mode("rx");
    ASSERT_EQ(result, rx);
    return 0;
}

TEST(access_mode_empty) {
    uint64_t result = sandbox_parse_access_mode("");
    uint64_t rx = sandbox_parse_access_mode("rx");
    ASSERT_EQ(result, rx);
    return 0;
}

/* ==================== parse_allow_list tests ==================== */

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
    struct allowed_entry *result = sandbox_parse_allow_list("/tmp:ro", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(result[0].resolved, "/tmp");
    sandbox_free_allow_entries(result, count);
    return 0;
}

TEST(allow_list_single_default_mode) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list("/tmp", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(result[0].access, sandbox_parse_access_mode("rx"));
    sandbox_free_allow_entries(result, count);
    return 0;
}

TEST(allow_list_multiple) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list("/tmp:ro,/usr:rw", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 2);
    ASSERT_STR_EQ(result[0].resolved, "/tmp");
    ASSERT_EQ(result[0].access, sandbox_parse_access_mode("ro"));
    ASSERT_STR_EQ(result[1].resolved, "/usr");
    ASSERT_EQ(result[1].access, sandbox_parse_access_mode("rw"));
    sandbox_free_allow_entries(result, count);
    return 0;
}

TEST(allow_list_mode_suffix_parsing) {
    int count = -1;
    struct allowed_entry *result = sandbox_parse_allow_list("/tmp:rw", &count, mock_always_valid, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(result[0].access, sandbox_parse_access_mode("rw"));
    sandbox_free_allow_entries(result, count);
    return 0;
}

/* ==================== parse_deny_list tests ==================== */

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
    ASSERT_STR_EQ(result[0].resolved, "/tmp");
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

/* ==================== simplify_allow_list tests ==================== */

static void init_allow_entry(struct allowed_entry *e, const char *path, uint64_t access) {
    e->original = strdup(path);
    e->resolved = strdup(path);
    e->access = access;
}

static struct allowed_entry *alloc_allow_entries(int count) {
    return calloc(count, sizeof(struct allowed_entry));
}

TEST(allow_simplify_single) {
    struct allowed_entry *entries = alloc_allow_entries(1);
    init_allow_entry(&entries[0], "/a", sandbox_parse_access_mode("rx"));
    int count = 1;
    sandbox_simplify_allow_list(&entries, &count);
    ASSERT_EQ(count, 1);
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries);
    return 0;
}

TEST(allow_simplify_siblings) {
    struct allowed_entry *entries = alloc_allow_entries(2);
    init_allow_entry(&entries[0], "/a", sandbox_parse_access_mode("rx"));
    init_allow_entry(&entries[1], "/b", sandbox_parse_access_mode("rx"));
    int count = 2;
    sandbox_simplify_allow_list(&entries, &count);
    ASSERT_EQ(count, 2);
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries[1].original);
    free(entries[1].resolved);
    free(entries);
    return 0;
}

TEST(allow_simplify_child_covered) {
    struct allowed_entry *entries = alloc_allow_entries(2);
    init_allow_entry(&entries[0], "/parent", sandbox_parse_access_mode("rw"));
    init_allow_entry(&entries[1], "/parent/child", sandbox_parse_access_mode("rw"));
    int count = 2;
    sandbox_simplify_allow_list(&entries, &count);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(entries[0].resolved, "/parent");
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries);
    return 0;
}

TEST(allow_simplify_parent_covered) {
    struct allowed_entry *entries = alloc_allow_entries(2);
    init_allow_entry(&entries[0], "/parent/child", sandbox_parse_access_mode("rw"));
    init_allow_entry(&entries[1], "/parent", sandbox_parse_access_mode("rw"));
    int count = 2;
    sandbox_simplify_allow_list(&entries, &count);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(entries[0].resolved, "/parent");
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries);
    return 0;
}

TEST(allow_simplify_different_access) {
    struct allowed_entry *entries = alloc_allow_entries(2);
    init_allow_entry(&entries[0], "/parent", sandbox_parse_access_mode("ro"));
    init_allow_entry(&entries[1], "/parent/child", sandbox_parse_access_mode("rw"));
    int count = 2;
    sandbox_simplify_allow_list(&entries, &count);
    ASSERT_EQ(count, 2);
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries[1].original);
    free(entries[1].resolved);
    free(entries);
    return 0;
}

TEST(allow_simplify_deep_nested) {
    struct allowed_entry *entries = alloc_allow_entries(3);
    init_allow_entry(&entries[0], "/a", sandbox_parse_access_mode("rx"));
    init_allow_entry(&entries[1], "/a/b", sandbox_parse_access_mode("rx"));
    init_allow_entry(&entries[2], "/a/b/c", sandbox_parse_access_mode("rx"));
    int count = 3;
    sandbox_simplify_allow_list(&entries, &count);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(entries[0].resolved, "/a");
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries);
    return 0;
}

TEST(allow_simplify_sibling_not_covered) {
    struct allowed_entry *entries = alloc_allow_entries(2);
    init_allow_entry(&entries[0], "/parentXYZ", sandbox_parse_access_mode("rw"));
    init_allow_entry(&entries[1], "/parent", sandbox_parse_access_mode("rw"));
    int count = 2;
    sandbox_simplify_allow_list(&entries, &count);
    ASSERT_EQ(count, 2);
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries[1].original);
    free(entries[1].resolved);
    free(entries);
    return 0;
}

/* ==================== simplify_deny_list tests ==================== */

static void init_deny_entry(struct denied_entry *e, const char *path) {
    e->original = strdup(path);
    e->resolved = strdup(path);
}

static struct denied_entry *alloc_deny_entries(int count) {
    return calloc(count, sizeof(struct denied_entry));
}

TEST(deny_simplify_single) {
    struct denied_entry *entries = alloc_deny_entries(1);
    init_deny_entry(&entries[0], "/a");
    int count = 1;
    sandbox_simplify_deny_list(&entries, &count);
    ASSERT_EQ(count, 1);
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries);
    return 0;
}

TEST(deny_simplify_siblings) {
    struct denied_entry *entries = alloc_deny_entries(2);
    init_deny_entry(&entries[0], "/a");
    init_deny_entry(&entries[1], "/b");
    int count = 2;
    sandbox_simplify_deny_list(&entries, &count);
    ASSERT_EQ(count, 2);
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries[1].original);
    free(entries[1].resolved);
    free(entries);
    return 0;
}

TEST(deny_simplify_parent_child) {
    struct denied_entry *entries = alloc_deny_entries(2);
    init_deny_entry(&entries[0], "/parent");
    init_deny_entry(&entries[1], "/parent/child");
    int count = 2;
    sandbox_simplify_deny_list(&entries, &count);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(entries[0].resolved, "/parent");
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries);
    return 0;
}

TEST(deny_simplify_deep_nested) {
    struct denied_entry *entries = alloc_deny_entries(3);
    init_deny_entry(&entries[0], "/a");
    init_deny_entry(&entries[1], "/a/b");
    init_deny_entry(&entries[2], "/a/b/c");
    int count = 3;
    sandbox_simplify_deny_list(&entries, &count);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(entries[0].resolved, "/a");
    free(entries[0].original);
    free(entries[0].resolved);
    free(entries);
    return 0;
}

/* ==================== overlap removal tests ==================== */

TEST(overlap_none) {
    struct allowed_entry allow[2];
    struct denied_entry deny[1];
    
    init_allow_entry(&allow[0], "/a", sandbox_parse_access_mode("rw"));
    init_allow_entry(&allow[1], "/b", sandbox_parse_access_mode("rx"));
    init_deny_entry(&deny[0], "/c");
    
    int allow_count = 2;
    int deny_count = 1;
    
    allow_count = sandbox_remove_overlaps(allow, allow_count, deny, deny_count);
    
    ASSERT_EQ(allow_count, 2);
    
    free(allow[0].original);
    free(allow[0].resolved);
    free(allow[1].original);
    free(allow[1].resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    return 0;
}

TEST(overlap_exact) {
    struct allowed_entry allow[1];
    struct denied_entry deny[1];
    
    init_allow_entry(&allow[0], "/a", sandbox_parse_access_mode("rw"));
    init_deny_entry(&deny[0], "/a");
    
    int allow_count = 1;
    int deny_count = 1;
    
    allow_count = sandbox_remove_overlaps(allow, allow_count, deny, deny_count);
    
    ASSERT_EQ(allow_count, 0);
    
    free(deny[0].original);
    free(deny[0].resolved);
    return 0;
}

TEST(overlap_partial) {
    struct allowed_entry allow[2];
    struct denied_entry deny[1];
    
    init_allow_entry(&allow[0], "/a", sandbox_parse_access_mode("rw"));
    init_allow_entry(&allow[1], "/b", sandbox_parse_access_mode("rx"));
    init_deny_entry(&deny[0], "/a");
    
    int allow_count = 2;
    int deny_count = 1;
    
    allow_count = sandbox_remove_overlaps(allow, allow_count, deny, deny_count);
    
    ASSERT_EQ(allow_count, 1);
    ASSERT_STR_EQ(allow[0].resolved, "/b");
    
    free(allow[0].original);
    free(allow[0].resolved);
    free(allow[1].original);
    free(allow[1].resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    return 0;
}

TEST(overlap_multiple) {
    struct allowed_entry allow[3];
    struct denied_entry deny[2];
    
    init_allow_entry(&allow[0], "/a", sandbox_parse_access_mode("rw"));
    init_allow_entry(&allow[1], "/b", sandbox_parse_access_mode("rx"));
    init_allow_entry(&allow[2], "/c", sandbox_parse_access_mode("ro"));
    init_deny_entry(&deny[0], "/a");
    init_deny_entry(&deny[1], "/c");
    
    int allow_count = 3;
    int deny_count = 2;
    
    allow_count = sandbox_remove_overlaps(allow, allow_count, deny, deny_count);
    
    ASSERT_EQ(allow_count, 1);
    ASSERT_STR_EQ(allow[0].resolved, "/b");
    
    free(allow[0].original);
    free(allow[0].resolved);
    free(allow[1].original);
    free(allow[1].resolved);
    free(allow[2].original);
    free(allow[2].resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    free(deny[1].original);
    free(deny[1].resolved);
    return 0;
}

/* ==================== handled_access calculation tests ==================== */

TEST(handled_access_empty) {
    struct allowed_entry allow[0];
    uint64_t result = sandbox_calc_handled_access(allow, 0);
    ASSERT_EQ(result, 0);
    return 0;
}

TEST(handled_access_single_ro) {
    struct allowed_entry allow[1];
    init_allow_entry(&allow[0], "/a", sandbox_parse_access_mode("ro"));
    uint64_t result = sandbox_calc_handled_access(allow, 1);
    ASSERT_EQ(result, sandbox_parse_access_mode("ro"));
    free(allow[0].original);
    free(allow[0].resolved);
    return 0;
}

TEST(handled_access_single_rw) {
    struct allowed_entry allow[1];
    init_allow_entry(&allow[0], "/a", sandbox_parse_access_mode("rw"));
    uint64_t result = sandbox_calc_handled_access(allow, 1);
    ASSERT_EQ(result, sandbox_parse_access_mode("rw"));
    free(allow[0].original);
    free(allow[0].resolved);
    return 0;
}

TEST(handled_access_multiple) {
    struct allowed_entry allow[2];
    init_allow_entry(&allow[0], "/a", sandbox_parse_access_mode("ro"));
    init_allow_entry(&allow[1], "/b", sandbox_parse_access_mode("rx"));
    uint64_t result = sandbox_calc_handled_access(allow, 2);
    uint64_t expected = sandbox_parse_access_mode("ro") | sandbox_parse_access_mode("rx");
    ASSERT_EQ(result, expected);
    free(allow[0].original);
    free(allow[0].resolved);
    free(allow[1].original);
    free(allow[1].resolved);
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

    RUN_TEST(allow_simplify_single);
    RUN_TEST(allow_simplify_siblings);
    RUN_TEST(allow_simplify_child_covered);
    RUN_TEST(allow_simplify_parent_covered);
    RUN_TEST(allow_simplify_different_access);
    RUN_TEST(allow_simplify_deep_nested);
    RUN_TEST(allow_simplify_sibling_not_covered);

    RUN_TEST(deny_simplify_single);
    RUN_TEST(deny_simplify_siblings);
    RUN_TEST(deny_simplify_parent_child);
    RUN_TEST(deny_simplify_deep_nested);

    RUN_TEST(overlap_none);
    RUN_TEST(overlap_exact);
    RUN_TEST(overlap_partial);
    RUN_TEST(overlap_multiple);

    RUN_TEST(handled_access_empty);
    RUN_TEST(handled_access_single_ro);
    RUN_TEST(handled_access_single_rw);
    RUN_TEST(handled_access_multiple);

    printf("\n  Total: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
}

void get_sandbox_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run; *passed = tests_passed; *failed = tests_failed;
}

void reset_sandbox_test_stats(void) {
    tests_run = tests_passed = tests_failed = 0;
}
