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
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

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

TEST(overlap_deny_prefix_of_allow) {
    struct allowed_entry allow[2];
    struct denied_entry deny[1];
    
    init_allow_entry(&allow[0], "/parent/child", sandbox_parse_access_mode("rw"));
    init_allow_entry(&allow[1], "/other", sandbox_parse_access_mode("rx"));
    init_deny_entry(&deny[0], "/parent");
    
    int allow_count = 2;
    int deny_count = 1;
    
    allow_count = sandbox_remove_overlaps(allow, allow_count, deny, deny_count);
    
    ASSERT_EQ(allow_count, 1);
    ASSERT_STR_EQ(allow[0].resolved, "/other");
    
    free(allow[0].original);
    free(allow[0].resolved);
    free(allow[1].original);
    free(allow[1].resolved);
    free(deny[0].original);
    free(deny[0].resolved);
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

/* ==================== Symlink expansion tests ==================== */

static char *temp_dir = NULL;

static int mkdirtmp(const char *path) {
    return mkdir(path, 0755);
}

static int symlinktmp(const char *target, const char *link) {
    return symlink(target, link);
}

static int rmtree(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return -1;
    struct dirent *entry;
    int ret = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        struct stat st;
        if (lstat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (rmtree(full_path) != 0) ret = -1;
            } else {
                if (unlink(full_path) != 0) ret = -1;
            }
        }
    }
    closedir(dir);
    if (rmdir(path) != 0) ret = -1;
    return ret;
}

static int cleanup_temp_dir(void) {
    if (temp_dir) {
        rmtree(temp_dir);
        free(temp_dir);
        temp_dir = NULL;
    }
    return 0;
}

static int setup_temp_dir(void) {
    cleanup_temp_dir();
    temp_dir = strdup("/tmp/test_robox_symlink_XXXXXX");
    if (!temp_dir) return -1;
    if (!mkdtemp(temp_dir)) {
        free(temp_dir);
        temp_dir = NULL;
        return -1;
    }
    return 0;
}

static void cleanup_expansion(void) {
    sandbox_expansion_cleanup();
}

static int path_in_expanded(const char *path) {
    int count = sandbox_get_expanded_count();
    for (int i = 0; i < count; i++) {
        const char *p = sandbox_get_expanded_path(i);
        if (p && strcmp(p, path) == 0) return 1;
    }
    return 0;
}

static int count_in_expanded(const char *path) {
    int count = sandbox_get_expanded_count();
    int c = 0;
    for (int i = 0; i < count; i++) {
        const char *p = sandbox_get_expanded_path(i);
        if (p && strcmp(p, path) == 0) c++;
    }
    return c;
}

TEST(symlink_to_denied_directory) {
    if (setup_temp_dir() != 0) return 1;
    
    char allowed[512], denied[512], link[512];
    snprintf(allowed, sizeof(allowed), "%s/allowed", temp_dir);
    snprintf(denied, sizeof(denied), "%s/denied", temp_dir);
    snprintf(link, sizeof(link), "%s/allowed/link", temp_dir);
    
    if (mkdirtmp(allowed) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(denied) != 0) { cleanup_temp_dir(); return 1; }
    if (symlinktmp("../denied", link) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(allowed);
    allow.resolved = strdup(allowed);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    
    struct denied_entry deny[1];
    deny[0].original = strdup(denied);
    deny[0].resolved = strdup(denied);
    
    sandbox_expand_paths(&allow, 1, deny, 1);
    
    int found_denied = path_in_expanded(denied);
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    
    ASSERT(found_denied == 0);
    return 0;
}

TEST(symlink_chain) {
    if (setup_temp_dir() != 0) return 1;
    
    char root[512], final[512], link1[512], link2[512], marker[512];
    snprintf(root, sizeof(root), "%s/root", temp_dir);
    snprintf(final, sizeof(final), "%s/root/final", temp_dir);
    snprintf(link1, sizeof(link1), "%s/root/link1", temp_dir);
    snprintf(link2, sizeof(link2), "%s/root/link2", temp_dir);
    snprintf(marker, sizeof(marker), "%s/root/marker", temp_dir);
    
    if (mkdirtmp(root) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(final) != 0) { cleanup_temp_dir(); return 1; }
    if (symlinktmp("final", link1) != 0) { cleanup_temp_dir(); return 1; }
    if (symlinktmp("link1", link2) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(root);
    allow.resolved = strdup(root);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                   LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_EXECUTE;
    
    struct denied_entry deny[1];
    deny[0].original = strdup(marker);
    deny[0].resolved = strdup(marker);
    
    sandbox_expand_paths(&allow, 1, deny, 1);
    
    int found_final = path_in_expanded(final);
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    
    ASSERT(found_final == 1);
    return 0;
}

TEST(symlink_multiple_to_same_target) {
    if (setup_temp_dir() != 0) return 1;
    
    char target[512], dir1[512], dir2[512], link1[512], link2[512], marker[512];
    snprintf(target, sizeof(target), "%s/target", temp_dir);
    snprintf(dir1, sizeof(dir1), "%s/dir1", temp_dir);
    snprintf(dir2, sizeof(dir2), "%s/dir2", temp_dir);
    snprintf(link1, sizeof(link1), "%s/dir1/link", temp_dir);
    snprintf(link2, sizeof(link2), "%s/dir2/link", temp_dir);
    snprintf(marker, sizeof(marker), "%s/marker", temp_dir);
    
    if (mkdirtmp(target) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(dir1) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(dir2) != 0) { cleanup_temp_dir(); return 1; }
    if (symlinktmp("../../target", link1) != 0) { cleanup_temp_dir(); return 1; }
    if (symlinktmp("../../target", link2) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(temp_dir);
    allow.resolved = strdup(temp_dir);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    
    struct denied_entry deny[1];
    deny[0].original = strdup(marker);
    deny[0].resolved = strdup(marker);
    
    sandbox_expand_paths(&allow, 1, deny, 1);
    
    int target_count = count_in_expanded(target);
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    
    ASSERT(target_count == 1);
    return 0;
}

TEST(symlink_to_parent) {
    if (setup_temp_dir() != 0) return 1;
    
    char parent[512], child[512], link[512], marker[512];
    snprintf(parent, sizeof(parent), "%s/parent", temp_dir);
    snprintf(child, sizeof(child), "%s/parent/child", temp_dir);
    snprintf(link, sizeof(link), "%s/parent/child/link_to_parent", temp_dir);
    snprintf(marker, sizeof(marker), "%s/parent/child/marker", temp_dir);
    
    if (mkdirtmp(parent) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(child) != 0) { cleanup_temp_dir(); return 1; }
    if (symlinktmp("..", link) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(child);
    allow.resolved = strdup(child);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    
    struct denied_entry deny[1];
    deny[0].original = strdup(marker);
    deny[0].resolved = strdup(marker);
    
    sandbox_expand_paths(&allow, 1, deny, 1);
    
    int found_parent = path_in_expanded(parent);
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    
    ASSERT(found_parent == 0);
    return 0;
}

TEST(symlink_dangling) {
    if (setup_temp_dir() != 0) return 1;
    
    char link[512];
    snprintf(link, sizeof(link), "%s/dangle", temp_dir);
    
    if (symlinktmp("nonexistent_target", link) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(temp_dir);
    allow.resolved = strdup(temp_dir);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                   LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_EXECUTE;
    
    sandbox_expand_paths(&allow, 1, NULL, 0);
    
    int count = sandbox_get_expanded_count();
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    
    ASSERT(count >= 0);
    return 0;
}

TEST(symlink_to_file) {
    if (setup_temp_dir() != 0) return 1;
    
    char dir[512], file[512], link[512];
    snprintf(dir, sizeof(dir), "%s/mydir", temp_dir);
    snprintf(file, sizeof(file), "%s/mydir/myfile", temp_dir);
    snprintf(link, sizeof(link), "%s/mylink", temp_dir);
    
    if (mkdirtmp(dir) != 0) { cleanup_temp_dir(); return 1; }
    
    FILE *f = fopen(file, "w");
    if (!f) { cleanup_temp_dir(); return 1; }
    fclose(f);
    
    if (symlinktmp("mydir/myfile", link) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(temp_dir);
    allow.resolved = strdup(temp_dir);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                   LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_EXECUTE;
    
    sandbox_expand_paths(&allow, 1, NULL, 0);
    
    int count = sandbox_get_expanded_count();
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    
    ASSERT(count >= 0);
    return 0;
}

TEST(symlink_self_loop) {
    if (setup_temp_dir() != 0) return 1;
    
    char link[512];
    snprintf(link, sizeof(link), "%s/link", temp_dir);
    
    if (symlinktmp("link", link) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(temp_dir);
    allow.resolved = strdup(temp_dir);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                   LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_EXECUTE;
    
    sandbox_expand_paths(&allow, 1, NULL, 0);
    
    int count = sandbox_get_expanded_count();
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    
    ASSERT(count >= 0);
    return 0;
}

TEST(symlink_outside_tree) {
    if (setup_temp_dir() != 0) return 1;
    
    char root[512], outside[512], link[512], marker[512];
    snprintf(root, sizeof(root), "%s/root", temp_dir);
    snprintf(outside, sizeof(outside), "%s/outside", temp_dir);
    snprintf(link, sizeof(link), "%s/root/link", temp_dir);
    snprintf(marker, sizeof(marker), "%s/root/marker", temp_dir);
    
    if (mkdirtmp(root) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(outside) != 0) { cleanup_temp_dir(); return 1; }
    if (symlinktmp("../outside", link) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(root);
    allow.resolved = strdup(root);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    
    struct denied_entry deny[1];
    deny[0].original = strdup(marker);
    deny[0].resolved = strdup(marker);
    
    sandbox_expand_paths(&allow, 1, deny, 1);
    
    int found_outside = path_in_expanded(outside);
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    
    ASSERT(found_outside == 1);
    return 0;
}

TEST(symlink_to_subdirectory_with_deny_child) {
    if (setup_temp_dir() != 0) return 1;
    
    char root[512], subdir[512], allowed_sub[512], denied_sub[512], link[512];
    snprintf(root, sizeof(root), "%s/root", temp_dir);
    snprintf(subdir, sizeof(subdir), "%s/root/subdir", temp_dir);
    snprintf(allowed_sub, sizeof(allowed_sub), "%s/root/subdir/allowed", temp_dir);
    snprintf(denied_sub, sizeof(denied_sub), "%s/root/subdir/denied", temp_dir);
    snprintf(link, sizeof(link), "%s/root/link", temp_dir);
    
    if (mkdirtmp(root) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(subdir) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(allowed_sub) != 0) { cleanup_temp_dir(); return 1; }
    if (mkdirtmp(denied_sub) != 0) { cleanup_temp_dir(); return 1; }
    if (symlinktmp("subdir", link) != 0) { cleanup_temp_dir(); return 1; }
    
    struct allowed_entry allow;
    allow.original = strdup(root);
    allow.resolved = strdup(root);
    allow.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    
    struct denied_entry deny[1];
    deny[0].original = strdup(denied_sub);
    deny[0].resolved = strdup(denied_sub);
    
    sandbox_expand_paths(&allow, 1, deny, 1);
    
    int found_allowed = path_in_expanded(allowed_sub);
    int found_denied = path_in_expanded(denied_sub);
    
    cleanup_expansion();
    cleanup_temp_dir();
    free(allow.original);
    free(allow.resolved);
    free(deny[0].original);
    free(deny[0].resolved);
    
    ASSERT(found_allowed == 1);
    ASSERT(found_denied == 0);
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
    RUN_TEST(overlap_deny_prefix_of_allow);

    RUN_TEST(handled_access_empty);
    RUN_TEST(handled_access_single_ro);
    RUN_TEST(handled_access_single_rw);
    RUN_TEST(handled_access_multiple);

    RUN_TEST(symlink_to_denied_directory);
    RUN_TEST(symlink_chain);
    RUN_TEST(symlink_multiple_to_same_target);
    RUN_TEST(symlink_to_parent);
    RUN_TEST(symlink_dangling);
    RUN_TEST(symlink_to_file);
    RUN_TEST(symlink_self_loop);
    RUN_TEST(symlink_outside_tree);
    RUN_TEST(symlink_to_subdirectory_with_deny_child);

    printf("\n  Total: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
}

void get_sandbox_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run; *passed = tests_passed; *failed = tests_failed;
}

void reset_sandbox_test_stats(void) {
    tests_run = tests_passed = tests_failed = 0;
}
