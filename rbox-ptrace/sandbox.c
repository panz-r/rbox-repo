/*
 * sandbox.c - Sandboxing functionality for rbox-ptrace
 *
 * Implements Landlock filesystem restrictions, seccomp network blocking,
 * and memory limits via setrlimit.
 *
 * Configuration is read from environment variables:
 * - READONLYBOX_MEMORY_LIMIT: memory limit (e.g., "256M", "1G")
 * - READONLYBOX_NO_NETWORK: if set, block network access
 * - READONLYBOX_HARD_ALLOW: colon-separated allowed paths with modes
 * - READONLYBOX_HARD_DENY: colon-separated denied paths
 *
 * Policy: When both HARD_ALLOW and HARD_DENY are set, deny takes precedence
 * for overlapping paths. Only directories are accepted.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <dirent.h>
#include <linux/filter.h>

#include "sandbox.h"
#include "soft_policy.h"
#include "debug.h"

static void apply_memory_limit(void) {
    const char *limit_str = getenv("READONLYBOX_MEMORY_LIMIT");
    if (!limit_str || !*limit_str) return;

    char *endptr;
    unsigned long long val = strtoull(limit_str, &endptr, 10);

    if (endptr == limit_str) {
        LOG_ERROR("Invalid memory limit format: %s", limit_str);
        return;
    }

    if (val == 0) {
        DEBUG_PRINT("SANDBOX: Memory limit is 0, skipping\n");
        return;
    }

    unsigned long long multiplier = 1;
    switch (*endptr) {
        case 'K':
        case 'k':
            multiplier = 1024ULL;
            break;
        case 'M':
        case 'm':
            multiplier = 1024ULL * 1024ULL;
            break;
        case 'G':
        case 'g':
            multiplier = 1024ULL * 1024ULL * 1024ULL;
            break;
        case 'T':
        case 't':
            multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;
        default:
            break;
    }

    if (multiplier > 1 && val > (ULLONG_MAX / multiplier)) {
        LOG_ERROR("Memory limit overflow: %s", limit_str);
        return;
    }
    val *= multiplier;

    if (val > RLIM_INFINITY) {
        LOG_ERROR("Memory limit exceeds maximum (%llu > %llu): %s",
                  (unsigned long long)val, (unsigned long long)RLIM_INFINITY, limit_str);
        return;
    }

    rlim_t limit = (rlim_t)val;
    struct rlimit rlim = {limit, limit};
    if (setrlimit(RLIMIT_AS, &rlim) != 0) {
        LOG_ERRNO("Failed to set memory limit");
    } else {
        DEBUG_PRINT("SANDBOX: Memory limit set to %llu bytes\n", (unsigned long long)limit);
    }
}

uint64_t sandbox_parse_access_mode(const char *mode) {
    uint64_t access_ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t access_rx = access_ro | LANDLOCK_ACCESS_FS_EXECUTE;
    uint64_t access_rw = access_ro | LANDLOCK_ACCESS_FS_WRITE_FILE |
                         LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                         LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                         LANDLOCK_ACCESS_FS_TRUNCATE;
    uint64_t access_rwx = access_rw | LANDLOCK_ACCESS_FS_EXECUTE |
                          LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                          LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
                          LANDLOCK_ACCESS_FS_REFER;

    if (strcmp(mode, "ro") == 0) return access_ro;
    if (strcmp(mode, "rx") == 0) return access_rx;
    if (strcmp(mode, "rw") == 0) return access_rw;
    if (strcmp(mode, "rwx") == 0) return access_rwx;
    return access_rx;
}

static int allow_compare(const void *a, const void *b) {
    const struct allowed_entry *ea = a;
    const struct allowed_entry *eb = b;
    return strlen(ea->resolved) - strlen(eb->resolved);
}

static int deny_compare(const void *a, const void *b) {
    const struct denied_entry *ea = a;
    const struct denied_entry *eb = b;
    return strlen(ea->resolved) - strlen(eb->resolved);
}

struct allowed_entry *sandbox_parse_allow_list(const char *env_value, int *out_count,
                                              sandbox_path_validator_t validator, void *ctx) {
    if (!validator) {
        LOG_FATAL("sandbox_parse_allow_list: NULL validator");
    }
    if (!env_value || !*env_value) {
        *out_count = 0;
        return NULL;
    }

    char *copy = strdup(env_value);
    if (!copy) return NULL;

    struct allowed_entry *entries = NULL;
    int capacity = 8;
    int count = 0;
    entries = malloc(capacity * sizeof(struct allowed_entry));
    if (!entries) {
        free(copy);
        *out_count = 0;
        return NULL;
    }

    char *saveptr;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token) {
        char *path = strdup(token);
        if (!path) {
            for (int i = 0; i < count; i++) {
                free(entries[i].original);
                free(entries[i].resolved);
            }
            free(entries);
            free(copy);
            *out_count = 0;
            return NULL;
        }

        uint64_t access = sandbox_parse_access_mode("rx");
        char *colon = strrchr(path, ':');
        if (colon && strlen(colon) >= 3) {
            if (strcmp(colon + 1, "ro") == 0 || strcmp(colon + 1, "rx") == 0 ||
                strcmp(colon + 1, "rw") == 0 || strcmp(colon + 1, "rwx") == 0) {
                access = sandbox_parse_access_mode(colon + 1);
                *colon = '\0';
            }
        }

        char *resolved = realpath(path, NULL);
        if (!resolved) {
            LOG_FATAL("hard-allow: cannot resolve path '%s': %s", path, strerror(errno));
            free(path);
        }

        if (!validator(resolved, ctx)) {
            LOG_FATAL("hard-allow: '%s' is not a directory", resolved);
            free(resolved);
            free(path);
        }

        if (count >= capacity) {
            capacity *= 2;
            struct allowed_entry *new_entries = realloc(entries, capacity * sizeof(struct allowed_entry));
            if (!new_entries) {
                free(resolved);
                free(path);
                for (int i = 0; i < count; i++) {
                    free(entries[i].original);
                    free(entries[i].resolved);
                }
                free(entries);
                free(copy);
                *out_count = 0;
                return NULL;
            }
            entries = new_entries;
        }

        entries[count].original = path;
        entries[count].resolved = resolved;
        entries[count].access = access;
        count++;

        token = strtok_r(NULL, ",", &saveptr);
    }

    free(copy);
    *out_count = count;
    return entries;
}

struct denied_entry *sandbox_parse_deny_list(const char *env_value, int *out_count,
                                            sandbox_path_validator_t validator, void *ctx) {
    if (!validator) {
        LOG_FATAL("sandbox_parse_deny_list: NULL validator");
    }
    if (!env_value || !*env_value) {
        *out_count = 0;
        return NULL;
    }

    char *copy = strdup(env_value);
    if (!copy) return NULL;

    struct denied_entry *entries = NULL;
    int capacity = 8;
    int count = 0;
    entries = malloc(capacity * sizeof(struct denied_entry));
    if (!entries) {
        free(copy);
        *out_count = 0;
        return NULL;
    }

    char *saveptr;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token) {
        char *path = strdup(token);
        if (!path) {
            for (int i = 0; i < count; i++) {
                free(entries[i].original);
                free(entries[i].resolved);
            }
            free(entries);
            free(copy);
            *out_count = 0;
            return NULL;
        }

        char *resolved = realpath(path, NULL);
        if (!resolved) {
            LOG_FATAL("hard-deny: cannot resolve path '%s': %s", path, strerror(errno));
            free(path);
        }

        if (!validator(resolved, ctx)) {
            LOG_FATAL("hard-deny: '%s' is not a directory", resolved);
            free(resolved);
            free(path);
        }

        if (count >= capacity) {
            capacity *= 2;
            struct denied_entry *new_entries = realloc(entries, capacity * sizeof(struct denied_entry));
            if (!new_entries) {
                free(resolved);
                free(path);
                for (int i = 0; i < count; i++) {
                    free(entries[i].original);
                    free(entries[i].resolved);
                }
                free(entries);
                free(copy);
                *out_count = 0;
                return NULL;
            }
            entries = new_entries;
        }

        entries[count].original = path;
        entries[count].resolved = resolved;
        count++;

        token = strtok_r(NULL, ",", &saveptr);
    }

    free(copy);
    *out_count = count;
    return entries;
}

void sandbox_simplify_allow_list(struct allowed_entry **entries, int *count) {
    if (*count <= 1) return;

    qsort(*entries, *count, sizeof(struct allowed_entry), allow_compare);

    int keep = 0;
    for (int i = 0; i < *count; i++) {
        bool covered = false;
        size_t child_len = strlen((*entries)[i].resolved);
        for (int j = 0; j < keep; j++) {
            struct allowed_entry *parent = &(*entries)[j];
            size_t parent_len = strlen(parent->resolved);
            if (parent_len < child_len &&
                strncmp(parent->resolved, (*entries)[i].resolved, parent_len) == 0 &&
                (*entries)[i].resolved[parent_len] == '/' &&
                (parent->access & (*entries)[i].access) == (*entries)[i].access) {
                covered = true;
                break;
            }
        }
        if (covered) {
            free((*entries)[i].original);
            free((*entries)[i].resolved);
            (*entries)[i].original = NULL;
            (*entries)[i].resolved = NULL;
        } else {
            if (keep != i) {
                free((*entries)[keep].original);
                free((*entries)[keep].resolved);
                (*entries)[keep] = (*entries)[i];
            }
            keep++;
        }
    }
    *count = keep;
}

void sandbox_simplify_deny_list(struct denied_entry **entries, int *count) {
    if (*count <= 1) return;

    qsort(*entries, *count, sizeof(struct denied_entry), deny_compare);

    int keep = 0;
    for (int i = 0; i < *count; i++) {
        bool has_parent = false;
        size_t child_len = strlen((*entries)[i].resolved);
        for (int j = 0; j < keep; j++) {
            struct denied_entry *parent = &(*entries)[j];
            size_t parent_len = strlen(parent->resolved);
            if (parent_len < child_len &&
                strncmp(parent->resolved, (*entries)[i].resolved, parent_len) == 0 &&
                (*entries)[i].resolved[parent_len] == '/') {
                has_parent = true;
                break;
            }
        }
        if (has_parent) {
            free((*entries)[i].original);
            free((*entries)[i].resolved);
            (*entries)[i].original = NULL;
            (*entries)[i].resolved = NULL;
        } else {
            if (keep != i) {
                free((*entries)[keep].original);
                free((*entries)[keep].resolved);
                (*entries)[keep] = (*entries)[i];
            }
            keep++;
        }
    }
    *count = keep;
}

int sandbox_remove_overlaps(struct allowed_entry *allow, int allow_count,
                           struct denied_entry *deny, int deny_count) {
    int keep = 0;
    for (int i = 0; i < allow_count; i++) {
        bool is_denied = false;
        size_t allow_len = strlen(allow[i].resolved);
        for (int j = 0; j < deny_count; j++) {
            if (deny[j].resolved == NULL) continue;
            size_t deny_len = strlen(deny[j].resolved);
            /* Exact match: deny path equals allow path */
            if (allow_len == deny_len && strcmp(allow[i].resolved, deny[j].resolved) == 0) {
                is_denied = true;
                break;
            }
            /* Deny is prefix of allow: deny path is a parent directory */
            if (deny_len < allow_len &&
                strncmp(allow[i].resolved, deny[j].resolved, deny_len) == 0 &&
                allow[i].resolved[deny_len] == '/') {
                is_denied = true;
                break;
            }
        }
        if (is_denied) {
            free(allow[i].original);
            free(allow[i].resolved);
            allow[i].original = NULL;
            allow[i].resolved = NULL;
        } else {
            if (keep != i) {
                allow[keep] = allow[i];
                allow[i].original = NULL;
                allow[i].resolved = NULL;
            }
            keep++;
        }
    }
    return keep;
}

uint64_t sandbox_calc_handled_access(const struct allowed_entry *allow, int allow_count) {
    uint64_t access = 0;
    for (int i = 0; i < allow_count; i++) {
        access |= allow[i].access;
    }
    return access;
}

void sandbox_free_allow_entries(struct allowed_entry *entries, int count) {
    for (int i = 0; i < count; i++) {
        free(entries[i].original);
        free(entries[i].resolved);
    }
    free(entries);
}

void sandbox_free_deny_entries(struct denied_entry *entries, int count) {
    for (int i = 0; i < count; i++) {
        free(entries[i].original);
        free(entries[i].resolved);
    }
    free(entries);
}

static bool real_path_validator(const char *path, void *ctx) {
    (void)ctx;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

#define MAX_EXPANDED_PATHS 1024
#define MAX_VISITED_PATHS 4096
#define MAX_QUEUE_PATHS 1024

struct expanded_path {
    char *path;
    uint64_t access;
};

struct queue_entry {
    char *path;
    uint64_t access;
};

struct expansion_context {
    struct expanded_path *paths;
    int path_count;
    int path_capacity;

    struct queue_entry *queue;
    int queue_head;
    int queue_size;
    int queue_capacity;

    char **visited;
    int visited_count;
    int visited_capacity;

    struct expanded_path *result_paths;
    int result_count;

    int failed;
};

static void expansion_context_init(struct expansion_context *ctx) {
    ctx->paths = NULL;
    ctx->path_count = 0;
    ctx->path_capacity = 0;

    ctx->queue = calloc(MAX_QUEUE_PATHS, sizeof(struct queue_entry));
    ctx->queue_head = 0;
    ctx->queue_size = 0;
    ctx->queue_capacity = MAX_QUEUE_PATHS;

    ctx->visited = NULL;
    ctx->visited_count = 0;
    ctx->visited_capacity = 0;

    ctx->result_paths = NULL;
    ctx->result_count = 0;

    ctx->failed = 0;
}

static void expansion_context_free(struct expansion_context *ctx) {
    for (int i = 0; i < ctx->path_count; i++) {
        free(ctx->paths[i].path);
    }
    free(ctx->paths);

    for (int i = 0; i < ctx->queue_size; i++) {
        int idx = (ctx->queue_head + i) % ctx->queue_capacity;
        free(ctx->queue[idx].path);
    }
    free(ctx->queue);

    for (int i = 0; i < ctx->visited_count; i++) {
        free(ctx->visited[i]);
    }
    free(ctx->visited);

    free(ctx->result_paths);

    ctx->paths = NULL;
    ctx->path_count = 0;
    ctx->path_capacity = 0;
    ctx->queue = NULL;
    ctx->queue_head = 0;
    ctx->queue_size = 0;
    ctx->queue_capacity = 0;
    ctx->visited = NULL;
    ctx->visited_count = 0;
    ctx->visited_capacity = 0;
    ctx->result_paths = NULL;
    ctx->result_count = 0;
}

static int add_expanded_path(struct expansion_context *ctx, const char *path, uint64_t access) {
    if (ctx->failed) return -1;
    if (ctx->path_count >= MAX_EXPANDED_PATHS) {
        return 0;
    }
    if (ctx->path_count >= ctx->path_capacity) {
        ctx->path_capacity = ctx->path_capacity ? ctx->path_capacity * 2 : 16;
        struct expanded_path *new_paths = realloc(ctx->paths, ctx->path_capacity * sizeof(struct expanded_path));
        if (!new_paths) {
            ctx->failed = 1;
            return -1;
        }
        ctx->paths = new_paths;
    }
    ctx->paths[ctx->path_count].path = strdup(path);
    if (!ctx->paths[ctx->path_count].path) {
        ctx->failed = 1;
        return -1;
    }
    ctx->paths[ctx->path_count].access = access;
    ctx->path_count++;
    return 0;
}

static bool is_under_deny(const char *path, size_t path_len,
                          struct denied_entry *deny, int deny_count) {
    for (int i = 0; i < deny_count; i++) {
        if (deny[i].resolved == NULL) continue;
        size_t deny_len = strlen(deny[i].resolved);
        if (deny_len <= path_len &&
            strncmp(path, deny[i].resolved, deny_len) == 0 &&
            (path_len == deny_len || path[deny_len] == '/')) {
            return true;
        }
    }
    return false;
}

bool sandbox_is_under_deny(const char *path, size_t path_len,
                           struct denied_entry *deny, int deny_count) {
    return is_under_deny(path, path_len, deny, deny_count);
}

static bool has_deny_under(const char *path, size_t path_len,
                           struct denied_entry *deny, int deny_count) {
    for (int i = 0; i < deny_count; i++) {
        if (deny[i].resolved == NULL) continue;
        size_t deny_len = strlen(deny[i].resolved);
        if (deny_len > path_len &&
            strncmp(path, deny[i].resolved, path_len) == 0 &&
            deny[i].resolved[path_len] == '/') {
            return true;
        }
    }
    return false;
}

bool sandbox_has_deny_under(const char *path, size_t path_len,
                           struct denied_entry *deny, int deny_count) {
    return has_deny_under(path, path_len, deny, deny_count);
}

static bool is_path_prefix(const char *parent, const char *child) {
    size_t parent_len = strlen(parent);
    size_t child_len = strlen(child);
    if (child_len < parent_len) return false;
    if (strncmp(parent, child, parent_len) != 0) return false;
    if (child_len == parent_len) return true;
    if (parent_len == 1 && parent[0] == '/') return true;
    return child[parent_len] == '/';
}

bool sandbox_is_path_prefix(const char *parent, const char *child) {
    return is_path_prefix(parent, child);
}

static int visited_set_add(struct expansion_context *ctx, const char *path) {
    if (ctx->failed) return -1;
    if (ctx->visited_count >= MAX_VISITED_PATHS) return 0;
    if (ctx->visited_count >= ctx->visited_capacity) {
        ctx->visited_capacity = ctx->visited_capacity ? ctx->visited_capacity * 2 : 32;
        char **new_visited = realloc(ctx->visited, ctx->visited_capacity * sizeof(char *));
        if (!new_visited) {
            ctx->failed = 1;
            return -1;
        }
        ctx->visited = new_visited;
    }
    ctx->visited[ctx->visited_count++] = strdup(path);
    if (!ctx->visited[ctx->visited_count - 1]) {
        ctx->failed = 1;
        return -1;
    }
    return 0;
}

static bool visited_set_contains(struct expansion_context *ctx, const char *path) {
    for (int i = 0; i < ctx->visited_count; i++) {
        if (strcmp(ctx->visited[i], path) == 0) {
            return true;
        }
    }
    return false;
}

static int queue_push(struct expansion_context *ctx, const char *path, uint64_t access) {
    if (ctx->failed) return -1;
    if (ctx->queue_size >= ctx->queue_capacity) {
        DEBUG_PRINT("SANDBOX: queue overflow, discarding path '%s'\n", path);
        return 0;
    }
    int idx = (ctx->queue_head + ctx->queue_size) % ctx->queue_capacity;
    ctx->queue[idx].path = strdup(path);
    if (!ctx->queue[idx].path) {
        ctx->failed = 1;
        return -1;
    }
    ctx->queue[idx].access = access;
    ctx->queue_size++;
    return 0;
}

static bool queue_empty(struct expansion_context *ctx) {
    return ctx->queue_size == 0;
}

static struct queue_entry queue_pop(struct expansion_context *ctx) {
    struct queue_entry empty = {NULL, 0};
    if (ctx->queue_size == 0) return empty;
    int idx = ctx->queue_head;
    ctx->queue_head = (ctx->queue_head + 1) % ctx->queue_capacity;
    ctx->queue_size--;
    return ctx->queue[idx];
}

static void scan_dir_for_external_symlinks(struct expansion_context *ctx, const char *path, uint64_t access,
                                          struct denied_entry *deny, int deny_count) {
    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char child_path[PATH_MAX];
        snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(child_path, &st) != 0) {
            continue;
        }

        if (!S_ISLNK(st.st_mode)) {
            continue;
        }

        char resolved[PATH_MAX];
        if (realpath(child_path, resolved) == NULL) {
            continue;
        }

        struct stat target_st;
        if (stat(resolved, &target_st) != 0 || !S_ISDIR(target_st.st_mode)) {
            continue;
        }

        if (is_under_deny(resolved, strlen(resolved), deny, deny_count)) {
            continue;
        }

        if (!visited_set_contains(ctx, resolved)) {
            visited_set_add(ctx, resolved);
            queue_push(ctx, resolved, access);
        }
    }
    closedir(dir);
}

static void expand_allow_path_recursive(struct expansion_context *ctx, const char *path, uint64_t access,
                                        struct denied_entry *deny, int deny_count) {
    if (ctx->failed) return;

    DIR *dir = opendir(path);
    if (!dir) {
        DEBUG_PRINT("SANDBOX: cannot open '%s': %s\n", path, strerror(errno));
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char child_path[PATH_MAX];
        snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name);

        if (is_under_deny(child_path, strlen(child_path), deny, deny_count)) {
            continue;
        }

        struct stat st;
        if (lstat(child_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!visited_set_contains(ctx, child_path)) {
                visited_set_add(ctx, child_path);
                add_expanded_path(ctx, child_path, access);
                scan_dir_for_external_symlinks(ctx, child_path, access, deny, deny_count);
                if (has_deny_under(child_path, strlen(child_path), deny, deny_count)) {
                    queue_push(ctx, child_path, access);
                }
            }
        } else if (S_ISLNK(st.st_mode)) {
            char resolved[PATH_MAX];
            if (realpath(child_path, resolved) == NULL) {
                DEBUG_PRINT("SANDBOX: cannot resolve symlink '%s'\n", child_path);
                continue;
            }
            struct stat target_st;
            if (stat(resolved, &target_st) != 0 || !S_ISDIR(target_st.st_mode)) {
                continue;
            }
            if (is_under_deny(resolved, strlen(resolved), deny, deny_count)) {
                DEBUG_PRINT("SANDBOX: symlink target '%s' is under deny, ignoring\n", resolved);
                continue;
            }
            if (is_path_prefix(path, resolved)) {
                if (!visited_set_contains(ctx, resolved)) {
                    visited_set_add(ctx, resolved);
                    add_expanded_path(ctx, resolved, access);
                    scan_dir_for_external_symlinks(ctx, resolved, access, deny, deny_count);
                    expand_allow_path_recursive(ctx, resolved, access, deny, deny_count);
                }
            } else {
                if (!visited_set_contains(ctx, resolved)) {
                    queue_push(ctx, resolved, access);
                }
            }
        }
    }
    closedir(dir);
}

static int expand_allow_list(struct expansion_context *ctx, struct allowed_entry *allow, int allow_count,
                       struct denied_entry *deny, int deny_count) {
    for (int i = 0; i < allow_count; i++) {
        if (allow[i].resolved == NULL) continue;
        if (is_under_deny(allow[i].resolved, strlen(allow[i].resolved), deny, deny_count)) {
            continue;
        }
        visited_set_add(ctx, allow[i].resolved);
        if (has_deny_under(allow[i].resolved, strlen(allow[i].resolved), deny, deny_count)) {
            add_expanded_path(ctx, allow[i].resolved, allow[i].access);
            expand_allow_path_recursive(ctx, allow[i].resolved, allow[i].access, deny, deny_count);
        } else {
            add_expanded_path(ctx, allow[i].resolved, allow[i].access);
            scan_dir_for_external_symlinks(ctx, allow[i].resolved, allow[i].access, deny, deny_count);
        }
    }

    while (!queue_empty(ctx)) {
        struct queue_entry entry = queue_pop(ctx);
        if (visited_set_contains(ctx, entry.path)) {
            free(entry.path);
            continue;
        }
        visited_set_add(ctx, entry.path);
        if (has_deny_under(entry.path, strlen(entry.path), deny, deny_count)) {
            expand_allow_path_recursive(ctx, entry.path, entry.access, deny, deny_count);
        } else {
            add_expanded_path(ctx, entry.path, entry.access);
        }
        free(entry.path);
    }

    ctx->result_paths = ctx->paths;
    ctx->result_count = ctx->path_count;
    ctx->paths = NULL;
    ctx->path_count = 0;

    return ctx->failed ? -1 : 0;
}

static struct expanded_path *g_result_paths = NULL;
static int g_result_count = 0;

static void free_result_paths(void) {
    for (int i = 0; i < g_result_count; i++) {
        free(g_result_paths[i].path);
    }
    free(g_result_paths);
    g_result_paths = NULL;
    g_result_count = 0;
}

int sandbox_expand_paths(struct allowed_entry *allow, int allow_count,
                         struct denied_entry *deny, int deny_count) {
    struct expansion_context ctx;
    expansion_context_init(&ctx);

    int result = expand_allow_list(&ctx, allow, allow_count, deny, deny_count);

    free_result_paths();
    g_result_paths = ctx.result_paths;
    g_result_count = ctx.result_count;
    ctx.result_paths = NULL;
    ctx.result_count = 0;

    expansion_context_free(&ctx);

    return result;
}

int sandbox_get_expanded_count(void) {
    return g_result_count;
}

const char *sandbox_get_expanded_path(int index) {
    if (index >= 0 && index < g_result_count)
        return g_result_paths[index].path;
    return NULL;
}

uint64_t sandbox_get_expanded_access(int index) {
    if (index >= 0 && index < g_result_count)
        return g_result_paths[index].access;
    return 0;
}

void sandbox_expansion_cleanup(void) {
    free_result_paths();
}

int validate_landlock_paths(void) {
    const char *allow_env = getenv("READONLYBOX_HARD_ALLOW");
    const char *deny_env = getenv("READONLYBOX_HARD_DENY");

    if ((!allow_env || !*allow_env) && (!deny_env || !*deny_env)) {
        return 0;
    }

    int allow_count = 0;
    int deny_count = 0;
    struct allowed_entry *allow_entries = sandbox_parse_allow_list(allow_env, &allow_count, real_path_validator, NULL);
    struct denied_entry *deny_entries = sandbox_parse_deny_list(deny_env, &deny_count, real_path_validator, NULL);

    if (allow_count == 0 && deny_count == 0) {
        if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
        if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
        return 0;
    }

    if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
    if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);

    return 0;
}

static soft_mode_t landlock_access_to_soft_mode(uint64_t landlock_access) {
    if (landlock_access & LANDLOCK_ACCESS_FS_REFER) {
        return SOFT_MODE_RWX;
    }
    if (landlock_access & LANDLOCK_ACCESS_FS_EXECUTE) {
        if (landlock_access & (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG)) {
            return SOFT_MODE_RWX;
        }
        return SOFT_MODE_RX;
    }
    if (landlock_access & (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
                           LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                           LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_TRUNCATE)) {
        return SOFT_MODE_RW;
    }
    if (landlock_access & (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)) {
        return SOFT_MODE_RO;
    }
    return SOFT_MODE_RO;
}

static int apply_landlock(void) {
    const char *allow_env = getenv("READONLYBOX_HARD_ALLOW");
    const char *deny_env = getenv("READONLYBOX_HARD_DENY");

    if ((!allow_env || !*allow_env) && (!deny_env || !*deny_env)) {
        return 0;
    }

    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        LOG_ERROR("Landlock not supported (ABI version %d)", abi);
        return -1;
    }

    int allow_count = 0;
    int deny_count = 0;
    struct allowed_entry *allow_entries = sandbox_parse_allow_list(allow_env, &allow_count, real_path_validator, NULL);
    struct denied_entry *deny_entries = sandbox_parse_deny_list(deny_env, &deny_count, real_path_validator, NULL);

    if (allow_count == 0 && deny_count == 0) {
        if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
        if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
        return 0;
    }

    allow_count = sandbox_remove_overlaps(allow_entries, allow_count, deny_entries, deny_count);

    sandbox_simplify_allow_list(&allow_entries, &allow_count);
    sandbox_simplify_deny_list(&deny_entries, &deny_count);

    int expand_result = sandbox_expand_paths(allow_entries, allow_count, deny_entries, deny_count);
    if (expand_result != 0) {
        LOG_WARN("Failed to expand Landlock paths, falling back to ptrace enforcement");
        sandbox_expansion_cleanup();
        if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
        if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
        return -1;
    }

    if (g_result_count == 0) {
        LOG_FATAL("Hard allow/deny options resulted in no allowed paths - possible configuration error");
        sandbox_expansion_cleanup();
        if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
        if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
    }

    if (g_result_count > MAX_EXPANDED_PATHS) {
        LOG_WARN("Too many Landlock rules (%d), falling back to ptrace enforcement", g_result_count);
        sandbox_expansion_cleanup();
        if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
        if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
        return -1;
    }

    uint64_t all_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                          LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_EXECUTE |
                          LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                          LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                          LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                          LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                          LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER;

    uint64_t handled_access_fs = all_access;

    switch (abi) {
    case 1:
        handled_access_fs &= ~(LANDLOCK_ACCESS_FS_REFER);
        /* fallthrough */
    case 2:
        handled_access_fs &= ~(LANDLOCK_ACCESS_FS_TRUNCATE);
        /* fallthrough */
    case 3:
        /* no network access used */
        /* fallthrough */
    case 4:
        handled_access_fs &= ~(LANDLOCK_ACCESS_FS_IOCTL_DEV);
        /* fallthrough */
    case 5:
        /* scoped flags not used */
        break;
    default:
        break;
    }

    struct landlock_ruleset_attr attr = {
        .handled_access_fs = handled_access_fs,
        .handled_access_net = 0,
        .scoped = 0,
    };

    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        LOG_ERRNO("Failed to create Landlock ruleset");
        sandbox_expansion_cleanup();
        if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
        if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
        return -1;
    }

    for (int i = 0; i < g_result_count; i++) {
        int dir_fd = open(g_result_paths[i].path, O_NOFOLLOW | O_PATH | O_CLOEXEC);
        if (dir_fd < 0) {
            LOG_ERROR("Landlock: cannot open allow path '%s': %s",
                    g_result_paths[i].path, strerror(errno));
            continue;
        }

        struct landlock_path_beneath_attr path_attr = {
            .allowed_access = g_result_paths[i].access & handled_access_fs,
            .parent_fd = dir_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                    &path_attr, 0) != 0) {
            LOG_ERROR("Landlock: failed to add allow rule for '%s' (access 0x%llx): %s",
                    g_result_paths[i].path, (unsigned long long)g_result_paths[i].access, strerror(errno));
        } else {
            DEBUG_PRINT("SANDBOX: Landlock allow rule for '%s' (access 0x%llx)\n",
                        g_result_paths[i].path, (unsigned long long)g_result_paths[i].access);
        }
        close(dir_fd);
    }

    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        LOG_ERRNO("Failed to enforce Landlock ruleset");
        fprintf(stderr, "landlock setup failed, activating soft policy fallback.\n");
        soft_policy_t *soft = soft_policy_get_global();
        for (int i = 0; i < g_result_count; i++) {
            soft_mode_t mode = landlock_access_to_soft_mode(g_result_paths[i].access);
            soft_policy_add_rule(soft, g_result_paths[i].path, mode);
        }
        close(ruleset_fd);
        sandbox_expansion_cleanup();
        if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
        if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
        return -2;
    }
    close(ruleset_fd);

    sandbox_expansion_cleanup();
    if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
    if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
    return 0;
}

/* Seccomp filter for blocking network syscalls.
 * Returns 0 on success, -1 on failure. */
static int apply_no_network(void) {
    if (!getenv("READONLYBOX_NO_NETWORK")) return 0;

#if defined(__i386__)
    LOG_ERROR("Seccomp network filtering is not supported on i386 (network syscalls use socketcall)");
    return -1;
#endif

    /* BPF filter program to block network syscalls.
     * Uses __NR_* syscall numbers for portability across architectures. */
    struct sock_filter filter[] = {
        /* Load syscall number from arch-specific location */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),

        /* Check if syscall is socket */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is connect */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is accept */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is sendto */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is recvfrom */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is sendmsg */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is recvmsg */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is shutdown */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_shutdown, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is bind */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is listen */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is getsockname */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockname, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is getpeername */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpeername, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is setsockopt */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setsockopt, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is getsockopt */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockopt, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is accept4 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept4, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is recvmmsg */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is sendmmsg */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Note: sendfile(2) and splice(2) are NOT blocked here because
         * they cannot be used for network access without socket().
         * - sendfile's out_fd must be a socket, which requires socket()
         * - splice requires at least one fd to be a pipe
         * Since socket(), connect(), accept(), etc. are all blocked above,
         * blocking sendfile/splice would only break legitimate file-to-file
         * copies and adds no security benefit. */

        /* Allow all other syscalls */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    /* Install seccomp filter */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        LOG_ERRNO("Failed to install seccomp filter");
        return -1;
    }
    DEBUG_PRINT("SANDBOX: Seccomp network filter applied\n");
    return 0;
}

/* Apply all sandbox restrictions as defined by environment variables.
 * Must be called after the child has been traced (PTRACE_TRACEME)
 * but before dropping privileges. */
void apply_sandboxing(void) {
    apply_memory_limit();
    int landlock_result = apply_landlock();
    if (landlock_result == -2) {
        soft_policy_t *soft = soft_policy_get_global();
        DEBUG_PRINT("SANDBOX: Soft policy active with %d rules (Landlock fallback)\n", soft->count);
    }
    if (getenv("READONLYBOX_NO_NETWORK") && apply_no_network() != 0) {
        LOG_FATAL("--no-network requested but seccomp failed to apply. Cannot enforce network restriction.");
    }
}
