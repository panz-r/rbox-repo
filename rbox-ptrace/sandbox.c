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
#include <linux/filter.h>

#include "sandbox.h"
#include "rule_engine.h"
#include "landlock_bridge.h"
#include "debug.h"

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER 0
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE 0
#endif

extern soft_ruleset_t *get_hard_fallthrough_fs_rules(void);

static void apply_memory_limit(void) {
    const char *limit_str = getenv("READONLYBOX_MEMORY_LIMIT");
    if (!limit_str || !*limit_str) return;

    char *endptr;
    errno = 0;
    unsigned long long val = strtoull(limit_str, &endptr, 10);

    if (endptr == limit_str || errno == ERANGE) {
        LOG_ERROR("Invalid memory limit format: %s", limit_str);
        return;
    }

    if (val == 0) {
        DEBUG_PRINT("SANDBOX: Memory limit is 0, skipping\n");
        return;
    }

    unsigned long long multiplier = 1;
    bool has_multiplier = false;
    switch (*endptr) {
        case 'K':
        case 'k':
            multiplier = 1024ULL;
            has_multiplier = true;
            break;
        case 'M':
        case 'm':
            multiplier = 1024ULL * 1024ULL;
            has_multiplier = true;
            break;
        case 'G':
        case 'g':
            multiplier = 1024ULL * 1024ULL * 1024ULL;
            has_multiplier = true;
            break;
        case 'T':
        case 't':
            multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            has_multiplier = true;
            break;
        default:
            break;
    }

    if (has_multiplier) {
        endptr++;
    }

    if (*endptr != '\0') {
        LOG_ERROR("Invalid memory limit format (trailing characters): %s", limit_str);
        return;
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

static bool real_path_validator(const char *path, void *ctx) {
    (void)ctx;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
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
            LOG_ERROR("hard-allow: cannot resolve path '%s': %s", path, strerror(errno));
            free(path);
            continue;
        }

        if (!validator(resolved, ctx)) {
            LOG_ERROR("hard-allow: '%s' is not a directory", resolved);
            free(resolved);
            free(path);
            continue;
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
            LOG_ERROR("hard-deny: cannot resolve path '%s': %s", path, strerror(errno));
            free(path);
            continue;
        }

        if (!validator(resolved, ctx)) {
            LOG_ERROR("hard-deny: '%s' is not a directory", resolved);
            free(resolved);
            free(path);
            continue;
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

static int apply_landlock(int *landlock_failed) {
    const char *allow_env = getenv("READONLYBOX_HARD_ALLOW");
    const char *deny_env = getenv("READONLYBOX_HARD_DENY");

    *landlock_failed = 0;

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
    struct allowed_entry *allow_entries = sandbox_parse_allow_list(allow_env, &allow_count,
                                                                 real_path_validator, NULL);
    struct denied_entry *deny_entries = sandbox_parse_deny_list(deny_env, &deny_count,
                                                               real_path_validator, NULL);

    if (allow_count == 0 && deny_count == 0) {
        if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
        if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
        return 0;
    }

    soft_ruleset_t *hard_rules = soft_ruleset_new();
    if (!hard_rules) {
        LOG_ERROR("Failed to create ruleset for hard policy");
        sandbox_free_allow_entries(allow_entries, allow_count);
        sandbox_free_deny_entries(deny_entries, deny_count);
        return -2;
    }

    for (int i = 0; i < allow_count; i++) {
        char recursive_path[PATH_MAX];
        size_t path_len = strlen(allow_entries[i].resolved);
        while (path_len > 1 && allow_entries[i].resolved[path_len - 1] == '/') {
            path_len--;
        }
        if (path_len + 4 >= PATH_MAX) {
            LOG_ERROR("Path too long for Landlock expansion: %s", allow_entries[i].resolved);
            continue;
        }
        if (path_len == 1 && allow_entries[i].resolved[0] == '/') {
            snprintf(recursive_path, sizeof(recursive_path), "/...");
        } else {
            snprintf(recursive_path, sizeof(recursive_path), "%.*s/...", (int)path_len, allow_entries[i].resolved);
        }
        soft_ruleset_add_rule_at_layer(hard_rules, 0, recursive_path, allow_entries[i].access,
                                      SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    }

    for (int i = 0; i < deny_count; i++) {
        char recursive_path[PATH_MAX];
        size_t path_len = strlen(deny_entries[i].resolved);
        while (path_len > 1 && deny_entries[i].resolved[path_len - 1] == '/') {
            path_len--;
        }
        if (path_len + 4 >= PATH_MAX) {
            LOG_ERROR("Path too long for Landlock expansion: %s", deny_entries[i].resolved);
            continue;
        }
        if (path_len == 1 && deny_entries[i].resolved[0] == '/') {
            snprintf(recursive_path, sizeof(recursive_path), "/...");
        } else {
            snprintf(recursive_path, sizeof(recursive_path), "%.*s/...", (int)path_len, deny_entries[i].resolved);
        }
        soft_ruleset_add_rule_at_layer(hard_rules, 0, recursive_path, SOFT_ACCESS_DENY,
                                      SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    }

    landlock_builder_t *builder = soft_ruleset_to_landlock(hard_rules, NULL);
    if (!builder) {
        LOG_ERROR("Failed to compile ruleset to Landlock, falling back to soft policy");
        extern soft_ruleset_t *hard_fallthrough_fs_rules;
        hard_fallthrough_fs_rules = hard_rules;
        sandbox_free_allow_entries(allow_entries, allow_count);
        sandbox_free_deny_entries(deny_entries, deny_count);
        *landlock_failed = 1;
        return -2;
    }

    if (landlock_builder_prepare(builder, abi, true) != 0) {
        LOG_ERROR("Failed to prepare Landlock ruleset");
        extern soft_ruleset_t *hard_fallthrough_fs_rules;
        hard_fallthrough_fs_rules = hard_rules;
        landlock_builder_free(builder);
        sandbox_free_allow_entries(allow_entries, allow_count);
        sandbox_free_deny_entries(deny_entries, deny_count);
        *landlock_failed = 1;
        return -2;
    }

    size_t rule_count;
    const landlock_rule_t *rules = landlock_builder_get_rules(builder, &rule_count);

    uint64_t all_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                          LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_EXECUTE |
                          LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                          LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                          LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                          LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                          LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER;

    uint64_t handled_access_fs = all_access;

    if (abi < 3) {
        handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
    }
    if (abi < 2) {
        handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    }

    struct landlock_ruleset_attr attr = {
        .handled_access_fs = handled_access_fs,
        .handled_access_net = 0,
        .scoped = 0,
    };

    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        LOG_ERRNO("Failed to create Landlock ruleset");
        landlock_builder_free(builder);
        sandbox_free_allow_entries(allow_entries, allow_count);
        sandbox_free_deny_entries(deny_entries, deny_count);
        return -2;
    }

    int rule_failures = 0;
    for (size_t i = 0; i < rule_count; i++) {
        int dir_fd = landlock_rule_open_fd(&rules[i], 0);
        if (dir_fd < 0) {
            LOG_ERROR("Landlock: cannot open path '%s': %s",
                    rules[i].path, strerror(errno));
            rule_failures++;
            continue;
        }

        struct landlock_path_beneath_attr path_attr = {
            .allowed_access = rules[i].access & handled_access_fs,
            .parent_fd = dir_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                    &path_attr, 0) != 0) {
            LOG_ERROR("Landlock: failed to add rule for '%s' (access 0x%llx): %s",
                    rules[i].path, (unsigned long long)rules[i].access, strerror(errno));
            rule_failures++;
        } else {
            DEBUG_PRINT("SANDBOX: Landlock rule for '%s' (access 0x%llx)\n",
                        rules[i].path, (unsigned long long)rules[i].access);
        }
        close(dir_fd);
    }

    if (rule_failures > 0) {
        LOG_ERROR("Landlock: %d rule(s) failed to apply", rule_failures);
        extern soft_ruleset_t *hard_fallthrough_fs_rules;
        hard_fallthrough_fs_rules = hard_rules;
        landlock_builder_free(builder);
        close(ruleset_fd);
        sandbox_free_allow_entries(allow_entries, allow_count);
        sandbox_free_deny_entries(deny_entries, deny_count);
        *landlock_failed = 1;
        return -2;
    }

    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        LOG_ERRNO("Failed to enforce Landlock ruleset");
        extern soft_ruleset_t *hard_fallthrough_fs_rules;
        hard_fallthrough_fs_rules = hard_rules;
        landlock_builder_free(builder);
        close(ruleset_fd);
        sandbox_free_allow_entries(allow_entries, allow_count);
        sandbox_free_deny_entries(deny_entries, deny_count);
        *landlock_failed = 1;
        return -2;
    }

    soft_ruleset_free(hard_rules);
    landlock_builder_free(builder);
    close(ruleset_fd);
    sandbox_free_allow_entries(allow_entries, allow_count);
    sandbox_free_deny_entries(deny_entries, deny_count);
    return 0;
}

/* Seccomp filter for blocking network syscalls.
 * Returns 0 on success, -1 on failure. */
static int apply_no_network(void) {
    if (!getenv("READONLYBOX_NO_NETWORK")) return 0;

#if !defined(__x86_64__) && !defined(__aarch64__) && !defined(__riscv)
    LOG_ERROR("Seccomp network filtering not supported on this architecture");
    return -1;
#endif

    /* BPF filter program to block network syscalls.
     * Uses __NR_* syscall numbers for portability across architectures.
     * Note: SECCOMP_RET_ERRNO requires Linux 4.14+. */
    struct sock_filter filter[] = {
        /* Load syscall number from arch-specific location */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),

        /* Check if syscall is socket */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is connect */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is bind */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is listen */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is accept */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is accept4 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept4, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is getsockopt */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockopt, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is setsockopt */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setsockopt, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is getpeername */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpeername, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is getsockname */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockname, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is socketpair */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socketpair, 0, 1),
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

        /* Allow all other syscalls */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        LOG_ERRNO("Failed to set no_new_privs");
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        LOG_ERRNO("Failed to install seccomp filter");
        return -1;
    }

    DEBUG_PRINT("SANDBOX: Network syscalls blocked via seccomp\n");
    return 0;
}

/* Apply all sandbox restrictions as defined by environment variables.
 * Must be called after the child has been traced (PTRACE_TRACEME)
 * but before dropping privileges. */
void apply_sandboxing(void) {
    apply_memory_limit();
    int landlock_failed = 0;
    int landlock_result = apply_landlock(&landlock_failed);
    if (landlock_result == -2 || landlock_failed) {
        extern soft_ruleset_t *hard_fallthrough_fs_rules;
        DEBUG_PRINT("SANDBOX: Hard fallthrough policy active with %zu rules\n",
                hard_fallthrough_fs_rules ? soft_ruleset_rule_count(hard_fallthrough_fs_rules) : 0);
    }
    if (getenv("READONLYBOX_NO_NETWORK") && apply_no_network() != 0) {
        LOG_FATAL("--no-network requested but seccomp failed to apply. Cannot enforce network restriction.");
    }
}
