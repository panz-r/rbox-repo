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
#include "debug.h"

static void apply_memory_limit(void) {
    const char *limit_str = getenv("READONLYBOX_MEMORY_LIMIT");
    if (!limit_str || !*limit_str) return;

    rlim_t limit = 0;
    char *endptr;
    unsigned long long val = strtoull(limit_str, &endptr, 10);

    if (endptr == limit_str) {
        fprintf(stderr, "readonlybox-ptrace: Invalid memory limit format: %s\n", limit_str);
        return;
    }

    if (val == 0) {
        DEBUG_PRINT("SANDBOX: Memory limit is 0, skipping\n");
        return;
    }

    switch (*endptr) {
        case 'K':
        case 'k':
            val *= 1024;
            break;
        case 'M':
        case 'm':
            val *= 1024 * 1024;
            break;
        case 'G':
        case 'g':
            val *= 1024 * 1024 * 1024;
            break;
        default:
            break;
    }

    limit = (rlim_t)val;
    struct rlimit rlim = {limit, limit};
    if (setrlimit(RLIMIT_AS, &rlim) != 0) {
        fprintf(stderr, "readonlybox-ptrace: Failed to set memory limit: %s\n", strerror(errno));
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
        fprintf(stderr, "sandbox_parse_allow_list: NULL validator\n");
        exit(1);
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
        if (!path) goto next_token;

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
            fprintf(stderr, "readonlybox-ptrace: hard-allow: cannot resolve path '%s': %s\n", path, strerror(errno));
            free(path);
            exit(1);
        }

        if (!validator(resolved, ctx)) {
            fprintf(stderr, "readonlybox-ptrace: hard-allow: '%s' is not a directory\n", resolved);
            free(resolved);
            free(path);
            exit(1);
        }

        if (count >= capacity) {
            capacity *= 2;
            struct allowed_entry *new_entries = realloc(entries, capacity * sizeof(struct allowed_entry));
            if (!new_entries) {
                free(resolved);
                free(path);
                goto next_token;
            }
            entries = new_entries;
        }

        entries[count].original = path;
        entries[count].resolved = resolved;
        entries[count].access = access;
        count++;

    next_token:
        token = strtok_r(NULL, ",", &saveptr);
    }

    free(copy);
    *out_count = count;
    return entries;
}

struct denied_entry *sandbox_parse_deny_list(const char *env_value, int *out_count,
                                            sandbox_path_validator_t validator, void *ctx) {
    if (!validator) {
        fprintf(stderr, "sandbox_parse_deny_list: NULL validator\n");
        exit(1);
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
        if (!path) goto next_token;

        char *resolved = realpath(path, NULL);
        if (!resolved) {
            fprintf(stderr, "readonlybox-ptrace: hard-deny: cannot resolve path '%s': %s\n", path, strerror(errno));
            free(path);
            exit(1);
        }

        if (!validator(resolved, ctx)) {
            fprintf(stderr, "readonlybox-ptrace: hard-deny: '%s' is not a directory\n", resolved);
            free(resolved);
            free(path);
            exit(1);
        }

        if (count >= capacity) {
            capacity *= 2;
            struct denied_entry *new_entries = realloc(entries, capacity * sizeof(struct denied_entry));
            if (!new_entries) {
                free(resolved);
                free(path);
                goto next_token;
            }
            entries = new_entries;
        }

        entries[count].original = path;
        entries[count].resolved = resolved;
        count++;

    next_token:
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
        for (int j = 0; j < deny_count; j++) {
            if (strcmp(allow[i].resolved, deny[j].resolved) == 0) {
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

static void apply_landlock(void) {
    const char *allow_env = getenv("READONLYBOX_HARD_ALLOW");
    const char *deny_env = getenv("READONLYBOX_HARD_DENY");

    if ((!allow_env || !*allow_env) && (!deny_env || !*deny_env)) {
        return;
    }

    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        fprintf(stderr, "readonlybox-ptrace: Landlock not supported (ABI version %d)\n", abi);
        return;
    }

    int allow_count = 0;
    int deny_count = 0;
    struct allowed_entry *allow_entries = sandbox_parse_allow_list(allow_env, &allow_count, real_path_validator, NULL);
    struct denied_entry *deny_entries = sandbox_parse_deny_list(deny_env, &deny_count, real_path_validator, NULL);

    if (allow_count == 0 && deny_count == 0) {
        return;
    }

    allow_count = sandbox_remove_overlaps(allow_entries, allow_count, deny_entries, deny_count);

    sandbox_simplify_allow_list(&allow_entries, &allow_count);
    sandbox_simplify_deny_list(&deny_entries, &deny_count);

    uint64_t handled_access_fs = sandbox_calc_handled_access(allow_entries, allow_count);

    uint64_t all_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                          LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_EXECUTE |
                          LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                          LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                          LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                          LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                          LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER;

    if (handled_access_fs == 0) {
        handled_access_fs = all_access;
    }

    struct landlock_ruleset_attr attr = {
        .handled_access_fs = handled_access_fs,
        .handled_access_net = 0,
        .scoped = 0,
    };

    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "readonlybox-ptrace: Failed to create Landlock ruleset: %s\n", strerror(errno));
        goto cleanup;
    }

    for (int i = 0; i < deny_count; i++) {
        int dir_fd = open(deny_entries[i].resolved, O_PATH | O_CLOEXEC);
        if (dir_fd < 0) {
            fprintf(stderr, "readonlybox-ptrace: Landlock: cannot open deny path '%s': %s\n",
                    deny_entries[i].resolved, strerror(errno));
            continue;
        }

        struct landlock_path_beneath_attr path_attr = {
            .allowed_access = 0,
            .parent_fd = dir_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                    &path_attr, 0) != 0) {
            fprintf(stderr, "readonlybox-ptrace: Landlock: failed to add deny rule for '%s': %s\n",
                    deny_entries[i].resolved, strerror(errno));
        } else {
            DEBUG_PRINT("SANDBOX: Landlock deny rule for '%s'\n", deny_entries[i].resolved);
        }
        close(dir_fd);
    }

    for (int i = 0; i < allow_count; i++) {
        int dir_fd = open(allow_entries[i].resolved, O_PATH | O_CLOEXEC);
        if (dir_fd < 0) {
            fprintf(stderr, "readonlybox-ptrace: Landlock: cannot open allow path '%s': %s\n",
                    allow_entries[i].resolved, strerror(errno));
            continue;
        }

        struct landlock_path_beneath_attr path_attr = {
            .allowed_access = allow_entries[i].access,
            .parent_fd = dir_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                    &path_attr, 0) != 0) {
            fprintf(stderr, "readonlybox-ptrace: Landlock: failed to add allow rule for '%s' (access 0x%llx): %s\n",
                    allow_entries[i].resolved, (unsigned long long)allow_entries[i].access, strerror(errno));
        } else {
            DEBUG_PRINT("SANDBOX: Landlock allow rule for '%s' (access 0x%llx)\n",
                        allow_entries[i].resolved, (unsigned long long)allow_entries[i].access);
        }
        close(dir_fd);
    }

    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        fprintf(stderr, "readonlybox-ptrace: Failed to enforce Landlock ruleset: %s\n", strerror(errno));
    } else {
        DEBUG_PRINT("SANDBOX: Landlock enforced\n");
    }
    close(ruleset_fd);

cleanup:
    if (allow_entries) sandbox_free_allow_entries(allow_entries, allow_count);
    if (deny_entries) sandbox_free_deny_entries(deny_entries, deny_count);
}

/* Seccomp filter for blocking network syscalls */
static void apply_no_network(void) {
    if (!getenv("READONLYBOX_NO_NETWORK")) return;

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

        /* Check if syscall is sendfile (can send data over socket) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendfile, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Check if syscall is splice (move data between sockets/files) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_splice, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        /* Allow all other syscalls */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    /* Install seccomp filter */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        fprintf(stderr, "readonlybox-ptrace: Failed to install seccomp filter: %s\n", strerror(errno));
    } else {
        DEBUG_PRINT("SANDBOX: Seccomp network filter applied\n");
    }
}

/* Apply all sandbox restrictions as defined by environment variables.
 * Must be called after the child has been traced (PTRACE_TRACEME)
 * but before dropping privileges. */
void apply_sandboxing(void) {
    apply_memory_limit();
    apply_landlock();
    apply_no_network();
}
