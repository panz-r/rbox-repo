/*
 * sandbox.c - Sandboxing functionality for rbox-ptrace
 *
 * Implements Landlock filesystem restrictions, seccomp network blocking,
 * and memory limits via setrlimit.
 *
 * Configuration is read from environment variables:
 * - READONLYBOX_MEMORY_LIMIT: memory limit (e.g., "256M", "1G")
 * - READONLYBOX_NO_NETWORK: if set, block network access
 * - READONLYBOX_LANDLOCK_PATHS: colon-separated allowed paths
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

/* Apply memory limit from READONLYBOX_MEMORY_LIMIT environment variable */
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

    /* Treat 0 as "no limit" (skip) */
    if (val == 0) {
        DEBUG_PRINT("SANDBOX: Memory limit is 0, skipping\n");
        return;
    }

    /* Multiply by unit if present */
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

/* Apply Landlock filesystem restrictions from READONLYBOX_LANDLOCK_PATHS
 *
 * Path format: path[:mode][,path[:mode],...]
 * Modes: ro (read-only), rx (read/execute), rw (read/write), rwx (read/write/execute)
 * Examples:
 *   /tmp:rw,/home:ro        - /tmp with read/write, /home with read-only
 *   /usr/bin:rwx,/tmp:rw     - /usr/bin with full access, /tmp with read/write
 *
 * Default mode is rx (read/execute) if not specified.
 */
static void apply_landlock(void) {
    const char *paths = getenv("READONLYBOX_LANDLOCK_PATHS");
    if (!paths || !*paths) return;

    /* Check if Landlock is available */
    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        fprintf(stderr, "readonlybox-ptrace: Landlock not supported (ABI version %d)\n", abi);
        return;
    }

    /* Parse paths and collect info.
     * Format: /path1:mode1,/path2:mode2,...
     * Mode suffix is optional, defaults to "rx".
     * We need to first pass through to parse and collect access requirements. */
    char *paths_copy = strdup(paths);
    if (!paths_copy) return;

    /* Structure to hold parsed path info */
    struct landlock_path_info {
        char *path;
        char *resolved_path;
        __u64 access;
        int dir_fd;
    };
    struct landlock_path_info path_info[64];
    int path_count = 0;

    /* Access mode flags */
    __u64 access_ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    __u64 access_rx = access_ro | LANDLOCK_ACCESS_FS_EXECUTE;
    __u64 access_rw = access_ro | LANDLOCK_ACCESS_FS_WRITE_FILE |
                      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                      LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                      LANDLOCK_ACCESS_FS_TRUNCATE;
    __u64 access_rwx = access_rw | LANDLOCK_ACCESS_FS_EXECUTE |
                       LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                       LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
                       LANDLOCK_ACCESS_FS_REFER;

    __u64 all_access = 0;

    /* First pass: parse paths and modes */
    char *saveptr;
    char *token = strtok_r(paths_copy, ",", &saveptr);
    while (token && path_count < 64) {
        /* Find mode suffix (last :ro, :rx, :rw, :rwx) */
        char *path = token;
        __u64 access = access_rx;  /* default */

        char *colon = strrchr(token, ':');
        if (colon && strlen(colon) >= 3) {
            if (strcmp(colon + 1, "ro") == 0) {
                access = access_ro;
                *colon = '\0';
            } else if (strcmp(colon + 1, "rx") == 0) {
                access = access_rx;
                *colon = '\0';
            } else if (strcmp(colon + 1, "rw") == 0) {
                access = access_rw;
                *colon = '\0';
            } else if (strcmp(colon + 1, "rwx") == 0) {
                access = access_rwx;
                *colon = '\0';
            }
            /* else not a mode suffix, keep as part of path */
        }

        path_info[path_count].path = strdup(path);
        path_info[path_count].access = access;
        path_info[path_count].resolved_path = NULL;
        path_info[path_count].dir_fd = -1;
        all_access |= access;
        path_count++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(paths_copy);

    if (all_access == 0) {
        DEBUG_PRINT("SANDBOX: Landlock no paths to add\n");
        return;
    }

    /* Create ruleset with union of all required access */
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = all_access,
        .handled_access_net = 0,
        .scoped = 0,
    };

    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "readonlybox-ptrace: Failed to create Landlock ruleset: %s\n", strerror(errno));
        for (int i = 0; i < path_count; i++) {
            free(path_info[i].path);
        }
        return;
    }

    /* Open each path and add rule */
    for (int i = 0; i < path_count; i++) {
        /* Open the path first to avoid TOCTOU race */
        int dir_fd = open(path_info[i].path, O_PATH | O_CLOEXEC);
        if (dir_fd < 0) {
            fprintf(stderr, "readonlybox-ptrace: Landlock: cannot open path '%s': %s\n",
                    path_info[i].path, strerror(errno));
            continue;
        }

        /* Check if it's a directory */
        struct stat st;
        if (fstat(dir_fd, &st) < 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "readonlybox-ptrace: Landlock: path '%s' is not a directory, skipping\n",
                    path_info[i].path);
            close(dir_fd);
            continue;
        }

        /* Get resolved path for logging */
        char linkbuf[PATH_MAX];
        char resolved[PATH_MAX];
        snprintf(linkbuf, sizeof(linkbuf), "/proc/self/fd/%d", dir_fd);
        ssize_t len = readlink(linkbuf, resolved, sizeof(resolved) - 1);
        if (len > 0) {
            /* Ensure null-termination - readlink doesn't guarantee it if buffer is too small */
            if (len < (ssize_t)sizeof(resolved)) {
                resolved[len] = '\0';
            } else {
                /* Truncated - cap at buffer size minus 1 and null-terminate */
                resolved[sizeof(resolved) - 1] = '\0';
            }
        } else {
            strncpy(resolved, path_info[i].path, sizeof(resolved) - 1);
            resolved[sizeof(resolved) - 1] = '\0';
        }
        path_info[i].resolved_path = strdup(resolved);
        path_info[i].dir_fd = dir_fd;

        /* Add rule with path-specific access */
        struct landlock_path_beneath_attr path_attr = {
            .allowed_access = path_info[i].access,
            .parent_fd = dir_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                    &path_attr, 0) != 0) {
            fprintf(stderr, "readonlybox-ptrace: Landlock: failed to add rule for '%s' (access 0x%llx): %s\n",
                    resolved, (unsigned long long)path_info[i].access, strerror(errno));
        } else {
            DEBUG_PRINT("SANDBOX: Landlock added rule for '%s' (access 0x%llx)\n",
                        resolved, (unsigned long long)path_info[i].access);
        }
    }

    /* Enforce the ruleset */
    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        fprintf(stderr, "readonlybox-ptrace: Failed to enforce Landlock ruleset: %s\n", strerror(errno));
    } else {
        DEBUG_PRINT("SANDBOX: Landlock enforced, allowed paths: %s\n", paths);
    }
    close(ruleset_fd);

    /* Cleanup */
    for (int i = 0; i < path_count; i++) {
        free(path_info[i].path);
        free(path_info[i].resolved_path);
    }
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
