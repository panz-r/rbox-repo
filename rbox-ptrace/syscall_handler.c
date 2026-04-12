/*
 * syscall_handler.c - Execve syscall interception and handling
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <limits.h>

#include "syscall_handler.h"
#include "memory.h"
#include "validation.h"
#include "protocol.h"
#include "debug.h"
#include "judge.h"
#include "soft_policy.h"
#include <shell_tokenizer.h>
#include "trampoline_allowance.h"

/* Forward declarations */

/* Forward declarations */
static int filter_env_decisions(ProcessState *state, pid_t pid, USER_REGS *regs);

/* Check if a process has a valid allowance for a specific subcommand.
 * Uses the hierarchical allowance chain. */
static int consume_allowance_argv(ProcessState *state, char *const argv[]) {
    if (!state) return 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    allowset_expire(&state->chains, &now);
    return allowset_consume_argv(&state->chains, (const char *const *)argv);
}

/* Grant allowances to a process based on the full command.
 * Uses the hierarchical allowance chain. */
static void grant_allowance(ProcessState *state, const char *full_command) {
    if (!state) return;
    allowset_grant(&state->chains, full_command);
}

/* Process state table (simple hash map.
 *
 * IMPORTANT: This is for CONCURRENT processes, not total spawns over time.
 * When a process exits, its entry is removed and can be reused.
 * The limit (4096) is the maximum number of processes that can be
 * traced simultaneously. For long-running shells that spawn many
 * commands over time, this is sufficient because each command process
 * exits and frees its table entry.
 *
 * The table is dynamically resizing - it starts with INITIAL_CAPACITY
 * and grows when the load factor exceeds 0.75, to handle arbitrary
 * numbers of concurrent processes without hitting a fixed limit.
 */
#define INITIAL_PROCESS_TABLE_CAPACITY 64
#define PROCESS_TABLE_LOAD_FACTOR_THRESHOLD 0.75
#define TOMBSTONE_THRESHOLD 0.5

#define TOMBSTONE ((ProcessState *)-1)

typedef struct {
    ProcessState **entries;
    size_t capacity;
    size_t count;
    size_t tombstone_count;
} ProcessTable;

static ProcessTable g_process_table = {NULL, 0, 0, 0};
static pid_t g_main_process_pid = 0;

/* Get hash index for pid */
static size_t pid_hash(pid_t pid, size_t capacity) {
    return ((size_t)pid * 2654435761U) % capacity;  /* Knuth's multiplicative hash */
}

/* Resize the process table - only rehashes live entries, skips tombstones */
static int resize_process_table(size_t new_capacity) {
    ProcessState **new_entries = calloc(new_capacity, sizeof(ProcessState *));
    if (!new_entries) {
        return -1;
    }

    /* Rehash existing live entries only (skip tombstones) */
    for (size_t i = 0; i < g_process_table.capacity; i++) {
        if (g_process_table.entries[i] && g_process_table.entries[i] != TOMBSTONE) {
            ProcessState *p = g_process_table.entries[i];
            size_t idx = pid_hash(p->pid, new_capacity);

            /* Linear probe for empty slot - keep probing until we find one */
            size_t probe = idx;
            bool placed = false;
            for (size_t j = 0; j < new_capacity; j++) {
                if (!new_entries[probe]) {
                    new_entries[probe] = p;
                    placed = true;
                    break;
                }
                probe = (probe + 1) % new_capacity;
            }
            /* With proper load factor management, we should ALWAYS find a slot.
             * If we don't, it's a critical error - entries would be lost. */
            if (!placed) {
                LOG_ERROR("CRITICAL: hash table resize failed to place entry - table corrupted");
                free(new_entries);
                return -1;
            }
        }
    }

    free(g_process_table.entries);
    g_process_table.entries = new_entries;
    g_process_table.capacity = new_capacity;
    g_process_table.tombstone_count = 0;

    return 0;
}

/* Free all resources in a process state (allowances, wrapper chain, execve data) */
static void free_process_state(ProcessState *p) {
    if (!p) return;

    /* Free allowance chains */
    allowset_deinit(&p->chains);

    /* Free execve data */
    free(p->execve_pathname);
    memory_free_string_array(p->execve_argv);
    memory_free_string_array(p->execve_envp);
    memory_free_ulong_array(p->execve_envp_addrs);
    free(p->last_validated_cmd);
}

/* Set the main process PID */
void syscall_set_main_process(pid_t pid) {
    g_main_process_pid = pid;
}

/* Initialize syscall handler */
int syscall_handler_init(void) {
    g_process_table.entries = calloc(INITIAL_PROCESS_TABLE_CAPACITY, sizeof(ProcessState *));
    if (!g_process_table.entries) {
        return -1;
    }
    g_process_table.capacity = INITIAL_PROCESS_TABLE_CAPACITY;
    g_process_table.count = 0;
    g_process_table.tombstone_count = 0;
    g_main_process_pid = 0;
    return 0;
}

/* Cleanup syscall handler */
void syscall_handler_cleanup(void) {
    if (g_process_table.entries) {
        for (size_t i = 0; i < g_process_table.capacity; i++) {
            ProcessState *entry = g_process_table.entries[i];
            if (entry && entry != TOMBSTONE) {
                free_process_state(entry);
                free(entry);
            }
        }
        free(g_process_table.entries);
        g_process_table.entries = NULL;
        g_process_table.capacity = 0;
        g_process_table.count = 0;
        g_process_table.tombstone_count = 0;
    }
}

/* Get process state (create if needed) */
ProcessState *syscall_get_process_state(pid_t pid) {
    if (!g_process_table.entries) {
        return NULL;
    }

    /* Check if tombstone cleanup needed */
    if (g_process_table.capacity > INITIAL_PROCESS_TABLE_CAPACITY &&
        (double)g_process_table.tombstone_count / g_process_table.capacity > TOMBSTONE_THRESHOLD) {
        if (resize_process_table(g_process_table.capacity) != 0) {
            return NULL;
        }
    }

    /* Check if resize needed */
    if (g_process_table.count > 0 &&
        (double)g_process_table.count / g_process_table.capacity > PROCESS_TABLE_LOAD_FACTOR_THRESHOLD) {
        size_t new_capacity = g_process_table.capacity * 2;
        if (resize_process_table(new_capacity) != 0) {
            return NULL;
        }
    }

    size_t idx = pid_hash(pid, g_process_table.capacity);
    size_t first_tombstone = SIZE_MAX;

    /* Search for existing entry */
    for (size_t i = 0; i < g_process_table.capacity; i++) {
        size_t probe = (idx + i) % g_process_table.capacity;
        ProcessState *entry = g_process_table.entries[probe];

        if (entry == TOMBSTONE) {
            if (first_tombstone == SIZE_MAX) {
                first_tombstone = probe;
            }
            continue;
        }
        if (!entry) {
            /* Found empty slot - use first tombstone if found, otherwise this slot */
            size_t insert_at = (first_tombstone != SIZE_MAX) ? first_tombstone : probe;

            /* Create new entry at insert_at */
            g_process_table.entries[insert_at] = calloc(1, sizeof(ProcessState));
            if (g_process_table.entries[insert_at]) {
                g_process_table.entries[insert_at]->pid = pid;
                allowset_init(&g_process_table.entries[insert_at]->chains);
                g_process_table.count++;
                if (first_tombstone != SIZE_MAX) {
                    g_process_table.tombstone_count--;
                }
            }
            return g_process_table.entries[insert_at];
        }
        if (entry->pid == pid) {
            return entry;
        }
    }

    /* No NULL slot found - reuse first tombstone if available */
    if (first_tombstone != SIZE_MAX) {
        g_process_table.entries[first_tombstone] = calloc(1, sizeof(ProcessState));
        if (g_process_table.entries[first_tombstone]) {
            g_process_table.entries[first_tombstone]->pid = pid;
            allowset_init(&g_process_table.entries[first_tombstone]->chains);
            g_process_table.count++;
            g_process_table.tombstone_count--;
        }
        return g_process_table.entries[first_tombstone];
    }

    return NULL;  /* Should not reach here with dynamic resizing */
}

/* Find process state without creating - returns NULL if not found */
ProcessState *syscall_find_process_state(pid_t pid) {
    if (!g_process_table.entries) {
        return NULL;
    }

    size_t idx = pid_hash(pid, g_process_table.capacity);

    /* Search for existing entry */
    for (size_t i = 0; i < g_process_table.capacity; i++) {
        size_t probe = (idx + i) % g_process_table.capacity;
        ProcessState *entry = g_process_table.entries[probe];
        if (entry == TOMBSTONE) {
            continue;
        }
        if (!entry) {
            return NULL;
        }
        if (entry->pid == pid) {
            return entry;
        }
    }

    return NULL;  /* Not found */
}

/* Remove process state */
void syscall_remove_process_state(pid_t pid) {
    if (!g_process_table.entries) {
        return;
    }

    size_t idx = pid_hash(pid, g_process_table.capacity);

    for (size_t i = 0; i < g_process_table.capacity; i++) {
        size_t probe = (idx + i) % g_process_table.capacity;
        ProcessState *entry = g_process_table.entries[probe];
        if (entry == TOMBSTONE) {
            continue;
        }
        if (!entry) {
            return;
        }
        if (entry->pid == pid) {
            free_process_state(entry);
            free(entry);
            g_process_table.entries[probe] = TOMBSTONE;
            g_process_table.count--;
            g_process_table.tombstone_count++;
            return;
        }
    }
}

/* Check if syscall is execve or execveat */
int syscall_is_execve(USER_REGS *regs) {
    long sysnum = REG_SYSCALL(regs);
    return (sysnum == SYSCALL_EXECVE || sysnum == SYSCALL_EXECVEAT);
}

/* Check if syscall is fork/clone/vfork */
int syscall_is_fork(USER_REGS *regs) {
    long sysnum = REG_SYSCALL(regs);
    return (sysnum == SYSCALL_CLONE ||
            sysnum == SYSCALL_FORK ||
            sysnum == SYSCALL_VFORK);
}

/* Check if syscall is a filesystem syscall subject to soft policy */
static int syscall_is_filesystem(USER_REGS *regs) {
    long sysnum = REG_SYSCALL(regs);
    switch (sysnum) {
        case SYSCALL_OPEN:
        case SYSCALL_OPENAT:
        case SYSCALL_CREAT:
        case SYSCALL_MKDIR:
        case SYSCALL_MKDIRAT:
        case SYSCALL_RMDIR:
        case SYSCALL_UNLINK:
        case SYSCALL_UNLINKAT:
        case SYSCALL_RENAME:
        case SYSCALL_RENAMEAT:
        case SYSCALL_SYMLINK:
        case SYSCALL_SYMLINKAT:
        case SYSCALL_LINK:
        case SYSCALL_LINKAT:
        case SYSCALL_CHMOD:
        case SYSCALL_CHOWN:
        case SYSCALL_TRUNCATE:
        case SYSCALL_FTRUNCATE:
        case SYSCALL_UTIME:
        case SYSCALL_STAT:
        case SYSCALL_LSTAT:
        case SYSCALL_NEWFSTATAT:
        case SYSCALL_FSTAT:
        case SYSCALL_ACCESS:
        case SYSCALL_FACCESSAT:
        case SYSCALL_FACCESSAT2:
            return 1;
        default:
            return 0;
    }
}

/*
 * Resolve a path for a *_at syscall or any syscall with a relative path.
 *
 * For absolute paths, this returns a realpath-resolved canonical path.
 * For relative paths:
 *   - If dirfd == AT_FDCWD, resolves against the child process's cwd.
 *   - Otherwise, resolves against the directory referred to by dirfd.
 *
 * If the path does not exist (e.g., for file creation), this function
 * resolves the parent directory and appends the basename. This allows
 * policy checking on creation operations.
 *
 * chdir() handling: We read /proc/pid/cwd fresh on every call, so chdir()
 * is handled automatically without needing to intercept that syscall.
 *
 * TOCTOU note: There is an inherent race between reading /proc/PID/cwd or
 * /proc/PID/fd/N and the actual syscall execution. A process could change
 * its cwd or close/reopen a directory fd between our readlink() and the
 * kernel's actual path resolution. This is a fundamental limitation of
 * ptrace-based interception and cannot be fixed without kernel support.
 * The policy is best-effort, not a hard security boundary.
 *
 * Returns NULL on error (path cannot be resolved).
 */
static void strip_trailing_slashes(char *p) {
    size_t len = strlen(p);
    while (len > 1 && p[len-1] == '/') p[--len] = '\0';
}

static void get_parent_path(const char *path, char *parent, size_t parent_size) {
    const char *last_slash = strrchr(path, '/');
    if (last_slash && last_slash != path) {
        size_t parent_len = last_slash - path;
        if (parent_len >= parent_size) parent_len = parent_size - 1;
        memcpy(parent, path, parent_len);
        parent[parent_len] = '\0';
    } else if (last_slash == path) {
        strcpy(parent, "/");
    } else {
        strcpy(parent, ".");
    }
}

static char *resolve_path_at(pid_t pid, int dirfd, const char *path, char *buf, size_t buf_size, int *file_exists) {
    char dir_buf[PATH_MAX];
    char *result;
    int exists = -1;

    if (!path || !buf || buf_size < PATH_MAX) return NULL;
    if (file_exists) *file_exists = -1;

    if (path[0] == '/') {
        result = realpath(path, buf);
        if (result) {
            exists = 1;
        } else if (errno == ENOENT) {
            exists = 0;
            strlcpy(buf, path, buf_size);
            strip_trailing_slashes(buf);
            if (buf[0] == '\0') {
                strcpy(buf, "/");
            }
        } else {
            return NULL;
        }
        if (file_exists) *file_exists = exists;
        return exists >= 0 ? buf : NULL;
    }

    if (dirfd == AT_FDCWD) {
        snprintf(dir_buf, sizeof(dir_buf), "/proc/%d/cwd", pid);
    } else {
        snprintf(dir_buf, sizeof(dir_buf), "/proc/%d/fd/%d", pid, dirfd);
    }

    char link_buf[PATH_MAX];
    ssize_t len = readlink(dir_buf, link_buf, sizeof(link_buf)-1);
    if (len <= 0) {
        DEBUG_PRINT("HANDLER: failed to read link %s: %s\n", dir_buf, strerror(errno));
        return NULL;
    }
    link_buf[len] = '\0';

    size_t link_len = strlen(link_buf);
    size_t path_len = strlen(path);
    if (link_len + 1 + path_len >= buf_size) {
        DEBUG_PRINT("HANDLER: path too long: %s/%s\n", link_buf, path);
        return NULL;
    }

    int written = snprintf(buf, buf_size, "%s/%s", link_buf, path);
    if (written < 0 || (size_t)written >= buf_size) {
        DEBUG_PRINT("HANDLER: snprintf failed or truncated: %s/%s\n", link_buf, path);
        return NULL;
    }

    char tmp_buf[PATH_MAX];
    result = realpath(buf, tmp_buf);
    if (result) {
        exists = 1;
        size_t copy_len = strlen(tmp_buf);
        if (copy_len >= buf_size) copy_len = buf_size - 1;
        memcpy(buf, tmp_buf, copy_len);
        buf[copy_len] = '\0';
    } else if (errno == ENOENT) {
        exists = 0;
        strip_trailing_slashes(buf);
    } else {
        return NULL;
    }
    if (file_exists) *file_exists = exists;
    return buf;
}

/* Build command string from argv - dynamic allocation */
#define MAX_COMMAND_STRING_LEN 65536  /* 64KB sanity limit */

/* Check if an argument needs quoting to preserve shell syntax */
static int needs_quoting(const char *str) {
    if (!str || !*str) return 1;
    for (int i = 0; str[i]; i++) {
        char c = str[i];
        if (isspace((unsigned char)c)) return 1;
        if (strchr(";&|()<>[]{}$`\"'#*?!~\\", c)) return 1;
    }
    return 0;
}

/* Quote an argument using single quotes, escaping embedded single quotes as '\'' */
static char *quote_arg_single(const char *arg) {
    if (!arg) return strdup("''");
    if (!needs_quoting(arg)) return strdup(arg);

    size_t len = strlen(arg);
    char *result = malloc(len * 4 + 3);
    char *out = result;
    *out++ = '\'';

    for (size_t i = 0; i < len; i++) {
        if (arg[i] == '\'') {
            *out++ = '\'';
            *out++ = '\\';
            *out++ = '\'';
            *out++ = '\'';
        } else {
            *out++ = arg[i];
        }
    }
    *out++ = '\'';
    *out = '\0';
    return result;
}

static char *build_command_string_alloc(char *const argv[]) {
    if (!argv || !argv[0]) return NULL;

    /* First pass: quote each arg and calculate total length */
    char **quoted = NULL;
    size_t total_len = 0;
    int argc = 0;

    for (int i = 0; argv[i]; i++) {
        char *q = quote_arg_single(argv[i]);
        if (!q) {
            for (int j = 0; j < argc; j++) free(quoted[j]);
            free(quoted);
            return NULL;
        }
        quoted = realloc(quoted, (argc + 1) * sizeof(char *));
        quoted[argc++] = q;
        total_len += strlen(q) + 1;
    }

    if (argc == 0) {
        free(quoted);
        return NULL;
    }
    total_len--;

    char *buf = malloc(total_len + 1);
    if (!buf) {
        for (int i = 0; i < argc; i++) free(quoted[i]);
        free(quoted);
        return NULL;
    }

    char *p = buf;
    for (int i = 0; i < argc; i++) {
        if (i > 0) *p++ = ' ';
        size_t len = strlen(quoted[i]);
        memcpy(p, quoted[i], len);
        p += len;
    }
    *p = '\0';

    for (int i = 0; i < argc; i++) free(quoted[i]);
    free(quoted);
    return buf;
}

/* Get basename from path */
static const char *get_basename(const char *path) {
    if (!path) return "unknown";
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

/* Block a filesystem syscall by returning an error and skipping the syscall instruction.
 * Returns 1 if blocked, -1 on error. */
static int block_syscall(pid_t pid, USER_REGS *regs) {
#ifdef __x86_64__
    regs->rax = -EACCES;
    regs->rip += 2;
#elif defined(__aarch64__)
    regs->regs[0] = -EACCES;
    regs->pc += 4;
#elif defined(__riscv)
    regs->regs[0] = -EACCES;
    regs->epc += 4;
#else
    return -1;
#endif

    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        if (errno == ESRCH) {
            DEBUG_PRINT("HANDLER: pid %d already exited (race), skipping block_syscall\n", pid);
            return 0;
        }
        perror("ptrace(SETREGS) for block_syscall");
        if (kill(pid, 0) == 0) {
            kill(pid, SIGKILL);
        }
        return -1;
    }

    DEBUG_PRINT("HANDLER: blocked filesystem syscall\n");
    return 1;
}

/* Block execve by replacing it with a shell command that prints permission denied */
static int block_execve(pid_t pid, USER_REGS *regs) {
    MemoryContext mem_ctx;

    /* Initialize memory context */
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        LOG_ERROR("Failed to init memory context for block");
        return -1;
    }

    /* Try multiple shell paths - some minimal systems may not have /bin/sh */
    const char *shell_paths[] = { "/bin/sh", "/bin/bash", "/bin/dash", NULL };
    const char *sh_path = NULL;
    for (int i = 0; shell_paths[i]; i++) {
        if (access(shell_paths[i], X_OK) == 0) {
            sh_path = shell_paths[i];
            break;
        }
    }
    if (!sh_path) {
        DEBUG_PRINT("HANDLER: no shell found for block_execve, using kill\n");
        return -1;
    }

    const char *dash_c = "-c";
    const char *message_cmd = "echo 'Permission denied, this command was not executed and had no effects on the system.' >&2; exit 1";

    /* Write strings to process memory */
    unsigned long sh_addr, dash_c_addr, cmd_addr, new_argv;
    if (memory_write_string(&mem_ctx, sh_path, &sh_addr) != 0) {
        LOG_ERROR("Failed to write shell path");
        return -1;
    }
    if (memory_write_string(&mem_ctx, dash_c, &dash_c_addr) != 0) {
        LOG_ERROR("Failed to write dash_c");
        return -1;
    }
    if (memory_write_string(&mem_ctx, message_cmd, &cmd_addr) != 0) {
        LOG_ERROR("Failed to write message command");
        return -1;
    }

    /* Create argv = {"/bin/sh", "-c", "echo ...", NULL} */
    unsigned long argv_ptrs[4];
    argv_ptrs[0] = sh_addr;
    argv_ptrs[1] = dash_c_addr;
    argv_ptrs[2] = cmd_addr;
    argv_ptrs[3] = 0;

    if (memory_write_pointer_array(&mem_ctx, argv_ptrs, 3, &new_argv) != 0) {
        LOG_ERROR("Failed to write argv for shell");
        return -1;
    }

    /* Update registers to exec /bin/sh
     * Note: execveat has different argument order:
     *   execve(path, argv, envp) -> rdi, rsi, rdx
     *   execveat(dirfd, path, argv, envp, flags) -> rdi, rsi, rdx, r10
     */
    if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
        /* For execveat: set dirfd = AT_FDCWD */
        REG_ARG1(regs) = -100;  /* AT_FDCWD */
        REG_ARG2(regs) = sh_addr;
        REG_ARG3(regs) = new_argv;
        REG_ARG4(regs) = 0;  /* envp = NULL */
    } else {
        /* For execve: standard arguments */
        REG_ARG1(regs) = sh_addr;
        REG_ARG2(regs) = new_argv;
        REG_ARG3(regs) = 0;  /* envp = NULL */
    }

    /* Apply changes */
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        if (errno == ESRCH) {
            DEBUG_PRINT("HANDLER: pid %d already exited (race), skipping block_execve\n", pid);
            return 0;
        }
        perror("ptrace(SETREGS)");
        return -1;
    }

    return 0;
}

/* Handle syscall entry (before execution) */
int syscall_handle_entry(pid_t pid, USER_REGS *regs, ProcessState *state) {
    if (!state) {
        LOG_ERROR("Cannot track process %d - blocking execve", pid);
        block_execve(pid, regs);
        return -1;
    }

    /* Skip detached processes */
    if (state->detached) {
        return 0;
    }

    /* Clear stale environment decisions before any DFA or filtering checks.
     * These variables may be set from a previous command and should not affect
     * subsequent commands (especially DFA-fast-path commands that don't query the server). */
    unsetenv("READONLYBOX_ENV_DECISIONS");
    unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

    /* Only check execve syscalls */
    if (syscall_is_execve(regs)) {
        DEBUG_PRINT("HANDLER: pid=%d execve detected, initial=%d, detached=%d\n",
                    pid, state->initial_execve, state->detached);

        /* New execve that needs validation - reset validated flag */
        state->validated = 0;
        state->in_execve = 1;

        /* Read execve/execveat arguments */
        /* Note: execveat has different argument order than execve:
         *   execve(pathname, argv, envp)
         *   execveat(dirfd, pathname, argv, envp, flags)
         */
        unsigned long pathname_addr;
        unsigned long argv_addr;
        unsigned long envp_addr;
        int dirfd = AT_FDCWD;

        if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
            /* execveat: dirfd is in arg1, pathname in arg2 */
            dirfd = (int)REG_ARG1(regs);
            pathname_addr = REG_ARG2(regs);
            argv_addr = REG_ARG3(regs);
            envp_addr = REG_ARG4(regs);
        } else {
            /* execve: all arguments in standard positions */
            pathname_addr = REG_ARG1(regs);
            argv_addr = REG_ARG2(regs);
            envp_addr = REG_ARG3(regs);
        }

        /* Save original arguments */
        free(state->execve_pathname);
        memory_free_string_array(state->execve_argv);
        memory_free_string_array(state->execve_envp);
        memory_free_ulong_array(state->execve_envp_addrs);

        state->execve_pathname = memory_read_string(pid, pathname_addr);

        /* Handle empty pathname with AT_EMPTY_PATH semantics:
         * If pathname is empty, resolve from dirfd using /proc/<pid>/fd/<dirfd>.
         * This handles execveat(dirfd, "", argv, envp, AT_EMPTY_PATH) correctly. */
        if (state->execve_pathname && state->execve_pathname[0] == '\0' && dirfd != AT_FDCWD) {
            char fd_path[64];
            char resolved[PATH_MAX];
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, dirfd);
            ssize_t len = readlink(fd_path, resolved, sizeof(resolved) - 1);
            if (len > 0) {
                resolved[len] = '\0';
                free(state->execve_pathname);
                state->execve_pathname = strdup(resolved);
            }
        }

        state->execve_argv = memory_read_string_array(pid, argv_addr);
        /* Also capture the addresses of environment variables in child memory */
        state->execve_envp = memory_read_string_array_with_addrs(pid, envp_addr, &state->execve_envp_addrs);

        if (!state->execve_pathname || !state->execve_argv) {
            /* Block the command by replacing it with a permission denied message */
            if (block_execve(pid, regs) < 0) {
                /* If we can't block it, kill the process */
                kill(pid, SIGKILL);
            }
            return 0;
        }

        /* Build command string for validation - use dynamic allocation to avoid truncation */
        char *command = build_command_string_alloc(state->execve_argv);
        if (!command) {
            /* Allocation failed - block the command to be safe */
            DEBUG_PRINT("HANDLER: pid=%d failed to build command string, blocking\n", pid);
            if (block_execve(pid, regs) < 0) {
                kill(pid, SIGKILL);
            }
            return 0;
        }

        /* Check if this is the main process's initial execve - allow without validation */
        if (!state->initial_execve && pid == g_main_process_pid) {
            /* This is the main process's first execve, allow without validation */
            DEBUG_PRINT("HANDLER: Allowing main process %d initial execve without validation\n", pid);
            state->initial_execve = 1;
            free(command);
            /* Don't detach - continue tracing this process for future execves */
            return 0;
        }

        /* Mark that we've seen an execve for this process */
        if (!state->initial_execve) {
            state->initial_execve = 1;
        }

        /* Get parent PID to check for allowances */
        char proc_status[64];
        snprintf(proc_status, sizeof(proc_status), "/proc/%d/status", pid);
        FILE *status_file = fopen(proc_status, "r");
        pid_t parent_pid = 0;
        if (status_file) {
            char line[256];
            while (fgets(line, sizeof(line), status_file)) {
                if (strncmp(line, "PPid:", 5) == 0) {
                    sscanf(line + 5, "%d", &parent_pid);
                    break;
                }
            }
            fclose(status_file);
        } else {
            /* /proc may not be mounted (e.g., containers with limited procfs).
             * In this case, we skip the allowance check - commands will be
             * validated normally via DFA/server. This is a safe degradation. */
            DEBUG_PRINT("HANDLER: pid=%d could not open %s, skipping allowance check\n",
                       pid, proc_status);
        }

        /* NEW: Check own process's allowances first */
        if (consume_allowance_argv(state, state->execve_argv)) {
            DEBUG_PRINT("HANDLER: pid=%d has own allowance for '%s', allowing\n", pid, command);
            state->validated = 1;
            free(state->last_validated_cmd);
            state->last_validated_cmd = strdup(command);
            free(command);
            return 0;
        }

        /* Walk up the process tree to find an ancestor with allowances. */
        pid_t ancestor_pid = parent_pid;
        while (ancestor_pid > 0 && ancestor_pid != g_main_process_pid) {
            ProcessState *ancestor_state = syscall_find_process_state(ancestor_pid);
            if (ancestor_state) {
                if (consume_allowance_argv(ancestor_state, state->execve_argv)) {
                    DEBUG_PRINT("HANDLER: pid=%d has allowance from ancestor %d for '%s', allowing\n",
                               pid, ancestor_pid, command);
                    state->validated = 1;
                    free(state->last_validated_cmd);
                    state->last_validated_cmd = strdup(command);
                    free(command);
                    return 0;
                }
            }

            /* Get parent's parent to continue walking up the tree */
            char ancestor_status_path[64];
            snprintf(ancestor_status_path, sizeof(ancestor_status_path), "/proc/%d/status", ancestor_pid);
            FILE *ancestor_status = fopen(ancestor_status_path, "r");
            pid_t next_ancestor = 0;
            if (ancestor_status) {
                char line[256];
                while (fgets(line, sizeof(line), ancestor_status)) {
                    if (strncmp(line, "PPid:", 5) == 0) {
                        sscanf(line + 5, "%d", &next_ancestor);
                        break;
                    }
                }
                fclose(ancestor_status);
            }
            if (next_ancestor == 0 || next_ancestor == ancestor_pid) {
                break;
            }
            ancestor_pid = next_ancestor;
        }

        /* Check if this is the same command we just validated for this process.
         * This prevents duplicate requests when a process retries exec while we're waiting.
         * Must come after wrapper chain to allow chain propagation first. */
        if (state->last_validated_cmd && strcmp(state->last_validated_cmd, command) == 0) {
            DEBUG_PRINT("HANDLER: pid=%d command '%s' already validated, allowing\n", pid, command);
            free(command);
            state->validated = 1;
            return 0;
        }

        /* For subsequent execves (commands run by bash), validate with server */
        /* Check DFA fast-path */
        int dfa_result = validation_check_dfa(command);

        /* Debug: print DFA result for every command */
        DEBUG_PRINT("DFA: command='%s' result=%s\n", command,
                dfa_result == VALIDATION_ALLOW ? "ALLOW" :
                (dfa_result == VALIDATION_DENY ? "DENY" : "ASK"));

        if (dfa_result == VALIDATION_ALLOW) {
            /* Fast allow - mark as validated but continue tracing for future execves */
            DEBUG_PRINT("DFA: Fast-allowing command '%s', continuing to trace\n", command);
            state->validated = 1;

            /* Filter environment variables even for DFA-allowed commands */
            if (filter_env_decisions(state, pid, regs) < 0) {
                /* Filter failed - block the command to be safe */
                DEBUG_PRINT("HANDLER: pid=%d env filter failed for '%s', blocking\n", pid, command);
                if (block_execve(pid, regs) < 0) {
                    kill(pid, SIGKILL);
                }
                unsetenv("READONLYBOX_ENV_DECISIONS");
                unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");
                free(command);
                return 0;
            }

            /* Clear environment decision variables to prevent leakage to subsequent commands */
            unsetenv("READONLYBOX_ENV_DECISIONS");
            unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

            /* Continue tracing - don't detach */
            free(command);
            return 0;
        }

        /* DFA didn't allow - need to ask server for decision */
        DEBUG_PRINT("HANDLER: pid=%d DFA result=%d, asking server for decision on '%s'\n",
                    pid, dfa_result, command);

        /* Build caller info for the request */
        char caller_info[256 + 8] = {0};  /* basename + ":execve" - safe */
        char exe_link[64];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
        char exe_path[PATH_MAX];
        ssize_t exe_len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (exe_len > 0) {
            exe_path[exe_len] = '\0';
            const char *base = get_basename(exe_path);
            /* Safely copy basename, truncating if needed but preserving null terminator */
            size_t base_len = strlen(base);
            if (base_len > 255) base_len = 255;
            memcpy(caller_info, base, base_len);
            memcpy(caller_info + base_len, ":execve", 8);
        } else {
            strcpy(caller_info, "unknown:execve");
        }

        /* Ask server for decision via readonlybox --judge
         * judge_run now waits indefinitely for server availability */
        int decision = judge_run(command, caller_info);

        DEBUG_PRINT("JUDGE: pid=%d command='%s' decision=%d\n", pid, command, decision);

        if (decision != 0) {
            /* Server denied (exit 9) or timeout after retries - block the command */
            DEBUG_PRINT("HANDLER: pid=%d server denied command '%s', blocking\n", pid, command);
            if (block_execve(pid, regs) < 0) {
                kill(pid, SIGKILL);
            }
            free(command);
            return 0;
        }

        /* Server allowed - let the execve proceed */
        DEBUG_PRINT("HANDLER: pid=%d server allowed command '%s', continuing to trace\n", pid, command);
        state->validated = 1;

        /* Grant allowances to this process for subcommands of the allowed command.
         * Child processes will be able to exec subcommands without new server requests. */
        grant_allowance(state, command);

        /* Track this validated command to prevent duplicates on retry */
        free(state->last_validated_cmd);
        state->last_validated_cmd = strdup(command);

        /* Filter environment variables based on server decisions and apply to child */
        if (filter_env_decisions(state, pid, regs) < 0) {
            /* Filter failed - block the command to be safe */
            DEBUG_PRINT("HANDLER: pid=%d env filter failed for '%s', blocking\n", pid, command);
            if (block_execve(pid, regs) < 0) {
                kill(pid, SIGKILL);
            }
            /* Clear environment decision variables before returning */
            unsetenv("READONLYBOX_ENV_DECISIONS");
            unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");
            free(command);
            return 0;
        }

        free(command);
        return 0;
    }

    /* Check for filesystem syscalls (soft policy) */
    if (syscall_is_filesystem(regs)) {
        soft_policy_t *policy = soft_policy_get_global();
        if (soft_policy_is_active(policy)) {
            soft_path_mode_t inputs[16];
            int results[16];
            int count = 0;
            long sysnum = REG_SYSCALL(regs);
            uint32_t access_mask = 0;
            char *path1 = NULL;
            char *path2 = NULL;
            char path_buf1[PATH_MAX];
            char path_buf2[PATH_MAX];
            int dirfd1 = AT_FDCWD;
            int dirfd2 = AT_FDCWD;
            int ret = 0;
            int is_creat = 0;
            int modifies_dir_entry = 0;

            switch (sysnum) {
                case SYSCALL_OPEN: {
                    access_mask = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    if (path1) {
                        int flags = (int)REG_ARG2(regs);
                        if ((flags & O_ACCMODE) == O_RDONLY) {
                            access_mask = SOFT_ACCESS_READ;
                        } else if ((flags & O_ACCMODE) == O_WRONLY) {
                            access_mask = SOFT_ACCESS_WRITE;
                        } else if ((flags & O_ACCMODE) == O_RDWR) {
                            access_mask = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
                        }
                        if (flags & O_TRUNC) {
                            access_mask |= SOFT_ACCESS_TRUNCATE;
                        }
                        if (flags & O_CREAT) {
                            access_mask |= SOFT_ACCESS_WRITE;
                            is_creat = 1;
                        }
                    }
                    dirfd1 = AT_FDCWD;
                    break;
                }
                case SYSCALL_OPENAT: {
                    access_mask = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    if (path1) {
                        int flags = (int)REG_ARG3(regs);
                        if ((flags & O_ACCMODE) == O_RDONLY) {
                            access_mask = SOFT_ACCESS_READ;
                        } else if ((flags & O_ACCMODE) == O_WRONLY) {
                            access_mask = SOFT_ACCESS_WRITE;
                        } else if ((flags & O_ACCMODE) == O_RDWR) {
                            access_mask = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
                        }
                        if (flags & O_TRUNC) {
                            access_mask |= SOFT_ACCESS_TRUNCATE;
                        }
                        if (flags & O_CREAT) {
                            access_mask |= SOFT_ACCESS_WRITE;
                            is_creat = 1;
                        }
                    }
                    break;
                }
                case SYSCALL_CREAT:
                    access_mask = SOFT_ACCESS_WRITE | SOFT_ACCESS_TRUNCATE;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    is_creat = 1;
                    break;
                case SYSCALL_MKDIR:
                    access_mask = SOFT_ACCESS_MKDIR;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_MKDIRAT:
                    access_mask = SOFT_ACCESS_MKDIR;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                case SYSCALL_RMDIR:
                    access_mask = SOFT_ACCESS_RMDIR;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_UNLINK:
                    access_mask = SOFT_ACCESS_UNLINK;
                    modifies_dir_entry = 1;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_UNLINKAT:
                    access_mask = SOFT_ACCESS_UNLINK;
                    modifies_dir_entry = 1;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                case SYSCALL_RENAME:
                    access_mask = SOFT_ACCESS_RENAME;
                    modifies_dir_entry = 1;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    path2 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd1 = AT_FDCWD;
                    dirfd2 = AT_FDCWD;
                    break;
                case SYSCALL_RENAMEAT:
                    access_mask = SOFT_ACCESS_RENAME;
                    modifies_dir_entry = 1;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd2 = (int)REG_ARG3(regs);
                    path2 = memory_read_string(pid, REG_ARG4(regs));
                    break;
                case SYSCALL_SYMLINK:
                    access_mask = SOFT_ACCESS_SYMLINK;
                    modifies_dir_entry = 1;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    path2 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd1 = AT_FDCWD;
                    dirfd2 = AT_FDCWD;
                    break;
                case SYSCALL_SYMLINKAT:
                    access_mask = SOFT_ACCESS_SYMLINK;
                    modifies_dir_entry = 1;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd2 = AT_FDCWD;
                    path2 = memory_read_string(pid, REG_ARG3(regs));
                    break;
                case SYSCALL_LINK:
                    access_mask = SOFT_ACCESS_LINK;
                    modifies_dir_entry = 1;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    path2 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd1 = AT_FDCWD;
                    dirfd2 = AT_FDCWD;
                    break;
                case SYSCALL_LINKAT:
                    access_mask = SOFT_ACCESS_LINK;
                    modifies_dir_entry = 1;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd2 = (int)REG_ARG3(regs);
                    path2 = memory_read_string(pid, REG_ARG4(regs));
                    break;
                case SYSCALL_CHMOD:
                    access_mask = SOFT_ACCESS_CHMOD;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_CHOWN:
                    access_mask = SOFT_ACCESS_CHOWN;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_TRUNCATE:
                    access_mask = SOFT_ACCESS_WRITE | SOFT_ACCESS_TRUNCATE;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_FTRUNCATE:
                    /* ftruncate operates on a file descriptor, not a path.
                     * We cannot apply soft policy without tracking open file descriptors.
                     * The file descriptor was already checked at open() time. */
                    DEBUG_PRINT("HANDLER: pid=%d ftruncate (fd-based), allowing\n", pid);
                    return 0;
                case SYSCALL_UTIME:
                    access_mask = SOFT_ACCESS_WRITE;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_STAT:
                    access_mask = SOFT_ACCESS_READ;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_LSTAT:
                    access_mask = SOFT_ACCESS_READ;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_NEWFSTATAT:
                    access_mask = SOFT_ACCESS_READ;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                case SYSCALL_FSTAT:
                    /* fstat operates on a file descriptor, not a path.
                     * We cannot apply soft policy without tracking open file descriptors.
                     * The file descriptor was already checked at open() time. */
                    DEBUG_PRINT("HANDLER: pid=%d fstat (fd-based), allowing\n", pid);
                    return 0;
                case SYSCALL_ACCESS:
                    access_mask = SOFT_ACCESS_READ;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_FACCESSAT:
                    access_mask = SOFT_ACCESS_READ;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                case SYSCALL_FACCESSAT2:
                    access_mask = SOFT_ACCESS_READ;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                default:
                    DEBUG_PRINT("HANDLER: pid=%d unknown filesystem syscall %ld\n", pid, sysnum);
                    return 0;
            }

            if (path1) {
                int file_exists = -1;
                char *resolved = resolve_path_at(pid, dirfd1, path1, path_buf1, sizeof(path_buf1), &file_exists);
                if (!resolved) {
                    DEBUG_PRINT("HANDLER: pid=%d path resolution failed for '%s', allowing kernel to handle\n", pid, path1);
                    free(path1);
                    path1 = NULL;
                } else if (is_creat && !file_exists) {
                    char parent_buf[PATH_MAX];
                    get_parent_path(path_buf1, parent_buf, sizeof(parent_buf));
                    char *parent_resolved = resolve_path_at(pid, dirfd1, parent_buf, parent_buf, sizeof(parent_buf), &file_exists);
                    (void)file_exists;
                    DEBUG_PRINT("HANDLER: pid=%d O_CREAT on non-existent '%s', checking parent '%s'\n", pid, path1, parent_buf);
                    free(path1);
                    path1 = NULL;
                    if (parent_resolved) {
                        inputs[count].path = strdup(parent_buf);
                        inputs[count].access_mask = SOFT_ACCESS_WRITE;
                        count++;
                    }
                } else {
                    /* For dir entry modifications (rename/symlink/link/unlink), check parent with WRITE.
                     * For symlink/link, also check target with READ if it exists. */
                    if (modifies_dir_entry) {
                        char parent_buf[PATH_MAX];
                        get_parent_path(path_buf1, parent_buf, sizeof(parent_buf));
                        inputs[count].path = strdup(parent_buf);
                        inputs[count].access_mask = SOFT_ACCESS_WRITE;
                        count++;
                        /* For symlink/link: check target (path1) with READ if it exists */
                        if ((sysnum == SYSCALL_SYMLINK || sysnum == SYSCALL_SYMLINKAT ||
                             sysnum == SYSCALL_LINK || sysnum == SYSCALL_LINKAT) && file_exists) {
                            inputs[count].path = strdup(path_buf1);
                            inputs[count].access_mask = SOFT_ACCESS_READ;
                            count++;
                        }
                    }
                    free(path1);
                    path1 = NULL;
                    inputs[count].path = strdup(path_buf1);
                    inputs[count].access_mask = access_mask;
                    count++;
                }
            }

            if (path2) {
                int file_exists = -1;
                char *resolved = resolve_path_at(pid, dirfd2, path2, path_buf2, sizeof(path_buf2), &file_exists);
                if (!resolved) {
                    DEBUG_PRINT("HANDLER: pid=%d path resolution failed for '%s', allowing kernel to handle\n", pid, path2);
                    free(path2);
                    path2 = NULL;
                } else if (is_creat && !file_exists) {
                    char parent_buf[PATH_MAX];
                    get_parent_path(path_buf2, parent_buf, sizeof(parent_buf));
                    char *parent_resolved = resolve_path_at(pid, dirfd2, parent_buf, parent_buf, sizeof(parent_buf), &file_exists);
                    (void)file_exists;
                    DEBUG_PRINT("HANDLER: pid=%d O_CREAT on non-existent '%s', checking parent '%s'\n", pid, path2, parent_buf);
                    free(path2);
                    path2 = NULL;
                    if (parent_resolved) {
                        inputs[count].path = strdup(parent_buf);
                        inputs[count].access_mask = SOFT_ACCESS_WRITE;
                        count++;
                    }
                } else {
                    /* For dir entry modifications, check parent with WRITE */
                    if (modifies_dir_entry) {
                        char parent_buf[PATH_MAX];
                        get_parent_path(path_buf2, parent_buf, sizeof(parent_buf));
                        inputs[count].path = strdup(parent_buf);
                        inputs[count].access_mask = SOFT_ACCESS_WRITE;
                        count++;
                    }
                    free(path2);
                    path2 = NULL;
                    inputs[count].path = strdup(path_buf2);
                    inputs[count].access_mask = access_mask;
                    count++;
                }
            }

            if (count > 0) {
                DEBUG_PRINT("HANDLER: pid=%d filesystem syscall %ld, checking %d paths\n",
                           pid, sysnum, count);
                int check_result = soft_policy_check(policy, inputs, results, count);
                if (check_result != 0) {
                    DEBUG_PRINT("HANDLER: soft_policy_check failed (error), blocking syscall\n");
                    if (block_syscall(pid, regs) < 0) {
                        kill(pid, SIGKILL);
                    }
                    ret = -1;
                    goto cleanup;
                } else {
                    for (int i = 0; i < count; i++) {
                        if (g_soft_debug) {
                            fprintf(stderr, "SOFT: syscall=%ld path=%s access=0x%x -> %s\n",
                                    sysnum, inputs[i].path, inputs[i].access_mask,
                                    results[i] ? "ALLOW" : "DENY");
                        }
                        if (!results[i]) {
                            DEBUG_PRINT("HANDLER: pid=%d SOFT POLICY DENY path '%s'\n", pid, inputs[i].path);
                            int block_result = block_syscall(pid, regs);
                            if (block_result < 0) {
                                DEBUG_PRINT("HANDLER: failed to block syscall, killing child\n");
                                kill(pid, SIGKILL);
                                ret = -1;
                                goto cleanup;
                            }
                            ret = block_result;
                            goto cleanup;
                        }
                    }
                }
            }

cleanup:
            for (int i = 0; i < count; i++) {
                free((void *)inputs[i].path);
            }
            free(path1);
            free(path2);
            return ret;
        }
    }

    return 0;
}

/* Filter environment variables based on server decisions
 * Reads READONLYBOX_ENV_DECISIONS and removes denied vars from state->execve_envp
 * Also writes the filtered envp to the child's memory and updates the register
 * Returns: 0 on success, -1 on error (parse error or allocation failure) */
static int filter_env_decisions(ProcessState *state, pid_t pid, USER_REGS *regs) {
    if (!state || !state->execve_envp || !state->execve_envp_addrs) return 0;

    const char *env_decisions_str = getenv("READONLYBOX_ENV_DECISIONS");
    if (!env_decisions_str || strlen(env_decisions_str) == 0) return 0;

    DEBUG_PRINT("FILTER: parsing env decisions: '%s'\n", env_decisions_str);

    /* Parse decisions: format is "index:decision,index:decision,..."
     * where decision is 0=allow, 1=deny
     * First pass: collect all entries to size our array */
    typedef struct { int idx; int decision; } DecisionEntry;
    DecisionEntry *entries = NULL;
    int entry_capacity = 16;
    int entry_count = 0;
    int max_index = -1;
    int parse_error = 0;

    entries = malloc(entry_capacity * sizeof(DecisionEntry));
    if (!entries) return -1;

    const char *p = env_decisions_str;
    while (*p) {
        if (entry_count >= entry_capacity) {
            entry_capacity *= 2;
            DecisionEntry *new_entries = realloc(entries, entry_capacity * sizeof(DecisionEntry));
            if (!new_entries) {
                free(entries);
                return -1;
            }
            entries = new_entries;
        }
        char *end;
        long idx = strtol(p, &end, 10);
        if (end == p || idx < 0) { parse_error = 1; break; }
        if (*end != ':') { parse_error = 1; break; }
        p = end + 1;

        int decision = *p - '0';
        if (decision != 0 && decision != 1) { parse_error = 1; break; }
        p++;

        if (*p == ',') {
            p++;
        } else if (*p != '\0') {
            parse_error = 1; break;
        }

        entries[entry_count].idx = (int)idx;
        entries[entry_count].decision = decision;
        entry_count++;
        if ((int)idx > max_index) max_index = (int)idx;
    }

    if (parse_error) {
        DEBUG_PRINT("FILTER: env decision parse error, rejecting\n");
        free(entries);
        return -1;
    }

    if (entry_count == 0 || max_index < 0) {
        free(entries);
        return 0;
    }

    /* Build sparse array indexed by idx for O(1) lookup */
    int *decisions = calloc(max_index + 1, sizeof(int));
    if (!decisions) {
        free(entries);
        return -1;
    }
    for (int i = 0; i < entry_count; i++) {
        decisions[entries[i].idx] = entries[i].decision;
    }
    free(entries);

    const char *env_names_str = getenv("READONLYBOX_FLAGGED_ENV_NAMES");
    char **flagged_names = NULL;
    int flagged_count = 0;

    if (!env_names_str || strlen(env_names_str) == 0) {
        DEBUG_PRINT("FILTER: no flagged env var names available\n");
        free(decisions);
        return 0;
    }

    /* Parse names from environment - first pass to count */
    char buf[4096];
    strlcpy(buf, env_names_str, sizeof(buf));

    char *saveptr;
    char *token = strtok_r(buf, ",", &saveptr);
    while (token) {
        flagged_count++;
        token = strtok_r(NULL, ",", &saveptr);
    }

    if (flagged_count == 0) {
        free(decisions);
        return 0;
    }

    flagged_names = calloc(flagged_count, sizeof(char *));
    if (!flagged_names) {
        free(decisions);
        return -1;
    }

    /* Second pass: actually parse the names */
    strlcpy(buf, env_names_str, sizeof(buf));
    int i = 0;
    token = strtok_r(buf, ",", &saveptr);
    while (token) {
        flagged_names[i++] = token;
        token = strtok_r(NULL, ",", &saveptr);
    }

    /* Filter envp - remove denied vars */
    /* Build new filtered envp */
    int env_count = 0;
    while (state->execve_envp[env_count]) env_count++;

    /* Allocate new envp */
    char **new_envp = calloc(env_count + 1, sizeof(char *));
    if (!new_envp) {
        DEBUG_PRINT("FILTER: failed to allocate new_envp\n");
        return -1;
    }
    unsigned long *new_env_addrs = calloc(env_count + 1, sizeof(unsigned long));
    if (!new_env_addrs) {
        free(new_envp);
        DEBUG_PRINT("FILTER: failed to allocate new_env_addrs\n");
        return -1;
    }

    /* Track which entries are being removed (for cleanup on success) */
    int *removed_indices = calloc(env_count, sizeof(int));
    if (!removed_indices) {
        free(new_envp);
        free(new_env_addrs);
        DEBUG_PRINT("FILTER: failed to allocate removed_indices\n");
        return -1;
    }
    int removed_count = 0;

    int new_idx = 0;
    for (int i = 0; i < env_count && state->execve_envp[i]; i++) {
        /* Get env var name */
        char *eq = strchr(state->execve_envp[i], '=');
        size_t name_len = eq ? (size_t)(eq - state->execve_envp[i]) : strlen(state->execve_envp[i]);

        /* Check if this var is in flagged list and denied */
        int denied = 0;
        for (int j = 0; j < flagged_count; j++) {
            if (decisions[j] == 1 && flagged_names[j]) {
                size_t flagged_len = strlen(flagged_names[j]);
                if (strncmp(state->execve_envp[i], flagged_names[j], name_len) == 0 &&
                    (name_len == flagged_len || state->execve_envp[i][name_len] == '=')) {
                    denied = 1;
                    break;
                }
            }
        }

        if (!denied) {
            new_envp[new_idx] = state->execve_envp[i];
            new_env_addrs[new_idx] = state->execve_envp_addrs[i];
            new_idx++;
        } else {
            removed_indices[removed_count++] = i;
        }
    }
    new_envp[new_idx] = NULL;
    new_env_addrs[new_idx] = 0;

    /* Free sparse decisions array - we only needed it for O(1) lookup */
    free(decisions);
    free(flagged_names);

    /* Keep pointers to old state for cleanup on failure */
    char **old_envp = state->execve_envp;
    unsigned long *old_env_addrs = state->execve_envp_addrs;

    /* Write the new envp array to the child's memory and update the register */
    MemoryContext mem_ctx;
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        DEBUG_PRINT("FILTER: failed to init memory context\n");
        free(new_envp);
        free(new_env_addrs);
        free(removed_indices);
        return -1;
    }

    /* Count how many env vars we're keeping */
    int keep_count = 0;
    while (new_envp[keep_count]) keep_count++;

    if (keep_count == 0) {
        /* No environment variables - set envp to NULL */
        unsigned long new_envp_addr = 0;

        /* Update register */
        if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
            REG_ARG4(regs) = new_envp_addr;
        } else {
            REG_ARG3(regs) = new_envp_addr;
        }

        if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
            DEBUG_PRINT("FILTER: failed to set regs: %s\n", strerror(errno));
            free(new_envp);
            free(new_env_addrs);
            free(removed_indices);
            kill(pid, SIGKILL);
            return -1;
        }

        /* Success - now update state and free removed entries */
        for (int i = 0; i < removed_count; i++) {
            free(old_envp[removed_indices[i]]);
        }
        free(old_envp);
        free(old_env_addrs);
        free(removed_indices);
        state->execve_envp = new_envp;
        state->execve_envp_addrs = new_env_addrs;

        DEBUG_PRINT("FILTER: env vars filtered, 0 remaining (empty envp)\n");
        return 0;
    }

    /* Allocate space in child for the new envp pointer array */
    unsigned long new_envp_addr = memory_alloc(&mem_ctx, (keep_count + 1) * sizeof(unsigned long));
    if (!new_envp_addr) {
        DEBUG_PRINT("FILTER: failed to allocate memory for envp\n");
        free(new_envp);
        free(new_env_addrs);
        free(removed_indices);
        return -1;
    }

    /* Write each pointer to the child's memory.
     * We use the original addresses of each string in the child memory. */
    for (int i = 0; i < keep_count; i++) {
        if (memory_write_pointer_at(&mem_ctx, new_envp_addr + i * sizeof(unsigned long),
                                     new_env_addrs[i]) != 0) {
            DEBUG_PRINT("FILTER: failed to write envp pointer %d\n", i);
            free(new_envp);
            free(new_env_addrs);
            free(removed_indices);
            return -1;
        }
    }

    /* Write NULL terminator */
    if (memory_write_pointer_at(&mem_ctx, new_envp_addr + keep_count * sizeof(unsigned long), 0) != 0) {
        DEBUG_PRINT("FILTER: failed to write envp NULL terminator\n");
        free(new_envp);
        free(new_env_addrs);
        free(removed_indices);
        return -1;
    }

    /* Update register to point to new envp array */
    if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
        REG_ARG4(regs) = new_envp_addr;
    } else {
        REG_ARG3(regs) = new_envp_addr;
    }

    /* Apply changes to the child */
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        DEBUG_PRINT("FILTER: failed to set regs: %s\n", strerror(errno));
        free(new_envp);
        free(new_env_addrs);
        free(removed_indices);
        kill(pid, SIGKILL);
        return -1;
    }

    /* Success - now update state and free removed entries */
    for (int i = 0; i < removed_count; i++) {
        free(old_envp[removed_indices[i]]);
    }
    free(old_envp);
    free(old_env_addrs);
    free(removed_indices);
    state->execve_envp = new_envp;
    state->execve_envp_addrs = new_env_addrs;

    DEBUG_PRINT("FILTER: env vars filtered, %d remaining, envp updated at 0x%lx\n", keep_count, new_envp_addr);
    return 0;
}

/* Handle syscall exit (after execution) */
int syscall_handle_exit(pid_t pid, USER_REGS *regs, ProcessState *state) {
    (void)pid;  /* Currently unused but may be needed for future logging */

    if (!state) return 0;

    if (state->in_execve && syscall_is_execve(regs)) {
        state->in_execve = 0;

        /* Check if execve failed */
        long retval = REG_ARG1(regs);  /* Return value is in RAX */
        if (retval < 0) {
            /* execve failed - clean up saved state */
            free(state->execve_pathname);
            state->execve_pathname = NULL;
            memory_free_string_array(state->execve_argv);
            state->execve_argv = NULL;
            memory_free_string_array(state->execve_envp);
            state->execve_envp = NULL;
            memory_free_ulong_array(state->execve_envp_addrs);
            state->execve_envp_addrs = NULL;
        }

        /* Note: We now detach in syscall_handle_entry when post_redirect_exec is first set,
         * so this block is no longer needed. The state is also cleaned up there.
         * Keeping this only for cleanup of saved state on execve failure.
         */
    }

    return 0;
}
