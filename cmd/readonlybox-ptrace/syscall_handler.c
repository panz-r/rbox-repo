/*
 * syscall_handler.c - Execve syscall interception and handling
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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

/* Forward declaration for judge execution */
extern int run_judge(const char *command);

/* Debug output macro - only enabled when DEBUG is defined */
#ifdef DEBUG
static FILE *g_debug_file = NULL;

static void debug_init(void) {
    g_debug_file = fopen("/tmp/readonlybox-ptrace.log", "a");
    if (!g_debug_file) {
        g_debug_file = stderr;
    }
}

static void debug_close(void) {
    if (g_debug_file && g_debug_file != stderr) {
        fclose(g_debug_file);
    }
}

#define DEBUG_PRINT(fmt, ...) do { \
        if (!g_debug_file) debug_init(); \
        time_t now = time(NULL); \
        struct tm *tm = localtime(&now); \
        fprintf(g_debug_file, "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec); \
        fprintf(g_debug_file, fmt, ##__VA_ARGS__); \
        fflush(g_debug_file); \
    } while(0)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/* Process state table (simple hash map).
 * 
 * IMPORTANT: This is for CONCURRENT processes, not total spawns over time.
 * When a process exits, its entry is removed and can be reused.
 * The limit (4096) is the maximum number of processes that can be
 * traced simultaneously. For long-running shells that spawn many
 * commands over time, this is sufficient because each command process
 * exits and frees its table entry.
 */
#define MAX_PROCESSES 4096
static ProcessState *g_process_table[MAX_PROCESSES];
static pid_t g_main_process_pid = 0;

/* Get hash index for pid */
static int pid_hash(pid_t pid) {
    return pid % MAX_PROCESSES;
}

/* Set the main process PID */
void syscall_set_main_process(pid_t pid) {
    g_main_process_pid = pid;
}

/* Initialize syscall handler */
int syscall_handler_init(void) {
    memset(g_process_table, 0, sizeof(g_process_table));
    g_main_process_pid = 0;
    return 0;
}

/* Cleanup syscall handler */
void syscall_handler_cleanup(void) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (g_process_table[i]) {
            free(g_process_table[i]->execve_pathname);
            memory_free_string_array(g_process_table[i]->execve_argv);
            memory_free_string_array(g_process_table[i]->execve_envp);
            free(g_process_table[i]);
            g_process_table[i] = NULL;
        }
    }
}

/* Get process state (create if needed) */
ProcessState *syscall_get_process_state(pid_t pid) {
    int idx = pid_hash(pid);

    /* Search for existing entry */
    for (int i = 0; i < MAX_PROCESSES; i++) {
        int probe = (idx + i) % MAX_PROCESSES;
        if (g_process_table[probe] && g_process_table[probe]->pid == pid) {
            return g_process_table[probe];
        }
        if (!g_process_table[probe]) {
            /* Create new entry */
            g_process_table[probe] = calloc(1, sizeof(ProcessState));
            if (g_process_table[probe]) {
                g_process_table[probe]->pid = pid;
            }
            return g_process_table[probe];
        }
    }

    return NULL;  /* Table full */
}

/* Remove process state */
void syscall_remove_process_state(pid_t pid) {
    int idx = pid_hash(pid);

    for (int i = 0; i < MAX_PROCESSES; i++) {
        int probe = (idx + i) % MAX_PROCESSES;
        if (g_process_table[probe] && g_process_table[probe]->pid == pid) {
            free(g_process_table[probe]->execve_pathname);
            memory_free_string_array(g_process_table[probe]->execve_argv);
            memory_free_string_array(g_process_table[probe]->execve_envp);
            free(g_process_table[probe]);
            g_process_table[probe] = NULL;
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

/* Build command string from argv */
static void build_command_string(char *buf, size_t buf_size, char *const argv[]) {
    buf[0] = '\0';
    if (!argv || !argv[0]) return;

    /* Start with argv[0] (the command name) */
    strncpy(buf, argv[0], buf_size - 1);
    buf[buf_size - 1] = '\0';

    /* Append arguments */
    size_t len = strlen(buf);
    for (int i = 1; argv[i] && len < buf_size - 2; i++) {
        strncat(buf, " ", buf_size - len - 1);
        len = strlen(buf);
        strncat(buf, argv[i], buf_size - len - 1);
        len = strlen(buf);
    }
}

/* Get basename from path */
static const char *get_basename(const char *path) {
    if (!path) return "unknown";
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

/* Block execve by replacing it with a shell command that prints permission denied */
static int block_execve(pid_t pid, USER_REGS *regs) {
    MemoryContext mem_ctx;

    /* Initialize memory context */
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        fprintf(stderr, "readonlybox-ptrace: Failed to init memory context for block\n");
        return -1;
    }

    /* Use /bin/sh to print the permission denied message */
    const char *sh_path = "/bin/sh";
    const char *dash_c = "-c";
    const char *message_cmd = "echo 'Permission denied, this command was not executed and had no effects on the system.' >&2; exit 1";

    /* Write strings to process memory */
    unsigned long sh_addr = memory_write_string(&mem_ctx, sh_path);
    unsigned long dash_c_addr = memory_write_string(&mem_ctx, dash_c);
    unsigned long cmd_addr = memory_write_string(&mem_ctx, message_cmd);

    if (!sh_addr || !dash_c_addr || !cmd_addr) {
        fprintf(stderr, "readonlybox-ptrace: Failed to write shell command strings\n");
        return -1;
    }

    /* Create argv = {"/bin/sh", "-c", "echo ...", NULL} */
    unsigned long argv_ptrs[4];
    argv_ptrs[0] = sh_addr;
    argv_ptrs[1] = dash_c_addr;
    argv_ptrs[2] = cmd_addr;
    argv_ptrs[3] = 0;

    unsigned long new_argv = memory_write_pointer_array(&mem_ctx, argv_ptrs, 3);
    if (!new_argv) {
        fprintf(stderr, "readonlybox-ptrace: Failed to write argv for shell\n");
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
        perror("ptrace(SETREGS)");
        return -1;
    }

    return 0;
}

/* Handle syscall entry (before execution) */
int syscall_handle_entry(pid_t pid, USER_REGS *regs, ProcessState *state) {
    if (!state) {
        DEBUG_PRINT("HANDLER: No state for pid=%d\n", pid);
        return 0;
    }

    /* Skip detached processes */
    if (state->detached) {
        return 0;
    }

    /* Only check redirected flag for execve syscalls */
    if (syscall_is_execve(regs)) {
        DEBUG_PRINT("HANDLER: pid=%d execve detected, initial=%d, detached=%d, redirected=%d, post_redirect=%d\n", 
                    pid, state->initial_execve, state->detached, state->redirected, state->post_redirect_exec);
        
        /* Check if this process was already redirected to readonlybox */
        if (state->redirected) {
            /* Check if we've already allowed the post-redirect execve.
             * If yes, this is a subsequent exec (like npm→tsx) - check what is being execed.
             * If no, this is the approved command (readonlybox→npm) - allow without request. */
            if (state->post_redirect_exec) {
                /* This process already executed the approved command.
                 * Allow subsequent execs to proceed but they should go through validation
                 * since they're new commands (e.g., npm→tsx). */
                DEBUG_PRINT("HANDLER: pid=%d allowing execve after approved command to be validated\n", pid);
                /* Fall through to validation logic */
            } else {
                /* This is readonlybox execving the approved command - allow without request */
                DEBUG_PRINT("HANDLER: pid=%d allowing post-redirect execve (readonlybox running command), continuing to trace\n", pid);
                state->post_redirect_exec = 1;
                state->in_execve = 1;  /* Mark that we're in an execve so exit handler knows */
                state->validated = 1;
                /* Continue tracing - don't detach */
                return 0;
            }
        }
        
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
        
        if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
            /* execveat: dirfd is in arg1, pathname in arg2 */
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

        state->execve_pathname = memory_read_string(pid, pathname_addr);
        state->execve_argv = memory_read_string_array(pid, argv_addr);
        state->execve_envp = memory_read_string_array(pid, envp_addr);

        if (!state->execve_pathname || !state->execve_argv) {
            /* Block the command by replacing it with a permission denied message */
            if (block_execve(pid, regs) < 0) {
                /* If we can't block it, kill the process */
                kill(pid, SIGKILL);
            }
            return 0;
        }

        /* Build command string for validation */
        char command[4096];
        build_command_string(command, sizeof(command), state->execve_argv);

        /* Check if this is the main process's initial execve - allow without validation */
        if (!state->initial_execve && pid == g_main_process_pid) {
            /* This is the main process's first execve, allow without validation */
            DEBUG_PRINT("HANDLER: Allowing main process %d initial execve without validation\n", pid);
            state->initial_execve = 1;
            /* Don't detach - continue tracing this process for future execves */
            return 0;
        }

        /* Mark that we've seen an execve for this process */
        if (!state->initial_execve) {
            state->initial_execve = 1;
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
            /* Continue tracing - don't detach */
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
         * This reuses all the server communication code from the main binary */
        int decision = run_judge(command);

        DEBUG_PRINT("JUDGE: pid=%d command='%s' decision=%d\n", pid, command, decision);

        if (decision != 0) {
            /* Server denied (exit 9) or error - block the command */
            DEBUG_PRINT("HANDLER: pid=%d server denied command '%s', blocking\n", pid, command);
            if (block_execve(pid, regs) < 0) {
                kill(pid, SIGKILL);
            }
            return 0;
        }

        /* Server allowed - let the execve proceed */
        DEBUG_PRINT("HANDLER: pid=%d server allowed command '%s', continuing to trace\n", pid, command);
        state->validated = 1;
        return 0;
    }

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
        }

        /* Note: We now detach in syscall_handle_entry when post_redirect_exec is first set,
         * so this block is no longer needed. The state is also cleaned up there.
         * Keeping this only for cleanup of saved state on execve failure.
         */
    }

    return 0;
}
