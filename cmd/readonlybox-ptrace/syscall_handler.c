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
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <limits.h>

#include "syscall_handler.h"
#include "memory.h"
#include "validation.h"
#include "protocol.h"

/* Debug output macro - only enabled when DEBUG is defined */
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
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

/* Check if syscall is execve */
int syscall_is_execve(USER_REGS *regs) {
    return REG_SYSCALL(regs) == SYSCALL_EXECVE;
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

/* Get path to readonlybox binary relative to our executable location */
static const char *get_readonlybox_path(void) {
    static char path_buf[PATH_MAX];
    
    /* First try production path */
    if (access("/usr/local/bin/readonlybox", X_OK) == 0) {
        return "/usr/local/bin/readonlybox";
    }
    
    /* Try to find relative to our executable location */
    /* /proc/self/exe gives us the path to this binary */
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len > 0) {
        self_path[len] = '\0';
        /* Get directory of our executable */
        char *dir = dirname(self_path);
        /* Try ../../bin/readonlybox (from cmd/readonlybox-ptrace/) */
        snprintf(path_buf, sizeof(path_buf), "%s/../../bin/readonlybox", dir);
        if (access(path_buf, X_OK) == 0) {
            return path_buf;
        }
    }
    
    /* Fall back to PATH lookup */
    return "readonlybox";
}

/* Redirect execve to readonlybox --run */
static int redirect_to_readonlybox(pid_t pid, USER_REGS *regs,
                                   const char *pathname,
                                   char **argv, char **envp) {
    MemoryContext mem_ctx;

    /* Initialize memory context */
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        fprintf(stderr, "readonlybox-ptrace: Failed to init memory context\n");
        return -1;
    }

    /* Find readonlybox binary */
    const char *readonlybox_path = get_readonlybox_path();

    /* Get current working directory */
    char cwd[512] = {0};
    char cwd_link[64];
    snprintf(cwd_link, sizeof(cwd_link), "/proc/%d/cwd", pid);
    ssize_t cwd_len = readlink(cwd_link, cwd, sizeof(cwd) - 1);
    if (cwd_len > 0) {
        cwd[cwd_len] = '\0';
    } else {
        /* Use empty string if we can't read target's CWD - don't use tracer's CWD */
        cwd[0] = '\0';
    }

    /* Get caller name (our own process name) */
    char caller[256] = {0};
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
    char exe_path[512];
    ssize_t exe_len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
    if (exe_len > 0) {
        exe_path[exe_len] = '\0';
        strncpy(caller, get_basename(exe_path), sizeof(caller) - 1);
    }

    /* Count original arguments */
    int orig_argc = 0;
    while (argv && argv[orig_argc]) orig_argc++;

    /* Build new argv for readonlybox --run */
    /* Format: readonlybox --caller <app:execve> --cwd <path> --run <orig-path> <orig-args...> */
    int new_argc = 6 + orig_argc;  /* readonlybox + 5 flags + orig args */
    unsigned long *argv_ptrs = calloc(new_argc + 1, sizeof(unsigned long));
    if (!argv_ptrs) return -1;

    /* Build caller info */
    char caller_info[320];
    if (caller[0]) {
        snprintf(caller_info, sizeof(caller_info), "%s:execve", caller);
    } else {
        strcpy(caller_info, "unknown:execve");
    }

    /* Write strings to traced process memory */
    int idx = 0;
    argv_ptrs[idx++] = memory_write_string(&mem_ctx, readonlybox_path);
    argv_ptrs[idx++] = memory_write_string(&mem_ctx, "--caller");
    argv_ptrs[idx++] = memory_write_string(&mem_ctx, caller_info);
    argv_ptrs[idx++] = memory_write_string(&mem_ctx, "--cwd");
    argv_ptrs[idx++] = memory_write_string(&mem_ctx, cwd);
    argv_ptrs[idx++] = memory_write_string(&mem_ctx, "--run");
    argv_ptrs[idx++] = memory_write_string(&mem_ctx, pathname);

    /* Copy original arguments (skip argv[0] since we use pathname) */
    for (int i = 1; i < orig_argc && idx < new_argc; i++) {
        argv_ptrs[idx++] = memory_write_string(&mem_ctx, argv[i]);
    }

    /* Write argv array */
    unsigned long new_argv = memory_write_pointer_array(&mem_ctx, argv_ptrs, idx);
    free(argv_ptrs);

    if (!new_argv) {
        fprintf(stderr, "readonlybox-ptrace: Failed to write argv\n");
        return -1;
    }

    /* Count environment variables */
    int envc = 0;
    while (envp && envp[envc]) envc++;

    /* Copy environment and add READONLYBOX_CWD */
    unsigned long *env_ptrs = calloc(envc + 2, sizeof(unsigned long));
    if (!env_ptrs) return -1;

    for (int i = 0; i < envc; i++) {
        env_ptrs[i] = memory_write_string(&mem_ctx, envp[i]);
    }

    /* Add READONLYBOX_CWD */
    char cwd_env[1024];
    snprintf(cwd_env, sizeof(cwd_env), "READONLYBOX_CWD=%s", cwd);
    env_ptrs[envc] = memory_write_string(&mem_ctx, cwd_env);

    /* Write envp array */
    unsigned long new_envp = memory_write_pointer_array(&mem_ctx, env_ptrs, envc + 1);
    free(env_ptrs);

    if (!new_envp) {
        fprintf(stderr, "readonlybox-ptrace: Failed to write envp\n");
        return -1;
    }

    /* Write readonlybox path */
    unsigned long new_path = memory_write_string(&mem_ctx, readonlybox_path);
    if (!new_path) {
        fprintf(stderr, "readonlybox-ptrace: Failed to write path\n");
        return -1;
    }

    /* Update registers */
    REG_ARG1(regs) = new_path;
    REG_ARG2(regs) = new_argv;
    REG_ARG3(regs) = new_envp;

    /* Apply changes */
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        perror("ptrace(SETREGS)");
        return -1;
    }

    return 0;
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

    /* Update registers to exec /bin/sh */
    REG_ARG1(regs) = sh_addr;
    REG_ARG2(regs) = new_argv;
    REG_ARG3(regs) = 0;  /* envp = NULL (inherit from parent) */

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
        DEBUG_PRINT("HANDLER: pid=%d execve detected, initial=%d, detached=%d, redirected=%d\n", 
                    pid, state->initial_execve, state->detached, state->redirected);
        /* Check if this process was already redirected to readonlybox */
        if (state->redirected) {
            /* Only allow ONE execve after redirection (readonlybox execing the actual command) */
            if (state->post_redirect_exec) {
                /* This shouldn't happen - block it */
                DEBUG_PRINT("HANDLER: pid=%d blocking unexpected second execve after redirect\n", pid);
                if (block_execve(pid, regs) < 0) {
                    kill(pid, SIGKILL);
                }
                return 0;
            }
            DEBUG_PRINT("HANDLER: pid=%d allowing post-redirect execve (readonlybox running command), detaching immediately\n", pid);
            state->post_redirect_exec = 1;
            state->in_execve = 1;  /* Mark that we're in an execve so exit handler knows */
            /* Detach immediately - don't wait for exit handler to avoid blocking bash */
            state->detached = 1;
            /* Just detach - PTRACE_DETACH automatically continues the process */
            if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
                perror("ptrace(DETACH)");
            }
            /* Clean up process state to prevent PID reuse issues */
            syscall_remove_process_state(pid);
            return 0;
        }
        state->in_execve = 1;

        /* Read execve arguments */
        unsigned long pathname_addr = REG_ARG1(regs);
        unsigned long argv_addr = REG_ARG2(regs);
        unsigned long envp_addr = REG_ARG3(regs);

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
            /* Fast allow - let it proceed and DETACH from this child process */
            /* We don't need to trace child processes of bash, only the main process */
            DEBUG_PRINT("DFA: Fast-allowing command '%s'\n", command);
            state->detached = 1;
            if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
                perror("ptrace(DETACH)");
            }
            /* Clean up process state to prevent PID reuse issues */
            syscall_remove_process_state(pid);
            return 0;
        }

        /* DFA didn't allow - need to redirect to readonlybox --run for validation */

        /* Redirect to readonlybox --run */
        if (redirect_to_readonlybox(pid, regs, state->execve_pathname,
                                    state->execve_argv, state->execve_envp) < 0) {
            /* Block the command if we can't redirect */
            if (block_execve(pid, regs) < 0) {
                kill(pid, SIGKILL);
            }
            return 0;
        }

        /* After redirect, the execve will call readonlybox.
         * We detach immediately - no need to trace our own binary.
         * readonlybox will handle server communication and exec the actual command.
         */
        DEBUG_PRINT("HANDLER: pid=%d redirected to readonlybox, detaching immediately\n", pid);
        state->detached = 1;
        if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
            perror("ptrace(DETACH)");
        }
        syscall_remove_process_state(pid);
    }

    return 0;
}

/* Handle syscall exit (after execution) */
int syscall_handle_exit(pid_t pid, USER_REGS *regs, ProcessState *state) {
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
