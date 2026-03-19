/*
 * syscall_handler.c - Execve syscall interception and handling
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/fcntl.h>
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
#include "debug.h"

/* Forward declaration for judge execution */
extern int run_judge(const char *command, const char *caller_info);

/* Signal safety: block signals during critical sections that access g_allowances */
static sigset_t g_blocked_signals;
static bool g_signals_initialized = false;

static void init_signal_blocking(void) {
    if (g_signals_initialized) return;
    sigemptyset(&g_blocked_signals);
    sigaddset(&g_blocked_signals, SIGCHLD);
    sigaddset(&g_blocked_signals, SIGTERM);
    sigaddset(&g_blocked_signals, SIGINT);
    g_signals_initialized = true;
}

static void block_signals(void) {
    init_signal_blocking();
    pthread_sigmask(SIG_BLOCK, &g_blocked_signals, NULL);
}

static void unblock_signals(void) {
    init_signal_blocking();
    pthread_sigmask(SIG_UNBLOCK, &g_blocked_signals, NULL);
}

/* Forward declarations */
static int filter_env_decisions(ProcessState *state, pid_t pid, USER_REGS *regs);

/* Allowance table for tracking validated commands */
Allowance g_allowances[MAX_ALLOWANCES];

/* Clear all allowances for a specific PID */
static void clear_allowances_for_pid(pid_t pid) {
    block_signals();
    for (int i = 0; i < MAX_ALLOWANCES; i++) {
        if (g_allowances[i].parent_pid == pid) {
            DEBUG_PRINT("ALLOWANCE: clearing allowances for exited parent %d\n", pid);
            for (int j = 0; j < g_allowances[i].subcommand_count; j++) {
                free(g_allowances[i].subcommands[j]);
                g_allowances[i].subcommands[j] = NULL;
            }
            g_allowances[i].subcommand_count = 0;
            g_allowances[i].parent_pid = 0;
        }
    }
    unblock_signals();
}

/* Extract first word (command name) from a subcommand range */
static void extract_command_name(const char *cmd, shell_range_t range, char *buf, size_t buf_size) {
    if (range.start + range.len > strlen(cmd)) {
        buf[0] = '\0';
        return;
    }
    
    /* Copy the full subcommand (everything between separators) */
    size_t len = range.len;
    if (len >= buf_size) len = buf_size - 1;
    memcpy(buf, cmd + range.start, len);
    buf[len] = '\0';
    
    /* Trim trailing whitespace */
    while (len > 0 && (buf[len-1] == ' ' || buf[len-1] == '\t' || buf[len-1] == '\n' || buf[len-1] == '\r')) {
        buf[--len] = '\0';
    }
}

/* Check if a parent PID has a valid allowance for a specific subcommand */
static int check_allowance(pid_t parent_pid, const char *subcommand) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    block_signals();
    for (int i = 0; i < MAX_ALLOWANCES; i++) {
        if (g_allowances[i].parent_pid == 0) {
            continue;  /* Empty slot */
        }

        /* Check timeout - discard allowances older than 10 minutes */
        double age_seconds = (now.tv_sec - g_allowances[i].timestamp.tv_sec) +
                            (now.tv_nsec - g_allowances[i].timestamp.tv_nsec) / 1e9;
        if (age_seconds > ALLOWANCE_TIMEOUT_SECONDS) {
            DEBUG_PRINT("ALLOWANCE: expired allowance for parent %d\n", parent_pid);
            for (int j = 0; j < g_allowances[i].subcommand_count; j++) {
                free(g_allowances[i].subcommands[j]);
            }
            g_allowances[i].subcommand_count = 0;
            g_allowances[i].parent_pid = 0;
            continue;
        }

        /* Check if this allowance matches the parent */
        if (g_allowances[i].parent_pid == parent_pid) {
            /* Look for matching subcommand */
            for (int j = 0; j < g_allowances[i].subcommand_count; j++) {
                int word_idx = j / 32;
                int bit_idx = j % 32;

                /* Already used? */
                if (g_allowances[i].used_mask[word_idx] & (1 << bit_idx)) {
                    continue;
                }

                /* Check if subcommand matches */
                if (g_allowances[i].subcommands[j] &&
                    strcmp(g_allowances[i].subcommands[j], subcommand) == 0) {

                    /* Mark as used */
                    g_allowances[i].used_mask[word_idx] |= (1 << bit_idx);

                    DEBUG_PRINT("ALLOWANCE: using allowance for parent %d, subcommand '%s'\n",
                               parent_pid, subcommand);
                    unblock_signals();
                    return 1;  /* Allow */
                }
            }
        }
    }
    unblock_signals();

    return 0;  /* No valid allowance */
}

/* Grant allowances to a parent PID based on the full command */
static void grant_allowance(pid_t parent_pid, const char *full_command) {
    shell_parse_result_t result;
    shell_error_t err;

    /* Try to parse with fast tokenizer */
    err = shell_parse_fast(full_command, strlen(full_command),
                          &SHELL_LIMITS_DEFAULT, &result);

    if (err != SHELL_OK && err != SHELL_ETRUNC) {
        /* Parse failed - no allowances */
        DEBUG_PRINT("ALLOWANCE: shell_parse_fast failed for '%s', no allowances\n", full_command);
        return;
    }

    DEBUG_PRINT("ALLOWANCE: parsed '%s' into %d subcommands\n", full_command, result.count);

    block_signals();
    /* Find empty slot */
    int slot = -1;
    for (int i = 0; i < MAX_ALLOWANCES; i++) {
        if (g_allowances[i].parent_pid == 0 && g_allowances[i].subcommand_count == 0) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        /* No empty slot - use first one and replace */
        slot = 0;
        for (int j = 0; j < g_allowances[0].subcommand_count; j++) {
            free(g_allowances[0].subcommands[j]);
        }
    }

    /* Store allowances for each subcommand */
    g_allowances[slot].parent_pid = parent_pid;
    clock_gettime(CLOCK_MONOTONIC, &g_allowances[slot].timestamp);
    g_allowances[slot].subcommand_count = 0;
    memset(g_allowances[slot].used_mask, 0, sizeof(g_allowances[slot].used_mask));

    for (uint32_t i = 0; i < result.count && i < SHELL_MAX_SUBCOMMANDS; i++) {
        char cmd_name[256];
        extract_command_name(full_command, result.cmds[i], cmd_name, sizeof(cmd_name));

        if (cmd_name[0] != '\0') {
            g_allowances[slot].subcommands[i] = strdup(cmd_name);
            g_allowances[slot].subcommand_count++;
            DEBUG_PRINT("ALLOWANCE: granted subcommand '%s' to parent %d\n", cmd_name, parent_pid);
        }
    }
    unblock_signals();
}

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
            memory_free_ulong_array(g_process_table[i]->execve_envp_addrs);
            free(g_process_table[i]->last_validated_cmd);
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

/* Find process state without creating - returns NULL if not found */
ProcessState *syscall_find_process_state(pid_t pid) {
    int idx = pid_hash(pid);

    /* Search for existing entry */
    for (int i = 0; i < MAX_PROCESSES; i++) {
        int probe = (idx + i) % MAX_PROCESSES;
        if (g_process_table[probe] && g_process_table[probe]->pid == pid) {
            return g_process_table[probe];
        }
    }

    return NULL;  /* Not found */
}

/* Remove process state */
void syscall_remove_process_state(pid_t pid) {
    int idx = pid_hash(pid);

    for (int i = 0; i < MAX_PROCESSES; i++) {
        int probe = (idx + i) % MAX_PROCESSES;
        if (g_process_table[probe] && g_process_table[probe]->pid == pid) {
            /* Clear any allowances associated with this PID */
            clear_allowances_for_pid(pid);
            
            free(g_process_table[probe]->execve_pathname);
            memory_free_string_array(g_process_table[probe]->execve_argv);
            memory_free_string_array(g_process_table[probe]->execve_envp);
            memory_free_ulong_array(g_process_table[probe]->execve_envp_addrs);
            free(g_process_table[probe]->last_validated_cmd);
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

/* Build command string from argv - dynamic allocation */
#define MAX_COMMAND_STRING_LEN 65536  /* 64KB sanity limit */

static char *build_command_string_alloc(char *const argv[]) {
    if (!argv || !argv[0]) return NULL;

    /* First pass: calculate total length needed */
    size_t total_len = 0;
    for (int i = 0; argv[i]; i++) {
        size_t len = strlen(argv[i]) + 1;  /* +1 for space separator */
        /* Check for integer overflow */
        if (total_len + len < total_len || total_len + len > MAX_COMMAND_STRING_LEN) {
            DEBUG_PRINT("HANDLER: command string too large or overflow\n");
            return NULL;
        }
        total_len += len;
    }

    if (total_len == 0) return NULL;

    /* Allocate buffer (add 1 for null terminator) */
    char *buf = malloc(total_len + 1);
    if (!buf) return NULL;
    
    /* Second pass: build the string */
    char *p = buf;
    for (int i = 0; argv[i]; i++) {
        if (i > 0) {
            *p++ = ' ';
        }
        size_t len = strlen(argv[i]);
        memcpy(p, argv[i], len);
        p += len;
    }
    *p = '\0';
    
    return buf;
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
        memory_free_ulong_array(state->execve_envp_addrs);

        state->execve_pathname = memory_read_string(pid, pathname_addr);
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

        /* Check if this is the same command we just validated for this process.
         * This prevents duplicate requests when a process retries exec while we're waiting. */
        if (state->last_validated_cmd && strcmp(state->last_validated_cmd, command) == 0) {
            DEBUG_PRINT("HANDLER: pid=%d command '%s' already validated, allowing\n", pid, command);
            free(command);
            state->validated = 1;
            return 0;
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
        }

        /* Check if parent has an allowance for this subcommand */
        if (parent_pid > 0) {
            /* Pass the full command - the allowance check will match against stored subcommands */
            if (check_allowance(parent_pid, command)) {
                DEBUG_PRINT("HANDLER: pid=%d has allowance from parent %d for '%s', allowing\n", 
                           pid, parent_pid, command);
                state->validated = 1;
                return 0;
            }
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
                /* Filter failed - log but continue (not critical for DFA-allowed) */
                DEBUG_PRINT("HANDLER: pid=%d env filter failed for '%s', continuing anyway\n", pid, command);
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
         * This reuses all the server communication code from the main binary */
        int decision = run_judge(command, caller_info);

        DEBUG_PRINT("JUDGE: pid=%d command='%s' decision=%d\n", pid, command, decision);

        if (decision != 0) {
            /* Server denied (exit 9) or error - block the command */
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
        grant_allowance(pid, command);
        
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

        /* Clear environment decision variables to prevent leakage to subsequent commands */
        unsetenv("READONLYBOX_ENV_DECISIONS");
        unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

        free(command);
        return 0;
    }

    return 0;
}

/* Filter environment variables based on server decisions
 * Reads READONLYBOX_ENV_DECISIONS and removes denied vars from state->execve_envp
 * Also writes the filtered envp to the child's memory and updates the register */
static int filter_env_decisions(ProcessState *state, pid_t pid, USER_REGS *regs) {
    if (!state || !state->execve_envp || !state->execve_envp_addrs) return 0;
    
    const char *env_decisions_str = getenv("READONLYBOX_ENV_DECISIONS");
    if (!env_decisions_str || strlen(env_decisions_str) == 0) return 0;
    
    DEBUG_PRINT("FILTER: parsing env decisions: '%s'\n", env_decisions_str);
    
    /* Parse decisions: format is "index:decision,index:decision,..."
     * where decision is 0=allow, 1=deny
     * Uses strict parsing - abort on any malformed input */
    int decisions[256] = {0};  /* index -> decision */
    int max_index = -1;
    int parse_error = 0;

    const char *p = env_decisions_str;
    while (*p) {
        /* Parse index - must be non-negative integer */
        char *end;
        long idx = strtol(p, &end, 10);
        if (end == p || idx < 0 || idx >= 256) { parse_error = 1; break; }
        if (*end != ':') { parse_error = 1; break; }
        p = end + 1;

        /* Parse decision - must be 0 or 1 */
        int decision = *p - '0';
        if (decision != 0 && decision != 1) { parse_error = 1; break; }
        p++;

        /* Must be either comma (more entries) or null (end) */
        if (*p == ',') {
            p++;
        } else if (*p == '\0') {
            /* Valid end of string */
            decisions[(int)idx] = decision;
            if ((int)idx > max_index) max_index = (int)idx;
            break;
        } else {
            parse_error = 1; break;
        }

        decisions[(int)idx] = decision;
        if ((int)idx > max_index) max_index = (int)idx;
    }

    /* Abort on parse error - reject potentially malicious/malformed input */
    if (parse_error) {
        DEBUG_PRINT("FILTER: env decision parse error, rejecting\n");
        return -1;
    }

    if (max_index < 0) return 0;

    /* Get flagged env var names from environment */
    const char *env_names_str = getenv("READONLYBOX_FLAGGED_ENV_NAMES");
    char *flagged_names[256] = {0};
    int flagged_count = 0;

    if (!env_names_str || strlen(env_names_str) == 0) {
        DEBUG_PRINT("FILTER: no flagged env var names available\n");
        return 0;
    }

    /* Parse names from environment */
    char buf[4096];
    strncpy(buf, env_names_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr;
    char *token = strtok_r(buf, ",", &saveptr);
    while (token && flagged_count < 256) {
        flagged_names[flagged_count++] = token;
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    /* Filter envp - remove denied vars */
    /* Build new filtered envp */
    int env_count = 0;
    while (state->execve_envp[env_count]) env_count++;
    
    /* Allocate new envp */
    char **new_envp = calloc(env_count + 1, sizeof(char *));
    unsigned long *new_env_addrs = calloc(env_count + 1, sizeof(unsigned long));
    if (!new_envp) {
        free(new_env_addrs);
        DEBUG_PRINT("FILTER: failed to allocate new_envp\n");
        return -1;
    }
    if (!new_env_addrs) {
        free(new_envp);
        DEBUG_PRINT("FILTER: failed to allocate new_env_addrs\n");
        return -1;
    }
    
    int new_idx = 0;
    for (int i = 0; i < env_count && state->execve_envp[i]; i++) {
        /* Get env var name */
        char *eq = strchr(state->execve_envp[i], '=');
        size_t name_len = eq ? (size_t)(eq - state->execve_envp[i]) : strlen(state->execve_envp[i]);
        
        /* Check if this var is in flagged list and denied */
        int denied = 0;
        for (int j = 0; j < flagged_count && j <= max_index; j++) {
            if (decisions[j] == 1 && flagged_names[j]) {
                if (strncmp(state->execve_envp[i], flagged_names[j], name_len) == 0 &&
                    (flagged_names[j][name_len] == '\0' || flagged_names[j][name_len] == '=')) {
                    /* This env var is denied */
                    DEBUG_PRINT("FILTER: removing denied env var '%s'\n", state->execve_envp[i]);
                    denied = 1;
                    break;
                }
            }
        }
        
        if (denied) {
            /* Free the string for denied env vars to prevent memory leak */
            free(state->execve_envp[i]);
            state->execve_envp[i] = NULL;
        } else {
            new_envp[new_idx] = state->execve_envp[i];
            new_env_addrs[new_idx] = state->execve_envp_addrs[i];
            new_idx++;
        }
    }
    new_envp[new_idx] = NULL;
    new_env_addrs[new_idx] = 0;
    
    /* Replace envp */
    free(state->execve_envp);
    state->execve_envp = new_envp;
    free(state->execve_envp_addrs);
    state->execve_envp_addrs = new_env_addrs;
    
    /* Write the new envp array to the child's memory and update the register */
    MemoryContext mem_ctx;
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        DEBUG_PRINT("FILTER: failed to init memory context\n");
        return -1;
    }
    
    /* Count how many env vars we're keeping */
    int keep_count = 0;
    while (state->execve_envp[keep_count]) keep_count++;
    
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
            return -1;
        }
        
        DEBUG_PRINT("FILTER: env vars filtered, 0 remaining (empty envp)\n");
        return 0;
    }
    
    /* Allocate space in child for the new envp pointer array */
    unsigned long new_envp_addr = memory_alloc(&mem_ctx, (keep_count + 1) * sizeof(unsigned long));
    if (!new_envp_addr) {
        DEBUG_PRINT("FILTER: failed to allocate memory for envp\n");
        return -1;
    }
    
    /* Write each pointer to the child's memory.
     * We use the original addresses of each string in the child memory. */
    for (int i = 0; i < keep_count; i++) {
        if (memory_write_pointer_at(&mem_ctx, new_envp_addr + i * sizeof(unsigned long), 
                                     state->execve_envp_addrs[i]) < 0) {
            DEBUG_PRINT("FILTER: failed to write envp pointer %d\n", i);
            return -1;
        }
    }
    
    /* Write NULL terminator */
    if (memory_write_pointer_at(&mem_ctx, new_envp_addr + keep_count * sizeof(unsigned long), 0) < 0) {
        DEBUG_PRINT("FILTER: failed to write envp NULL terminator\n");
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
        return -1;
    }
    
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
        }

        /* Note: We now detach in syscall_handle_entry when post_redirect_exec is first set,
         * so this block is no longer needed. The state is also cleaned up there.
         * Keeping this only for cleanup of saved state on execve failure.
         */
    }

    return 0;
}
