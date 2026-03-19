/*
 * syscall_handler.h - Execve syscall interception and handling
 */

#ifndef READONLYBOX_PTRACE_SYSCALL_HANDLER_H
#define READONLYBOX_PTRACE_SYSCALL_HANDLER_H

#include <sys/types.h>
#include <sys/user.h>
#include <time.h>

/* Shell tokenizer for parsing commands into subcommands */
#include "shell_tokenizer.h"

/*
 * Allowance tracking for validated commands.
 * When a command is allowed, child processes can inherit the permission
 * to run subcommands without requiring new server requests.
 *
 * LIMITS:
 * - MAX_ALLOWANCES (256): Maximum number of concurrent allowances
 * - ALLOWANCE_TIMEOUT_SECONDS (600): Allowances expire after 10 minutes
 * - SHELL_MAX_SUBCOMMANDS: Maximum subcommands per command (from shell_tokenizer.h)
 *
 * When the allowance table is full, old allowances are reused (oldest slot).
 * Each allowance tracks subcommands from one allowed parent command.
 */
#define MAX_ALLOWANCES 256
#define ALLOWANCE_TIMEOUT_SECONDS 600  /* 10 minutes */

typedef struct {
    pid_t parent_pid;           /* PID of the parent that was allowed */
    char *subcommands[SHELL_MAX_SUBCOMMANDS]; /* The subcommands that are allowed */
    int subcommand_count;
    struct timespec timestamp;  /* When the allowance was granted (monotonic clock) */
    int used_mask[(SHELL_MAX_SUBCOMMANDS + 31) / 32]; /* Bitmap of used subcommands */
} Allowance;

/* Global allowance table */
extern Allowance g_allowances[MAX_ALLOWANCES];

/* Architecture-specific syscall numbers and register access
 * Use system headers for syscall numbers (<sys/syscall.h> provides SYS_execve)
 * and architecture-specific register definitions from <sys/reg.h> when available.
 */
#include <sys/syscall.h>

/* Register access macros - architecture-specific */
#ifdef __x86_64__
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(regs)   ((regs)->orig_rax)
    #define REG_ARG1(regs)      ((regs)->rdi)
    #define REG_ARG2(regs)      ((regs)->rsi)
    #define REG_ARG3(regs)      ((regs)->rdx)
    #define REG_ARG4(regs)      ((regs)->r10)
    #define REG_SP(regs)        ((regs)->rsp)
#elif __i386__
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(regs)   ((regs)->orig_eax)
    #define REG_ARG1(regs)      ((regs)->ebx)
    #define REG_ARG2(regs)      ((regs)->ecx)
    #define REG_ARG3(regs)      ((regs)->edx)
    #define REG_ARG4(regs)      ((regs)->esi)
    #define REG_SP(regs)        ((regs)->esp)
#elif __aarch64__
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(regs)   ((regs)->regs[8])   /* x8 = syscall number */
    #define REG_ARG1(regs)      ((regs)->regs[0])   /* x0 */
    #define REG_ARG2(regs)      ((regs)->regs[1])   /* x1 */
    #define REG_ARG3(regs)      ((regs)->regs[2])   /* x2 */
    #define REG_ARG4(regs)      ((regs)->regs[3])   /* x3 */
    #define REG_SP(regs)        ((regs)->sp)
#else
    #error "Unsupported architecture"
#endif

/* Convenience macros using system syscall numbers */
#define SYSCALL_EXECVE      SYS_execve
#define SYSCALL_EXECVEAT    SYS_execveat
#define SYSCALL_CLONE       SYS_clone
#define SYSCALL_FORK        SYS_fork
#define SYSCALL_VFORK       SYS_vfork
#define SYSCALL_EXIT_GROUP  SYS_exit_group

/*
 * Process state tracking structure.
 *
 * Why we need this: Ptrace intercepts syscalls from multiple processes
 * (the main process and its children). We need to track state for each
 * process separately to know:
 * - Which processes are in the middle of an execve
 * - Which processes have been detached
 * - The original command arguments for validation
 *
 * LIMITS:
 * - MAX_PROCESSES (4096): Maximum simultaneous traced processes
 *   When full, new processes bypass validation (security tradeoff)
 * - Process table is a simple hash map indexed by PID
 * - When a process exits, its entry is freed for reuse
 *
 * The 4096 limit applies to simultaneous processes. Long-running shells
 * that spawn many sequential commands are fine because each command
 * process exits and frees its table entry.
 */
typedef struct {
    pid_t pid;
    int in_execve;          /* Currently in execve syscall */
    int initial_execve;     /* This is the initial execve (first one) */
    int detached;           /* Process has been detached */
    int validated;          /* This execve has been validated */
    char *execve_pathname;  /* Saved pathname for execve */
    char **execve_argv;     /* Saved argv for execve */
    char **execve_envp;     /* Saved envp for execve */
    unsigned long *execve_envp_addrs; /* Original addresses of envp strings in child memory */
    char *last_validated_cmd; /* Last command that was validated for this process */
} ProcessState;

/* Find process state without creating if not found - for fork event handling */
ProcessState *syscall_find_process_state(pid_t pid);

/* Set the main process PID */
void syscall_set_main_process(pid_t pid);

/* Initialize syscall handler */
int syscall_handler_init(void);

/* Cleanup syscall handler */
void syscall_handler_cleanup(void);

/* Handle syscall entry (before execution) */
int syscall_handle_entry(pid_t pid, USER_REGS *regs, ProcessState *state);

/* Handle syscall exit (after execution) */
int syscall_handle_exit(pid_t pid, USER_REGS *regs, ProcessState *state);

/* Check if syscall is execve */
int syscall_is_execve(USER_REGS *regs);

/* Check if syscall is fork/clone/vfork */
int syscall_is_fork(USER_REGS *regs);

/* Get process state (create if needed) */
ProcessState *syscall_get_process_state(pid_t pid);

/* Remove process state */
void syscall_remove_process_state(pid_t pid);

#endif /* READONLYBOX_PTRACE_SYSCALL_HANDLER_H */
