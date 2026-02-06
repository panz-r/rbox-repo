/*
 * syscall_handler.h - Execve syscall interception and handling
 */

#ifndef READONLYBOX_PTRACE_SYSCALL_HANDLER_H
#define READONLYBOX_PTRACE_SYSCALL_HANDLER_H

#include <sys/types.h>
#include <sys/user.h>

/* Architecture-specific syscall numbers */
#ifdef __x86_64__
    #define SYSCALL_EXECVE      59
    #define SYSCALL_EXECVEAT    322
    #define SYSCALL_CLONE       56
    #define SYSCALL_FORK        57
    #define SYSCALL_VFORK       58
    #define SYSCALL_EXIT_GROUP  231
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(regs)   ((regs)->orig_rax)
    #define REG_ARG1(regs)      ((regs)->rdi)
    #define REG_ARG2(regs)      ((regs)->rsi)
    #define REG_ARG3(regs)      ((regs)->rdx)
    #define REG_ARG4(regs)      ((regs)->r10)
    #define REG_SP(regs)        ((regs)->rsp)
#elif __i386__
    #define SYSCALL_EXECVE      11
    #define SYSCALL_EXECVEAT    358
    #define SYSCALL_CLONE       120
    #define SYSCALL_FORK        2
    #define SYSCALL_VFORK       190
    #define SYSCALL_EXIT_GROUP  252
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(regs)   ((regs)->orig_eax)
    #define REG_ARG1(regs)      ((regs)->ebx)
    #define REG_ARG2(regs)      ((regs)->ecx)
    #define REG_ARG3(regs)      ((regs)->edx)
    #define REG_ARG4(regs)      ((regs)->esi)
    #define REG_SP(regs)        ((regs)->esp)
#else
    #error "Unsupported architecture"
#endif

/* Process state tracking structure.
 * 
 * Why we need this: Ptrace intercepts syscalls from multiple processes
 * (the main process and its children). We need to track state for each
 * process separately to know:
 * - Which processes are in the middle of an execve
 * - Which processes were redirected to readonlybox
 * - Which processes have been detached
 * - The original command arguments for validation
 * 
 * The process table is a simple hash map indexed by PID. It can fill up
 * if the traced program creates more than MAX_PROCESSES (4096) processes.
 * In that case, new processes won't be tracked and their execves won't be
 * validated (they'll be allowed to run without server approval).
 */
typedef struct {
    pid_t pid;
    int in_execve;          /* Currently in execve syscall */
    int redirected;         /* Process was redirected to readonlybox */
    int post_redirect_exec; /* Already allowed post-redirect execve */
    int initial_execve;     /* This is the initial execve (first one) */
    int detached;           /* Process has been detached */
    char *execve_pathname;  /* Saved pathname for execve */
    char **execve_argv;     /* Saved argv for execve */
    char **execve_envp;     /* Saved envp for execve */
} ProcessState;

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
