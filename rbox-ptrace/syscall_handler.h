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

/* Allowance chain for validated commands */
#include "trampoline_allowance.h"

#define ALLOWANCE_TIMEOUT_SECONDS 600  /* 10 minutes */


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
#elif __riscv
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(regs)   ((regs)->regs[17])  /* a7 = syscall number */
    #define REG_ARG1(regs)      ((regs)->regs[10])  /* a0 */
    #define REG_ARG2(regs)      ((regs)->regs[11])  /* a1 */
    #define REG_ARG3(regs)      ((regs)->regs[12])  /* a2 */
    #define REG_ARG4(regs)      ((regs)->regs[13])  /* a3 */
    #define REG_SP(regs)        ((regs)->regs[2])   /* sp */
#else
    #error "Unsupported architecture"
#endif

/* Convenience macros using system syscall numbers.
 * System headers (<sys/syscall.h>) are the authoritative source for syscall numbers.
 * This ensures architecture-appropriate values are used automatically at build time.
 * If a syscall is not available on the build system, we fail at compile time. */
#define SYSCALL_EXECVE      SYS_execve
#ifdef SYS_execveat
    #define SYSCALL_EXECVEAT    SYS_execveat
#else
    #error "SYS_execveat not available on this platform"
#endif
#define SYSCALL_CLONE       SYS_clone
#define SYSCALL_FORK        SYS_fork
#define SYSCALL_VFORK       SYS_vfork
#define SYSCALL_EXIT_GROUP  SYS_exit_group

/* Filesystem syscalls for soft policy enforcement
 * Use SYS_* macros from <sys/syscall.h> for architecture portability */
#define SYSCALL_OPEN        SYS_open
#ifdef SYS_openat
    #define SYSCALL_OPENAT      SYS_openat
#else
    #error "SYS_openat not available on this platform"
#endif
#define SYSCALL_CREAT       SYS_creat
#define SYSCALL_MKDIR       SYS_mkdir
#ifdef SYS_mkdirat
    #define SYSCALL_MKDIRAT     SYS_mkdirat
#else
    #error "SYS_mkdirat not available on this platform"
#endif
#define SYSCALL_RMDIR       SYS_rmdir
#define SYSCALL_UNLINK      SYS_unlink
#ifdef SYS_unlinkat
    #define SYSCALL_UNLINKAT    SYS_unlinkat
#else
    #error "SYS_unlinkat not available on this platform"
#endif
#define SYSCALL_RENAME      SYS_rename
#ifdef SYS_renameat
    #define SYSCALL_RENAMEAT    SYS_renameat
#else
    #error "SYS_renameat not available on this platform"
#endif
#define SYSCALL_SYMLINK     SYS_symlink
#ifdef SYS_symlinkat
    #define SYSCALL_SYMLINKAT   SYS_symlinkat
#else
    #error "SYS_symlinkat not available on this platform"
#endif
#define SYSCALL_LINK        SYS_link
#ifdef SYS_linkat
    #define SYSCALL_LINKAT      SYS_linkat
#else
    #error "SYS_linkat not available on this platform"
#endif
#define SYSCALL_CHMOD       SYS_chmod
#define SYSCALL_CHOWN       SYS_chown
#define SYSCALL_TRUNCATE    SYS_truncate
#define SYSCALL_FTRUNCATE   SYS_ftruncate
#define SYSCALL_UTIME       SYS_utime

/* Read-only stat syscalls (for information leak prevention) */
#define SYSCALL_STAT        SYS_stat
#define SYSCALL_LSTAT       SYS_lstat
#ifdef SYS_newfstatat
    #define SYSCALL_NEWFSTATAT  SYS_newfstatat
#elif defined(SYS_fstatat)
    #define SYSCALL_NEWFSTATAT  SYS_fstatat
#else
    #error "SYS_newfstatat not available on this platform"
#endif
#define SYSCALL_FSTAT       SYS_fstat
#define SYSCALL_ACCESS      SYS_access
#ifdef SYS_faccessat
    #define SYSCALL_FACCESSAT SYS_faccessat
#else
    #error "SYS_faccessat not available on this platform"
#endif
#ifdef SYS_faccessat2
    #define SYSCALL_FACCESSAT2 SYS_faccessat2
#else
    #define SYSCALL_FACCESSAT2 (-1)
#endif

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
 * The process table is a dynamic hash table that grows automatically
 * when the load factor exceeds 0.75. It starts at 64 entries and
 * doubles in size as needed, handling arbitrary numbers of concurrent
 * processes without hitting a fixed limit.
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

    /* Hierarchical allowance chain for validated commands */
    AllowSet chains;

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
