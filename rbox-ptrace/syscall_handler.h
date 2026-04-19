/*
 * syscall_handler.h - Execve syscall interception and handling
 */

#ifndef READONLYBOX_PTRACE_SYSCALL_HANDLER_H
#define READONLYBOX_PTRACE_SYSCALL_HANDLER_H

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <linux/elf.h>
#include <time.h>

/* Shell tokenizer for parsing commands into subcommands */
#include "shell_tokenizer.h"

/* Allowance chain for validated commands */
#include "trampoline_allowance.h"

#define ALLOWANCE_TIMEOUT_SECONDS 600  /* 10 minutes */

/*
 * Internal syscall-specific access flags.
 * These are NOT ruleset SOFT_ACCESS_* flags - they are internal tracking
 * flags used by the syscall handler to track syscall properties for
 * policy decisions.
 *
 * These flags map to SOFT_ACCESS_* as follows:
 *   SYSCALL_ACCESS_TRUNCATE → SOFT_ACCESS_WRITE (truncate = write)
 *   SYSCALL_ACCESS_RMDIR    → SOFT_ACCESS_UNLINK
 *   SYSCALL_ACCESS_RENAME   → SOFT_ACCESS_WRITE | SOFT_ACCESS_UNLINK (move)
 *   SYSCALL_ACCESS_SYMLINK  → SOFT_ACCESS_LINK | SOFT_ACCESS_CREATE
 *   SYSCALL_ACCESS_CHMOD    → SOFT_ACCESS_WRITE
 *   SYSCALL_ACCESS_CHOWN    → SOFT_ACCESS_WRITE
 */
#define SYSCALL_ACCESS_TRUNCATE  (1U << 15)
#define SYSCALL_ACCESS_RMDIR     (1U << 10)
#define SYSCALL_ACCESS_RENAME    (1U << 11)
#define SYSCALL_ACCESS_SYMLINK   (1U << 12)
#define SYSCALL_ACCESS_CHMOD     (1U << 13)
#define SYSCALL_ACCESS_CHOWN     (1U << 14)


/* Architecture-specific syscall numbers and register access
 * Use system headers for syscall numbers (<sys/syscall.h> provides SYS_execve)
 * and architecture-specific register definitions from <sys/reg.h> when available.
 */
#include <sys/syscall.h>

/* Register access macros - architecture-specific */
#ifdef __x86_64__
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(r)     ((r)->orig_rax)
    #define REG_ARG1(r)         ((r)->rdi)
    #define REG_ARG2(r)         ((r)->rsi)
    #define REG_ARG3(r)         ((r)->rdx)
    #define REG_ARG4(r)         ((r)->r10)
    #define REG_SP(r)           ((r)->rsp)
    #define SET_REGS(pid, regs) ptrace(PTRACE_SETREGS, (pid), 0, (regs))
    #define GET_REGS(pid, regs) ptrace(PTRACE_GETREGS, (pid), 0, (regs))
#elif __aarch64__
    #include <sys/uio.h>
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(r)     ((r)->regs[8])   /* x8 = syscall number */
    #define REG_ARG1(r)         ((r)->regs[0])   /* x0 */
    #define REG_ARG2(r)         ((r)->regs[1])   /* x1 */
    #define REG_ARG3(r)         ((r)->regs[2])   /* x2 */
    #define REG_ARG4(r)         ((r)->regs[3])   /* x3 */
    #define REG_SP(r)           ((r)->sp)
    static inline long SET_REGS(pid_t pid, USER_REGS *regs) {
        struct iovec iov = { regs, sizeof(*regs) };
        return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
    }
    static inline long GET_REGS(pid_t pid, USER_REGS *regs) {
        struct iovec iov = { regs, sizeof(*regs) };
        return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov);
    }
#elif __riscv
    #include <sys/uio.h>
    #define USER_REGS           struct user_regs_struct
    #define REG_SYSCALL(r)     ((r)->regs[17])  /* a7 = syscall number */
    #define REG_ARG1(r)         ((r)->regs[10])  /* a0 */
    #define REG_ARG2(r)         ((r)->regs[11])  /* a1 */
    #define REG_ARG3(r)         ((r)->regs[12])  /* a2 */
    #define REG_ARG4(r)         ((r)->regs[13])  /* a3 */
    #define REG_SP(r)           ((r)->regs[2])   /* sp */
    static inline long SET_REGS(pid_t pid, USER_REGS *regs) {
        struct iovec iov = { regs, sizeof(*regs) };
        return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
    }
    static inline long GET_REGS(pid_t pid, USER_REGS *regs) {
        struct iovec iov = { regs, sizeof(*regs) };
        return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov);
    }
#else
    #error "Unsupported architecture"
#endif

/* Convenience macros using system syscall numbers.
 * System headers (<sys/syscall.h>) are the authoritative source for syscall numbers.
 * This ensures architecture-appropriate values are used automatically at build time.
 * Missing syscalls (e.g. on aarch64) get unique negative sentinel values. */

/* Sentinel values for syscalls not present on all architectures (e.g. aarch64).
 * Must be unique and negative so they never match a real syscall number. */
#define _SYS_MISSING_BASE  (-100)
#define _SYS_FORK_MISSING       (_SYS_MISSING_BASE - 1)
#define _SYS_VFORK_MISSING      (_SYS_MISSING_BASE - 2)
#define _SYS_OPEN_MISSING       (_SYS_MISSING_BASE - 3)
#define _SYS_CREAT_MISSING      (_SYS_MISSING_BASE - 4)
#define _SYS_MKDIR_MISSING      (_SYS_MISSING_BASE - 5)
#define _SYS_RMDIR_MISSING      (_SYS_MISSING_BASE - 6)
#define _SYS_UNLINK_MISSING     (_SYS_MISSING_BASE - 7)
#define _SYS_RENAME_MISSING     (_SYS_MISSING_BASE - 8)
#define _SYS_SYMLINK_MISSING    (_SYS_MISSING_BASE - 9)
#define _SYS_LINK_MISSING       (_SYS_MISSING_BASE - 10)
#define _SYS_CHMOD_MISSING      (_SYS_MISSING_BASE - 11)
#define _SYS_CHOWN_MISSING      (_SYS_MISSING_BASE - 12)
#define _SYS_UTIME_MISSING      (_SYS_MISSING_BASE - 13)
#define _SYS_STAT_MISSING       (_SYS_MISSING_BASE - 14)
#define _SYS_LSTAT_MISSING      (_SYS_MISSING_BASE - 15)
#define _SYS_ACCESS_MISSING     (_SYS_MISSING_BASE - 16)
#define SYSCALL_EXECVE      SYS_execve
#ifdef SYS_execveat
    #define SYSCALL_EXECVEAT    SYS_execveat
#else
    #error "SYS_execveat not available on this platform"
#endif
#define SYSCALL_CLONE       SYS_clone
#ifdef SYS_fork
    #define SYSCALL_FORK        SYS_fork
#else
    #define SYSCALL_FORK        _SYS_FORK_MISSING
#endif
#ifdef SYS_vfork
    #define SYSCALL_VFORK       SYS_vfork
#else
    #define SYSCALL_VFORK       _SYS_VFORK_MISSING
#endif
#define SYSCALL_EXIT_GROUP  SYS_exit_group

/* Filesystem syscalls for soft policy enforcement */
#ifdef SYS_open
    #define SYSCALL_OPEN        SYS_open
#else
    #define SYSCALL_OPEN        _SYS_OPEN_MISSING
#endif
#ifdef SYS_openat
    #define SYSCALL_OPENAT      SYS_openat
#else
    #error "SYS_openat not available on this platform"
#endif
#ifdef SYS_creat
    #define SYSCALL_CREAT       SYS_creat
#else
    #define SYSCALL_CREAT       _SYS_CREAT_MISSING
#endif
#ifdef SYS_mkdir
    #define SYSCALL_MKDIR       SYS_mkdir
#else
    #define SYSCALL_MKDIR       _SYS_MKDIR_MISSING
#endif
#ifdef SYS_mkdirat
    #define SYSCALL_MKDIRAT     SYS_mkdirat
#else
    #error "SYS_mkdirat not available on this platform"
#endif
#ifdef SYS_rmdir
    #define SYSCALL_RMDIR       SYS_rmdir
#else
    #define SYSCALL_RMDIR       _SYS_RMDIR_MISSING
#endif
#ifdef SYS_unlink
    #define SYSCALL_UNLINK      SYS_unlink
#else
    #define SYSCALL_UNLINK      _SYS_UNLINK_MISSING
#endif
#ifdef SYS_unlinkat
    #define SYSCALL_UNLINKAT    SYS_unlinkat
#else
    #error "SYS_unlinkat not available on this platform"
#endif
#ifdef SYS_rename
    #define SYSCALL_RENAME      SYS_rename
#else
    #define SYSCALL_RENAME      _SYS_RENAME_MISSING
#endif
#ifdef SYS_renameat
    #define SYSCALL_RENAMEAT    SYS_renameat
#else
    #error "SYS_renameat not available on this platform"
#endif
#ifdef SYS_symlink
    #define SYSCALL_SYMLINK     SYS_symlink
#else
    #define SYSCALL_SYMLINK     _SYS_SYMLINK_MISSING
#endif
#ifdef SYS_symlinkat
    #define SYSCALL_SYMLINKAT   SYS_symlinkat
#else
    #error "SYS_symlinkat not available on this platform"
#endif
#ifdef SYS_link
    #define SYSCALL_LINK        SYS_link
#else
    #define SYSCALL_LINK        _SYS_LINK_MISSING
#endif
#ifdef SYS_linkat
    #define SYSCALL_LINKAT      SYS_linkat
#else
    #error "SYS_linkat not available on this platform"
#endif
#ifdef SYS_chmod
    #define SYSCALL_CHMOD       SYS_chmod
#else
    #define SYSCALL_CHMOD       _SYS_CHMOD_MISSING
#endif
#ifdef SYS_chown
    #define SYSCALL_CHOWN       SYS_chown
#else
    #define SYSCALL_CHOWN       _SYS_CHOWN_MISSING
#endif
#define SYSCALL_TRUNCATE    SYS_truncate
#define SYSCALL_FTRUNCATE   SYS_ftruncate
#ifdef SYS_utime
    #define SYSCALL_UTIME   SYS_utime
#else
    #define SYSCALL_UTIME   _SYS_UTIME_MISSING
#endif

/* Read-only stat syscalls (for information leak prevention) */
#ifdef SYS_stat
    #define SYSCALL_STAT    SYS_stat
#else
    #define SYSCALL_STAT    _SYS_STAT_MISSING
#endif
#ifdef SYS_lstat
    #define SYSCALL_LSTAT   SYS_lstat
#else
    #define SYSCALL_LSTAT   _SYS_LSTAT_MISSING
#endif
#ifdef SYS_newfstatat
    #define SYSCALL_NEWFSTATAT  SYS_newfstatat
#elif defined(SYS_fstatat)
    #define SYSCALL_NEWFSTATAT  SYS_fstatat
#else
    #error "SYS_newfstatat not available on this platform"
#endif
#define SYSCALL_FSTAT       SYS_fstat
#ifdef SYS_access
    #define SYSCALL_ACCESS  SYS_access
#else
    #define SYSCALL_ACCESS  _SYS_ACCESS_MISSING
#endif
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
    long blocked_syscall;   /* Syscall number that was blocked (0 = not blocked) */

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
