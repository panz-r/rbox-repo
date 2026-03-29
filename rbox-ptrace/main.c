/*
 * main.c - Entry point for readonlybox-ptrace
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <math.h>
#include <libgen.h>
#include <syslog.h>

#include "syscall_handler.h"
#include "validation.h"
#include "protocol.h"
#include <rbox_protocol_defs.h>
#include <rbox_protocol.h>
#include "debug.h"
#include "env.h"
#include "pkexec.h"
#include "judge.h"
#include "privilege.h"
#include "sandbox.h"

#include "env_screener.h"

/* Debug file pointer - defined here, used by DEBUG_PRINT in all files */
#ifdef DEBUG
FILE *g_debug_file = NULL;

void debug_init(void) {
    if (g_debug_file) return;
    int fd = open("/tmp/readonlybox-ptrace.log", O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC, 0644);
    if (fd >= 0) {
        g_debug_file = fdopen(fd, "a");
    }
    if (!g_debug_file && fd >= 0) {
        close(fd);
        g_debug_file = stderr;
    } else if (!g_debug_file) {
        g_debug_file = stderr;
    }
}
#endif

static const char *g_progname = "readonlybox-ptrace";
static bool g_keep_env = true;  /* Keep environment by default */
static bool g_skip_pkexec = false;  /* Skip pkexec even if no ptrace capability */
static char **g_extra_env = NULL;
static int g_extra_env_count = 0;

/* Forward declarations */
static char *resolve_command_path(const char *cmd);

/* Cleanup function for atexit */
static void cleanup_global_resources(void) {
    /* Clear flagged env storage */
    env_clear_flagged();

    /* Close syslog */
    closelog();
}

static void print_usage(void) {
    fprintf(stderr, "Usage: %s wrap <command> [args...]\n", g_progname);
    fprintf(stderr, "       %s [options] -- <command> [args...]\n", g_progname);
    fprintf(stderr, "       %s -p <pid> [options] -- <command> [args...]\n", g_progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Run a command with ptrace-based command interception.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --attach <pid>   Attach to a running process\n");
    fprintf(stderr, "  -u, --uid <uid>      Run command as specified user\n");
    fprintf(stderr, "  -c, --cwd <path>     Set working directory\n");
    fprintf(stderr, "  -m, --cmd <path>     Command path (for pkexec)\n");
    fprintf(stderr, "  --keep-env           Keep original environment (default)\n");
    fprintf(stderr, "  --clean-env          Clear environment before execution\n");
    fprintf(stderr, "  --env VAR=value      Set environment variable for command\n");
    fprintf(stderr, "  --memory-limit <n>   Set memory limit (e.g., 256M, 1G)\n");
    fprintf(stderr, "  --hard-allow <p>    Allow directory with mode (path:mode,...)\n");
    fprintf(stderr, "                       Modes: ro (read), rx (read/exec), rw, rwx\n");
    fprintf(stderr, "  --hard-deny <p>     Deny directory access\n");
    fprintf(stderr, "  --no-network         Block network access\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
    fprintf(stderr, "  -v, --version        Show version\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "The -- separator is optional and separates options from the command.\n");
}

/* Drop privileges and apply extra environment variables */
static void drop_privileges_and_apply_env(void) {
    /* Drop privileges using privilege module */
    privilege_drop();

    /* Apply extra environment variables from --env options */
    for (int i = 0; i < g_extra_env_count; i++) {
        char *eq = strchr(g_extra_env[i], '=');
        if (eq) {
            *eq = '\0';
            if (setenv(g_extra_env[i], eq + 1, 1) != 0) {
                fprintf(stderr, "Warning: failed to set env var %s\n", g_extra_env[i]);
            }
            *eq = '=';
        } else {
            unsetenv(g_extra_env[i]);
        }
    }
}

static int trace_process(pid_t initial_pid) {
    int status;
    USER_REGS regs;
    pid_t pid;

    pid = waitpid(initial_pid, &status, WUNTRACED);
    if (pid < 0) {
        perror("waitpid");
        return 1;
    }

    if (ptrace(PTRACE_SETOPTIONS, pid, 0,
               PTRACE_O_TRACESYSGOOD |
               PTRACE_O_TRACEEXEC |
               PTRACE_O_TRACECLONE |
               PTRACE_O_TRACEFORK |
               PTRACE_O_TRACEVFORK) < 0) {
        perror("ptrace(SETOPTIONS)");
        return 1;
    }

    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
        perror("ptrace(SYSCALL)");
        return 1;
    }

    while (1) {
        pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status)) {
            if (pid == initial_pid) {
                return WEXITSTATUS(status);
            }
            syscall_remove_process_state(pid);
            continue;
        }

        if (WIFSIGNALED(status)) {
            if (pid == initial_pid) {
                return 128 + WTERMSIG(status);
            }
            syscall_remove_process_state(pid);
            continue;
        }

        /* Handle fork/clone/vfork */
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)) ||
            status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
            status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
            unsigned long child_pid;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid) != 0) {
                DEBUG_PRINT("PARENT: pid=%d GETEVENTMSG failed: %s\n", pid, strerror(errno));
                if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
                    DEBUG_PRINT("PARENT: pid=%d SYSCALL failed: %s\n", pid, strerror(errno));
                }
                continue;
            }

            /* Check if parent is readonlybox binary - if so, detach its child.
             *
             * Why: When a command is redirected to readonlybox for validation,
             * readonlybox contacts the server and gets approval. Then readonlybox
             * forks a child process to execute the actual command. We don't want
             * to trace that child because:
             * 1. It was already validated when we redirected to readonlybox
             * 2. We don't want to intercept readonlybox's internal operations
             *
             * Use stored execve_pathname from parent's ProcessState when available
             * to avoid race condition with /proc/pid/exe reading.
             */
            bool parent_is_readonlybox = false;
            bool parent_is_tracer = false;
            char parent_exe[256] = "unknown";

            ProcessState *parent_state = syscall_find_process_state(pid);
            if (parent_state && parent_state->execve_pathname) {
                /* Use stored pathname from parent's state */
                const char *path = parent_state->execve_pathname;
                strncpy(parent_exe, path, sizeof(parent_exe) - 1);
                parent_exe[sizeof(parent_exe) - 1] = '\0';
                if (strstr(parent_exe, "readonlybox") != NULL) {
                    parent_is_readonlybox = true;
                }
                if (strstr(parent_exe, "readonlybox-ptrace") != NULL) {
                    parent_is_tracer = true;
                }
            } else {
                /* Fallback to /proc/pid/exe if parent state not available */
                char parent_link[64];
                snprintf(parent_link, sizeof(parent_link), "/proc/%d/exe", pid);
                ssize_t parent_len = readlink(parent_link, parent_exe, sizeof(parent_exe) - 1);
                if (parent_len > 0) {
                    parent_exe[parent_len] = '\0';
                    if (strstr(parent_exe, "readonlybox") != NULL) {
                        parent_is_readonlybox = true;
                    }
                    if (strstr(parent_exe, "readonlybox-ptrace") != NULL) {
                        parent_is_tracer = true;
                    }
                }
            }

            /* Detach if parent is readonlybox binary OR if parent is our tracer
             * (judge child that will exec rbox-wrap). All other processes
             * should continue to be traced so their execves get validated */
            if (parent_is_readonlybox || parent_is_tracer) {
                DEBUG_PRINT("PARENT: detaching child %d (parent_is_readonlybox=%d, parent_is_tracer=%d)\n",
                          (int)child_pid, parent_is_readonlybox, parent_is_tracer);
                ptrace(PTRACE_DETACH, (pid_t)child_pid, 0, 0);
                /* Also remove process state for the detached child */
                syscall_remove_process_state((pid_t)child_pid);
            } else {
                DEBUG_PRINT("PARENT: pid=%d (%s) fork/clone, resuming child %d\n", pid, parent_exe, (int)child_pid);
                /* Set options on child for tracing */
                if (ptrace(PTRACE_SETOPTIONS, (pid_t)child_pid, 0,
                           PTRACE_O_TRACESYSGOOD |
                           PTRACE_O_TRACEEXEC |
                           PTRACE_O_TRACECLONE |
                           PTRACE_O_TRACEFORK |
                           PTRACE_O_TRACEVFORK) < 0) {
                    DEBUG_PRINT("PARENT: child %d SETOPTIONS failed: %s\n", (int)child_pid, strerror(errno));
                }
                /* Resume child - it will stop at next syscall */
                if (ptrace(PTRACE_SYSCALL, (pid_t)child_pid, 0, 0) < 0) {
                    DEBUG_PRINT("PARENT: child %d already exited: %s\n", (int)child_pid, strerror(errno));
                }
            }
            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
                DEBUG_PRINT("PARENT: pid=%d SYSCALL failed after fork handling: %s\n", pid, strerror(errno));
            }
            continue;
        }

        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == (SIGTRAP | 0x80)) {
                if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
                    perror("ptrace(GETREGS)");
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
                    continue;
                }

                ProcessState *state = syscall_get_process_state(pid);
                if (!state) {
                    /* Process table full - detach and block to prevent untracked execves */
                    fprintf(stderr, "%s: CRITICAL: Process table full, detaching from pid %d - execve will not be validated!\n", g_progname, pid);
                    syslog(LOG_CRIT, "readonlybox-ptrace: CRITICAL: Process table full, detaching from pid %d - execve will not be validated!", pid);
                    ptrace(PTRACE_DETACH, pid, 0, 0);
                    continue;
                }

                if (state->detached) {
                    continue;
                }

                if (!state->in_execve) {
                    syscall_handle_entry(pid, &regs, state);
                } else {
                    syscall_handle_exit(pid, &regs, state);
                }

                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                continue;
            }

            if (sig == SIGSTOP) {
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
            } else {
                ptrace(PTRACE_SYSCALL, pid, 0, sig);
            }
            continue;
        }
    }

    return 1;
}

int main(int argc, char *argv[]) {
    int opt;
    uid_t provided_uid = 0;
    const char *provided_cwd = NULL;
    char *provided_cmd_path = NULL;
    pid_t attach_pid = 0;  /* PID to attach to (0 = spawn new process) */
    int internal_screened = 0;  /* Flag: already screened (set after pkexec relaunch) */

    g_progname = argv[0];

    /* Disable core dumps to prevent sensitive data leakage when running with elevated privileges.
     * This must be done early, before any potentially dangerous operations. */
    prctl(PR_SET_DUMPABLE, 0);

    /* Initialize syslog for critical error logging (process table full, etc.) */
    openlog("readonlybox-ptrace", LOG_PID, LOG_USER);

    /* Register cleanup function for flagged env names and syslog */
    atexit(cleanup_global_resources);

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"uid", required_argument, 0, 'u'},
        {"cwd", required_argument, 0, 'c'},
        {"cmd", required_argument, 0, 'm'},
        {"attach", required_argument, 0, 'p'},
        {"keep-env", no_argument, 0, 'k'},
        {"env", required_argument, 0, 'e'},
        /* Option to explicitly clean the environment */
        {"clean-env", no_argument, 0, 257},
        /* Hidden internal flag: set after pkexec relaunch to skip re-screening */
        {"internal-screened", no_argument, 0, 256},
        /* Hidden option: restore environment from file passed by relaunch_with_pkexec */
        {"env-file", required_argument, 0, 258},
        /* Socket path options */
        {"system-socket", no_argument, 0, 259},
        {"user-socket", no_argument, 0, 260},
        /* Sandbox options */
        {"memory-limit", required_argument, 0, 261},
        {"landlock-paths", required_argument, 0, 262},
        {"hard-allow", required_argument, 0, 262},
        {"hard-deny", required_argument, 0, 265},
        {"no-network", no_argument, 0, 263},
        /* Skip pkexec even if no ptrace capability */
        {"no-pkexec", no_argument, 0, 264},
        {0, 0, 0, 0}
    };

    /* Parse options until we see -- or a non-option argument */
    /* Use + to stop at first non-option (for -- separator support) */
    /* Skip "wrap" keyword and handle --no-pkexec if present */
    if (argc > 1 && strcmp(argv[1], "wrap") == 0) {
        /* If next arg is --no-pkexec, set the flag and shift args */
        if (argc > 2 && strcmp(argv[2], "--no-pkexec") == 0) {
            g_skip_pkexec = true;
            /* Shift remaining args left to overwrite --no-pkexec */
            for (int i = 2; i < argc; i++) {
                argv[i] = argv[i + 1];
            }
            argc--;
        }
        /* Shift to skip "wrap" */
        for (int i = 1; i < argc; i++) {
            argv[i] = argv[i + 1];
        }
        argc--;
        optind = 1;
    }

    while ((opt = getopt_long(argc, argv, "+hvu:c:m:p:ke:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage();
                return 0;
            case 'v':
                printf("%s version 1.0.0\n", g_progname);
                return 0;
            case 'u':
                provided_uid = atoi(optarg);
                break;
            case 'c':
                provided_cwd = optarg;
                break;
            case 'm':
                provided_cmd_path = optarg;
                break;
            case 'p':
                attach_pid = atoi(optarg);
                if (attach_pid <= 0) {
                    fprintf(stderr, "%s: Invalid PID: %s\n", g_progname, optarg);
                    return 1;
                }
                break;
            case 'k':
                g_keep_env = true;
                break;
            case 'e': {
                char **new_env = realloc(g_extra_env, (g_extra_env_count + 1) * sizeof(char *));
                if (!new_env) {
                    fprintf(stderr, "Failed to allocate memory for --env\n");
                    return 1;
                }
                g_extra_env = new_env;
                g_extra_env[g_extra_env_count++] = strdup(optarg);
                break;
            }
            case 256:
                /* Hidden internal flag: already screened after pkexec relaunch */
                internal_screened = 1;
                break;
            case 257:
                /* Explicit request to clean environment */
                privilege_set_clean_env(true);
                g_keep_env = false;
                break;
            case 258: {
                /* Hidden option: restore environment from file passed by relaunch_with_pkexec.
                 * The file is in /dev/shm (memory-backed tmpfs) and is unlinked after reading. */
                FILE *f = fopen(optarg, "r");
                if (!f) {
                    fprintf(stderr, "Error: cannot open environment file %s: %s\n", optarg, strerror(errno));
                    return 1;
                }
                char *line = NULL;
                size_t line_cap = 0;
                ssize_t line_len;
                while ((line_len = getline(&line, &line_cap, f)) != -1) {
                    if (line_len > 0 && line[line_len-1] == '\n') line[line_len-1] = '\0';
                    if (line[0] == '\0') continue;
                    /* putenv expects the string to remain valid; strdup copies it */
                    char *env_entry = strdup(line);
                    if (!env_entry) {
                        fprintf(stderr, "Error: out of memory restoring environment\n");
                        free(line);
                        fclose(f);
                        unlink(optarg);
                        return 1;
                    }
                    if (putenv(env_entry) != 0) {
                        fprintf(stderr, "Warning: putenv failed for '%s'\n", env_entry);
                        free(env_entry);
                    }
                    /* Note: putenv does not copy the string on success,
                     * so we must not free env_entry. The string remains in environment. */
                }
                free(line);
                fclose(f);
                unlink(optarg);  /* Clean up the temp file */
                break;
            }
            case 259:
                /* Force system socket path */
                validation_set_system_mode();
                break;
            case 260:
                /* Use user socket (XDG_RUNTIME_DIR) */
                validation_set_user_mode();
                break;
            case 261:
                /* Set memory limit via environment variable */
                if (setenv("READONLYBOX_MEMORY_LIMIT", optarg, 1) != 0) {
                    fprintf(stderr, "%s: Warning: failed to set READONLYBOX_MEMORY_LIMIT\n", g_progname);
                }
                break;
            case 262:
                /* Set landlock paths via environment variable (legacy) or hard-allow */
                if (setenv("READONLYBOX_HARD_ALLOW", optarg, 1) != 0) {
                    fprintf(stderr, "%s: Warning: failed to set READONLYBOX_HARD_ALLOW\n", g_progname);
                }
                break;
            case 263:
                /* Block network access via environment variable */
                if (setenv("READONLYBOX_NO_NETWORK", "1", 1) != 0) {
                    fprintf(stderr, "%s: Warning: failed to set READONLYBOX_NO_NETWORK\n", g_progname);
                }
                break;
            case 264:
                /* Skip pkexec even if no ptrace capability */
                g_skip_pkexec = true;
                break;
            case 265:
                /* Set hard deny paths via environment variable */
                if (setenv("READONLYBOX_HARD_DENY", optarg, 1) != 0) {
                    fprintf(stderr, "%s: Warning: failed to set READONLYBOX_HARD_DENY\n", g_progname);
                }
                break;
            default:
                print_usage();
                return 1;
        }
    }

    privilege_init(provided_uid, provided_cwd);

    /* If attaching to a process, no command should be provided */
    int cmd_start = optind;
    if (attach_pid > 0) {
        /* Skip "wrap" keyword if present */
        if (cmd_start < argc && strcmp(argv[cmd_start], "wrap") == 0) {
            cmd_start++;
        }
        if (cmd_start < argc) {
            fprintf(stderr, "%s: Error: Cannot specify both -p/--attach and a command\n", g_progname);
            print_usage();
            return 1;
        }
        /* No command provided - this is fine for attach mode, continue without error */
    } else {
        if (cmd_start < argc && strcmp(argv[cmd_start], "wrap") == 0) {
            cmd_start++;
        }

        if (cmd_start >= argc) {
            print_usage();
            return 1;
        }
    }

    /* Initialize cmd_path only for spawn mode */
    char *cmd_path = NULL;
    if (attach_pid == 0) {
        /* Spawn mode - resolve command path */
        if (provided_cmd_path) {
            cmd_path = strdup(provided_cmd_path);
        } else {
            cmd_path = resolve_command_path(argv[cmd_start]);
        }

        if (!cmd_path) {
            fprintf(stderr, "%s: Command not found: %s\n", g_progname, argv[cmd_start]);
            return 1;
        }
    }

    /* Validate Landlock paths before requesting auth.
     * This ensures paths are valid directories before pkexec prompt. */
    if (validate_landlock_paths() != 0) {
        return 1;
    }

    /* Screen environment for potential secrets before launching.
     * When g_keep_env is true: screen and unset only flagged variables.
     * When g_keep_env is false: screen and clear everything (legacy behavior).
     * Skip if internal flag is set AND we're running as root (after pkexec relaunch).
     * The flag is only set by the wrapper when it relaunches via pkexec. */
    if (internal_screened && geteuid() == 0) {
        /* Already screened in the first instance; skip to avoid double prompt */
    } else {
        env_screen();
    }

    if (!g_skip_pkexec && attach_pid == 0 && provided_uid == 0 && !privilege_has_ptrace_capability()) {
        fprintf(stderr, "%s: Requesting elevated privileges...\n", g_progname);
        pkexec_set_progname(g_progname);
        int ret = pkexec_launch(argc, argv, cmd_path);
        free(cmd_path);
        return ret;
    }

    if (validation_init() < 0) {
        fprintf(stderr, "%s: Failed to initialize validation\n", g_progname);
        free(cmd_path);
        return 1;
    }

    if (syscall_handler_init() < 0) {
        fprintf(stderr, "%s: Failed to initialize syscall handler\n", g_progname);
        validation_shutdown();
        free(cmd_path);
        return 1;
    }

    /* Check if we're attaching to a running process or spawning new */
    if (attach_pid > 0) {
        /* Attach to existing process */
        fprintf(stderr, "%s: Attaching to process %d\n", g_progname, attach_pid);

        /* Send PTRACE_ATTACH to the target process */
        if (ptrace(PTRACE_ATTACH, attach_pid, NULL, NULL) < 0) {
            if (errno == EPERM) {
                fprintf(stderr, "%s: ptrace attach denied for pid %d.\n", g_progname, attach_pid);
                fprintf(stderr, "This may be due to Yama LSM (/proc/sys/kernel/yama/ptrace_scope).\n");
                fprintf(stderr, "Try: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n");
                fprintf(stderr, "Or run as root.\n");
            } else {
                perror("ptrace(ATTACH)");
            }
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }
        
        /* Wait for the process to stop */
        int status;
        if (waitpid(attach_pid, &status, 0) < 0) {
            perror("waitpid");
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }
        
        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "%s: Process %d did not stop as expected\n", g_progname, attach_pid);
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }
        
        /* Set trace options on the attached process */
        if (ptrace(PTRACE_SETOPTIONS, attach_pid, 0,
                   PTRACE_O_TRACESYSGOOD |
                   PTRACE_O_TRACEEXEC |
                   PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK) < 0) {
            perror("ptrace(SETOPTIONS)");
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }
        
        /* Resume the process with PTRACE_SYSCALL to trap syscall entries/exits */
        if (ptrace(PTRACE_SYSCALL, attach_pid, NULL, NULL) < 0) {
            perror("ptrace(SYSCALL)");
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }
        
        /* For attached processes, we DON'T set as main process.
         * This ensures the first execve from the attached process
         * goes through validation (not automatically allowed).
         * This is the expected behavior for Option A/D.
         */
        /* Note: We skip syscall_set_main_process(attach_pid) intentionally */
        
        int exit_code = trace_process(attach_pid);

        free(cmd_path);
        syscall_handler_cleanup();
        validation_shutdown();

        return exit_code;
    }

    /* Original spawn logic */
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        syscall_handler_cleanup();
        validation_shutdown();
        free(cmd_path);
        return 1;
    }

    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(TRACEME)");
            _exit(1);
        }
        raise(SIGSTOP);
        /* Apply sandbox restrictions before dropping privileges.
         * This must be done while we still have CAP_SYS_ADMIN.
         * Landlock and seccomp restrictions will be inherited by the execved process.
         * Configuration is read from environment variables set by CLI options. */
        apply_sandboxing();
        drop_privileges_and_apply_env();
        char cmd_path_copy[PATH_MAX];
        strncpy(cmd_path_copy, cmd_path, PATH_MAX - 1);
        cmd_path_copy[PATH_MAX - 1] = '\0';
        execv(cmd_path_copy, &argv[cmd_start]);
        fprintf(stderr, "%s: execv failed for %s: %s\n", g_progname, cmd_path_copy, strerror(errno));
        _exit(1);
    }

    syscall_set_main_process(child);
    int exit_code = trace_process(child);

    free(cmd_path);
    syscall_handler_cleanup();
    validation_shutdown();

    return exit_code;
}

/* Resolve command to full path using PATH */
static char *resolve_command_path(const char *cmd) {
    if (strchr(cmd, '/')) {
        char *resolved = malloc(PATH_MAX);
        if (!resolved) return NULL;
        if (realpath(cmd, resolved)) {
            return resolved;
        }
        free(resolved);
        return NULL;
    }

    const char *path_env = getenv("PATH");
    if (!path_env) {
        path_env = "/usr/local/bin:/usr/bin:/bin";
    }

    char *path_copy = strdup(path_env);
    if (!path_copy) return NULL;

    char *saveptr;
    char *dir = strtok_r(path_copy, ":", &saveptr);

    while (dir) {
        char *full_path = malloc(PATH_MAX);
        if (!full_path) {
            free(path_copy);
            return NULL;
        }
        snprintf(full_path, PATH_MAX, "%s/%s", dir, cmd);
        if (access(full_path, X_OK) == 0) {
            free(path_copy);
            return full_path;
        }
        free(full_path);
        dir = strtok_r(NULL, ":", &saveptr);
    }

    free(path_copy);
    return NULL;
}

