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
#include <sys/socket.h>
#include <sys/un.h>
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
#include "progname.h"
#include "sandbox.h"
#include "rule_engine.h"

#include "env_screener.h"
#include "compat_strl.h"

/* Debug file pointer - defined here, used by DEBUG_PRINT in all files */
FILE *g_debug_file = NULL;
int g_verbose_level = 0;
static const char *g_custom_log_file = NULL;

void debug_init(void) {
    if (g_debug_file) return;
    const char *log_path = g_custom_log_file ? g_custom_log_file : "/tmp/readonlybox-ptrace.log";
    int fd = open(log_path, O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0600);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
            close(fd);
            g_debug_file = stderr;
            return;
        }
        g_debug_file = fdopen(fd, "a");
    }
    if (!g_debug_file && fd >= 0) {
        close(fd);
        g_debug_file = stderr;
    } else if (!g_debug_file) {
        g_debug_file = stderr;
    }
}

static bool g_keep_env = true;  /* Keep environment by default */
static bool g_skip_pkexec = false;  /* Skip pkexec even if no ptrace capability */
static bool user_soft_policy_requested = false;  /* User requested soft policy via --soft-allow/--soft-deny */
bool g_soft_debug = false;  /* Enable soft policy debug logging */
static char **g_extra_env = NULL;
static int g_extra_env_count = 0;
static char *g_env_socket = NULL;  /* Abstract socket name for environment passing */

/* Forward declarations */
static char *resolve_command_path(const char *cmd);

/* External rulesets - defined in soft_ruleset_access.c */
extern soft_ruleset_t *user_fs_rules;
extern soft_ruleset_t *get_effective_fs_rules(void);

/* Soft mode enum - maps to ruleset access flags */
typedef enum {
    SOFT_MODE_DENY = 0,
    SOFT_MODE_RO,
    SOFT_MODE_RX,
    SOFT_MODE_RW,
    SOFT_MODE_RWX
} soft_mode_t;

/* Restore environment from an abstract Unix socket.
 * Returns 0 on success, -1 on error (caller may then proceed with a clean env). */
static int restore_environment_from_socket(const char *sock_name) {
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif
#define ENV_RESTORE_MAX (1024 * 1024)

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    addr.sun_path[0] = '\0';
    size_t name_len = strlen(sock_name);
    if (name_len + 1 > UNIX_PATH_MAX) {
        LOG_ERROR("Socket name too long");
        return -1;
    }
    memcpy(addr.sun_path + 1, sock_name, name_len + 1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERRNO("socket");
        return -1;
    }

    /* Timeout after 5 seconds to avoid hanging */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;
    if (connect(fd, (struct sockaddr*)&addr, addr_len) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
            LOG_WARN("Timeout connecting to environment socket, using clean environment");
        } else {
            LOG_ERRNO("connect to environment socket");
        }
        close(fd);
        return -1;
    }

    /* Read environment data with size limit (1 MB) */
    char *buf = malloc(ENV_RESTORE_MAX);
    if (!buf) {
        LOG_ERROR("malloc failed");
        close(fd);
        return -1;
    }

    size_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf + total, ENV_RESTORE_MAX - total - 1)) > 0) {
        total += n;
        if (total >= ENV_RESTORE_MAX - 1) {
            LOG_WARN("Environment too large, truncated");
            break;
        }
    }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_ERRNO("read from socket");
        free(buf);
        close(fd);
        return -1;
    }
    close(fd);
    buf[total] = '\0';

    /* Parse lines: each line is "NAME=value", terminated by an empty line */
    char *line = buf;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next = '\0';
        if (line[0] != '\0') {
            /* Validate line format: must contain '=' for a valid env var */
            char *eq = strchr(line, '=');
            if (!eq) {
                LOG_WARN("Ignoring malformed env line (no '='): '%s'", line);
            } else {
                /* Use setenv which copies the string, avoiding putenv issues */
                *eq = '\0';
                if (setenv(line, eq + 1, 1) != 0) {
                    LOG_WARN("setenv failed for '%s'", line);
                }
                *eq = '=';
            }
        }
        line = next ? next + 1 : NULL;
    }

    free(buf);
    return 0;
}

/* Cleanup function for atexit */
static void cleanup_global_resources(void) {
    /* Clear flagged env storage */
    env_clear_flagged();

    /* Free extra env storage */
    for (int i = 0; i < g_extra_env_count; i++) {
        free(g_extra_env[i]);
    }
    free(g_extra_env);
    g_extra_env = NULL;
    g_extra_env_count = 0;

    /* Close syslog */
    closelog();
}

static void print_usage(void) {
    fprintf(stderr, "Usage: ./readonlybox-ptrace wrap <command> [args...]\n");
    fprintf(stderr, "       ./readonlybox-ptrace [options] -- <command> [args...]\n");
    fprintf(stderr, "       ./readonlybox-ptrace -p <pid> [options] -- <command> [args...]\n");
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
    fprintf(stderr, "\n");
    fprintf(stderr, "Hard Policy (Landlock filesystem restrictions):\n");
    fprintf(stderr, "  --hard-allow <path:mode[,path:mode...]>\n");
    fprintf(stderr, "                       Allow access to a directory with the specified mode.\n");
    fprintf(stderr, "                       Modes: ro (read-only), rx (read+execute), rw (read+write),\n");
    fprintf(stderr, "                              rwx (full access, including special files).\n");
    fprintf(stderr, "                       This is a **default-deny** policy: only explicitly allowed\n");
    fprintf(stderr, "                       paths and operations are permitted; everything else is\n");
    fprintf(stderr, "                       blocked. Multiple entries can be comma-separated.\n");
    fprintf(stderr, "                       Example: --hard-allow /tmp:rw,/usr/bin:rx\n");
    fprintf(stderr, "  --hard-deny <path[,path...]>\n");
    fprintf(stderr, "                       Explicitly deny access to a directory (takes precedence\n");
    fprintf(stderr, "                       over --hard-allow if paths overlap).\n");
    fprintf(stderr, "  --no-network         Block network access using seccomp (default-allow for all\n");
    fprintf(stderr, "                       other syscalls)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Soft Policy (syscall interception - filesystem access checks):\n");
    fprintf(stderr, "  Default: DENY (fail-closed). Built-in rules (longest-prefix overridable):\n");
    fprintf(stderr, "    Read-only (RO):    /, /etc, /proc, /sys, /dev, /var, /run\n");
    fprintf(stderr, "    Read+Execute (RX): /usr, /lib, /lib64\n");
    fprintf(stderr, "    Read+Write (RW):   /tmp, /dev/shm, /var/tmp\n");
    fprintf(stderr, "    Denied (blocked):  /home, /root, /var/log, /var/spool, /run/user\n");
    fprintf(stderr, "                       plus sensitive files: /etc/shadow, /etc/gshadow,\n");
    fprintf(stderr, "                       /etc/sudoers, /etc/securetty, SSH private keys\n");
    fprintf(stderr, "  Current user's home, runtime dir, mail spool are automatically allowed.\n");
    fprintf(stderr, "  Add custom rules (override built-ins):\n");
    fprintf(stderr, "    --soft-allow <path>[:ro|rx|rw|rwx]   (default mode: ro)\n");
    fprintf(stderr, "    --soft-deny <path>                   (blocks all access)\n");
    fprintf(stderr, "  Example: --soft-allow /home/user:rwx --soft-deny /home/user/secret\n");
    fprintf(stderr, "  --soft-debug         Enable soft policy debug output\n");
    fprintf(stderr, "  --log-file <path>    Write debug output to specified file (default: /tmp/readonlybox-ptrace.log)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -h, --help           Show this help\n");
    fprintf(stderr, "  -v                   Enable verbose output (use -vv or -vvv for more verbosity)\n");
    fprintf(stderr, "  -V, --version        Show version\n");
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
                LOG_WARN("failed to set env var %s", g_extra_env[i]);
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
               PTRACE_O_TRACEVFORK |
               PTRACE_O_EXITKILL) < 0) {
        perror("ptrace(SETOPTIONS)");
        kill(pid, SIGKILL);
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
                strlcpy(parent_exe, path, sizeof(parent_exe));
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
            } else {
                DEBUG_PRINT("PARENT: pid=%d (%s) fork/clone, resuming child %d\n", pid, parent_exe, (int)child_pid);
                /* Set options on child for tracing */
                long setopts_ret = ptrace(PTRACE_SETOPTIONS, (pid_t)child_pid, 0,
                                          PTRACE_O_TRACESYSGOOD |
                                          PTRACE_O_TRACEEXEC |
                                          PTRACE_O_TRACECLONE |
                                          PTRACE_O_TRACEFORK |
                                          PTRACE_O_TRACEVFORK |
                                          PTRACE_O_EXITKILL);
                if (setopts_ret < 0) {
                    if (errno == ESRCH) {
                        /* Child already exited before we could set options - this is a race,
                         * not an error. Clean up process state since PID is no longer valid. */
                        DEBUG_PRINT("PARENT: child %d already exited (race), skipping options\n", (int)child_pid);
                        syscall_remove_process_state((pid_t)child_pid);
                    } else {
                        DEBUG_PRINT("PARENT: child %d SETOPTIONS failed: %s\n", (int)child_pid, strerror(errno));
                        /* Only kill if process still exists */
                        if (kill((pid_t)child_pid, 0) == 0) {
                            kill((pid_t)child_pid, SIGKILL);
                        }
                    }
                } else {
                    /* Resume child - it will stop at next syscall */
                    if (ptrace(PTRACE_SYSCALL, (pid_t)child_pid, 0, 0) < 0) {
                        DEBUG_PRINT("PARENT: child %d SYSCALL failed: %s\n", (int)child_pid, strerror(errno));
                    }
                }
            }
            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
                DEBUG_PRINT("PARENT: pid=%d SYSCALL failed after fork handling: %s\n", pid, strerror(errno));
            }
            continue;
        }

        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            ProcessState *state = syscall_get_process_state(pid);
            if (state) {
                char exe_path[PATH_MAX];
                char proc_link[64];
                snprintf(proc_link, sizeof(proc_link), "/proc/%d/exe", pid);
                ssize_t len = readlink(proc_link, exe_path, sizeof(exe_path) - 1);
                if (len > 0) {
                    exe_path[len] = '\0';
                    free(state->execve_pathname);
                    state->execve_pathname = strdup(exe_path);
                }
            }
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == (SIGTRAP | 0x80)) {
                if (GET_REGS(pid, &regs) < 0) {
                    perror("ptrace(GETREGS)");
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
                    continue;
                }

                ProcessState *state = syscall_get_process_state(pid);
                if (!state) {
                    /* Process table full - detaching to avoid tracer deadlock.
                     * WARNING: This is a fail-open scenario; the process will continue untraced. */
                    LOG_ERROR("Process table full, detaching from pid %d (process will run untraced)", pid);
                    syslog(LOG_CRIT, "readonlybox-ptrace: CRITICAL: Process table full, detaching from pid %d (process will run untraced)", pid);
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

            /* CRITICAL: Swallow SIGSTOP to prevent infinite stop-deliver loop.
             * Forwarding SIGSTOP causes the tracee to stop immediately again,
             * trapping the tracer in a loop and preventing execv. */
            if (sig == SIGSTOP) {
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
            } else {
                /* Forward all other signals (e.g., SIGINT, SIGTERM, SIGTSTP) */
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

    progname_set(argv[0]);

    /* Disable core dumps to prevent sensitive data leakage when running with elevated privileges.
     * This must be done early, before any potentially dangerous operations. */
    prctl(PR_SET_DUMPABLE, 0);

    /* Initialize syslog for critical error logging (process table full, etc.) */
    openlog("readonlybox-ptrace", LOG_PID, LOG_USER);

    /* Register cleanup function for flagged env names and syslog */
    atexit(cleanup_global_resources);

    /* Initialize DFA before argument parsing - exit on failure */
    if (dfa_init() != 0) {
        fprintf(stderr, "%s: failed to initialize DFA\n", g_progname);
        exit(1);
    }

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
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
        /* Soft policy options */
        {"soft-allow", required_argument, 0, 266},
        {"soft-deny", required_argument, 0, 267},
        {"soft-debug", no_argument, 0, 268},
        /* Abstract socket for environment passing (used by pkexec helper) */
        {"env-socket", required_argument, 0, 269},
        /* Custom debug log file path */
        {"log-file", required_argument, 0, 270},
        {0, 0, 0, 0}
    };

    /* Parse options until we see -- or a non-option argument */
    /* Use + to stop at first non-option (for -- separator support) */
    while ((opt = getopt_long(argc, argv, "+hvu:c:m:p:ke:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage();
                return 0;
            case 'v':
                g_verbose_level++;
                break;
            case 'V':
                printf("%s version 1.0.0\n", g_progname);
                return 0;
            case 'u': {
                char *end;
                unsigned long uid = strtoul(optarg, &end, 10);
                if (end == optarg || *end != '\0') {
                    LOG_ERROR("Invalid UID: %s", optarg);
                    return 1;
                }
                provided_uid = (uid_t)uid;
                break;
            }
            case 'c':
                provided_cwd = optarg;
                break;
            case 'm':
                provided_cmd_path = optarg;
                break;
            case 'p': {
                char *endptr;
                errno = 0;
                long pid_val = strtol(optarg, &endptr, 10);
                if (endptr == optarg || *endptr != '\0' || errno == ERANGE || pid_val <= 0 || pid_val > INT_MAX) {
                    LOG_ERROR("Invalid PID: %s", optarg);
                    return 1;
                }
                attach_pid = (pid_t)pid_val;
                break;
            }
            case 'k':
                g_keep_env = true;
                break;
            case 'e': {
                char *env_val = strdup(optarg);
                if (!env_val) {
                    LOG_ERROR("Failed to allocate memory for --env value");
                    return 1;
                }

                char *eq = strchr(env_val, '=');
                if (!eq) {
                    LOG_ERROR("Invalid --env format: %s (must be KEY=VALUE)", optarg);
                    free(env_val);
                    return 1;
                }

                size_t key_len = eq - env_val;
                char key[key_len + 1];
                memcpy(key, env_val, key_len);
                key[key_len] = '\0';

                const char *blocked[] = {
                    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
                    "LD_ORIGIN_PATH", "LD_PRELOAD_SEC", "LD_DYNAMIC_WEAK",
                    NULL
                };
                bool is_blocked = false;
                for (int i = 0; blocked[i]; i++) {
                    if (strcmp(key, blocked[i]) == 0) {
                        is_blocked = true;
                        break;
                    }
                }

                if (is_blocked) {
                    LOG_ERROR("Refusing to set dangerous environment variable: %s", key);
                    free(env_val);
                    return 1;
                }

                char **new_env = realloc(g_extra_env, (g_extra_env_count + 1) * sizeof(char *));
                if (!new_env) {
                    LOG_ERROR("Failed to allocate memory for --env");
                    free(env_val);
                    return 1;
                }
                g_extra_env = new_env;
                g_extra_env[g_extra_env_count++] = env_val;
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
                    LOG_ERROR("cannot open environment file %s: %s", optarg, strerror(errno));
                    return 1;
                }
                char *line = NULL;
                size_t line_cap = 0;
                ssize_t line_len;
                while ((line_len = getline(&line, &line_cap, f)) != -1) {
                    if (line_len > 0 && line[line_len-1] == '\n') line[line_len-1] = '\0';
                    if (line[0] == '\0') continue;
                    char *eq = strchr(line, '=');
                    if (!eq) {
                        LOG_WARN("Malformed env line in file: %s", line);
                        continue;
                    }
                    *eq = '\0';
                    const char *key = line;
                    const char *val = eq + 1;
                    if (setenv(key, val, 1) != 0) {
                        LOG_WARN("setenv failed for '%s'", key);
                    }
                    *eq = '=';
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
                    LOG_WARN("failed to set READONLYBOX_MEMORY_LIMIT");
                }
                break;
            case 262:
                {
                    const char *existing = getenv("READONLYBOX_HARD_ALLOW");
                    if (existing && existing[0]) {
                        size_t new_len = strlen(existing) + 1 + strlen(optarg) + 1;
                        char *combined = malloc(new_len);
                        if (combined) {
                            snprintf(combined, new_len, "%s,%s", existing, optarg);
                            setenv("READONLYBOX_HARD_ALLOW", combined, 1);
                            free(combined);
                        }
                    } else {
                        setenv("READONLYBOX_HARD_ALLOW", optarg, 1);
                    }
                }
                break;
            case 263:
                /* Block network access via environment variable */
                if (setenv("READONLYBOX_NO_NETWORK", "1", 1) != 0) {
                    LOG_FATAL("Failed to set READONLYBOX_NO_NETWORK, cannot enforce network restriction");
                    return 1;
                }
                break;
            case 264:
                /* Skip pkexec even if no ptrace capability */
                g_skip_pkexec = true;
                break;
            case 265:
                /* Set hard deny paths via environment variable */
                if (setenv("READONLYBOX_HARD_DENY", optarg, 1) != 0) {
                    LOG_WARN("failed to set READONLYBOX_HARD_DENY");
                }
                break;
            case 266:
                user_soft_policy_requested = true;
                {
                    const char *existing = getenv("READONLYBOX_SOFT_ALLOW");
                    if (existing && existing[0]) {
                        size_t new_len = strlen(existing) + 1 + strlen(optarg) + 1;
                        char *combined = malloc(new_len);
                        if (combined) {
                            snprintf(combined, new_len, "%s,%s", existing, optarg);
                            setenv("READONLYBOX_SOFT_ALLOW", combined, 1);
                            free(combined);
                        }
                    } else {
                        setenv("READONLYBOX_SOFT_ALLOW", optarg, 1);
                    }
                }
                break;
            case 267:
                user_soft_policy_requested = true;
                {
                    const char *existing = getenv("READONLYBOX_SOFT_DENY");
                    if (existing && existing[0]) {
                        size_t new_len = strlen(existing) + 1 + strlen(optarg) + 1;
                        char *combined = malloc(new_len);
                        if (combined) {
                            snprintf(combined, new_len, "%s,%s", existing, optarg);
                            setenv("READONLYBOX_SOFT_DENY", combined, 1);
                            free(combined);
                        }
                    } else {
                        setenv("READONLYBOX_SOFT_DENY", optarg, 1);
                    }
                }
                break;
            case 268:
                /* Enable soft policy debug logging */
                g_soft_debug = true;
                if (setenv("READONLYBOX_SOFT_DEBUG", "1", 1) != 0) {
                    LOG_WARN("failed to set READONLYBOX_SOFT_DEBUG");
                }
                break;
            case 269:
                /* Abstract socket name for environment passing from pkexec helper */
                g_env_socket = optarg;
                break;
            case 270:
                /* Custom debug log file path */
                g_custom_log_file = optarg;
                break;
            default:
                print_usage();
                return 1;
        }
    }

    /* Restore environment from abstract socket if passed by pkexec helper.
     * This must happen before privilege_init() so the environment is available. */
    if (g_env_socket && geteuid() == 0) {
        restore_environment_from_socket(g_env_socket);
        /* Remove --env-socket and its argument from argv to hide from later processing */
        for (int i = 0; i < argc; i++) {
            if (i + 1 < argc && strcmp(argv[i], "--env-socket") == 0) {
                for (int j = i; j < argc - 2; j++) {
                    argv[j] = argv[j + 2];
                }
                argv[argc - 2] = NULL;
                argc -= 2;
                optind = (optind > i) ? optind - 2 : optind;
                break;
            }
        }
    }

    privilege_init(provided_uid, provided_cwd);

    if (g_verbose_level > 0) {
        fprintf(stderr, "logging to %s\n", g_custom_log_file ? g_custom_log_file : "/tmp/readonlybox-ptrace.log");
    }

    /* If attaching to a process, no command should be provided */
    int cmd_start = optind;
    /* Skip "--" separator if present (handles case where --env-socket was removed) */
    if (cmd_start < argc && strcmp(argv[cmd_start], "--") == 0) {
        cmd_start++;
    }
    if (attach_pid > 0) {
        /* Skip "wrap" keyword if present */
        if (cmd_start < argc && strcmp(argv[cmd_start], "wrap") == 0) {
            cmd_start++;
        }
        if (cmd_start < argc) {
            LOG_ERROR("Cannot specify both -p/--attach and a command");
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
            LOG_ERROR("Command not found: %s", argv[cmd_start]);
            return 1;
        }
    }

    /* Screen environment for potential secrets before launching.
     * When g_keep_env is true: screen and unset only flagged variables.
     * When g_keep_env is false: screen and clear everything (legacy behavior).
     * Skip if internal flag is set AND we're running as root (after pkexec relaunch).
     * The flag is only set by the wrapper when it relaunches via pkexec. */
    if (internal_screened && geteuid() == 0) {
        /* Already screened in the first instance; skip to avoid double prompt */
    } else {
        if (env_screen() < 0) {
            LOG_ERROR("Failed to screen environment");
            free(cmd_path);
            return 1;
        }
    }

    /* Initialize validation (socket and wrap paths) before checking pkexec */
    if (validation_init() < 0) {
        LOG_ERROR("Failed to initialize validation");
        free(cmd_path);
        return 1;
    }

    /* Validate that rbox-wrap works before attempting pkexec or tracing.
     * Skip if already validated after pkexec relaunch (internal_screened && root). */
    if (!(internal_screened && geteuid() == 0)) {
        if (validate_wrap_binary() < 0) {
            fprintf(stderr, "%s: rbox-wrap validation failed - cannot proceed\n", g_progname);
            free(cmd_path);
            return 1;
        }
    }

    if (!g_skip_pkexec && attach_pid == 0 && provided_uid == 0 && !privilege_has_ptrace_capability()) {
        char uid_str[32];
        snprintf(uid_str, sizeof(uid_str), "%d", getuid());
        setenv("READONLYBOX_ORIGINAL_UID", uid_str, 1);
        fprintf(stderr, "%s: Requesting elevated privileges...\n", g_progname);
        pkexec_set_progname(g_progname);
        int ret = pkexec_launch(argc, argv, cmd_path);
        free(cmd_path);
        return ret;
    }

    if (syscall_handler_init() < 0) {
        LOG_ERROR("Failed to initialize syscall handler");
        validation_shutdown();
        free(cmd_path);
        return 1;
    }

    /* Initialize global soft ruleset only if soft policy was requested */
    if (user_soft_policy_requested) {
        user_fs_rules = soft_ruleset_new();
        if (!user_fs_rules) {
            LOG_ERROR("Failed to create soft ruleset");
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }

        /* Note: Layers 0-1 are reserved for hard policy fallback (deny/allow).
         * Hard rules use PRECEDENCE mode to shadow soft rules.
         * Soft rules start at layer 2. */

        /* Layer 2: User rules - SPECIFICITY mode (longest match wins) */
        soft_ruleset_set_layer_type(user_fs_rules, 2, LAYER_SPECIFICITY, 0);

        /* Layer 3: Builtin ALLOW rules - SPECIFICITY mode (fallback) */
        soft_ruleset_set_layer_type(user_fs_rules, 3, LAYER_SPECIFICITY, 0);

        /* Layer 4: Builtin DENY rules - PRECEDENCE mode (shadows lower layers) */
        soft_ruleset_set_layer_type(user_fs_rules, 4, LAYER_PRECEDENCE, 0);

        /* Parse and load user rules from environment */
        const char *allow_env = getenv("READONLYBOX_SOFT_ALLOW");
        const char *deny_env = getenv("READONLYBOX_SOFT_DENY");

        if (allow_env && *allow_env) {
            char *env_copy = strdup(allow_env);
            if (env_copy) {
                char *saveptr = NULL;
                char *token = strtok_r(env_copy, ",", &saveptr);
                while (token) {
                    while (*token == ' ' || *token == '\t') token++;
                    size_t len = strlen(token);
                    while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t')) {
                        len--;
                        token[len] = '\0';
                    }
                    if (len > 0) {
                        soft_mode_t mode = SOFT_MODE_RO;
                        char *path = token;
                        char *colon = strchr(token, ':');
                        if (colon) {
                            *colon = '\0';
                            if (strcmp(colon + 1, "ro") == 0 || strcmp(colon + 1, "r") == 0) mode = SOFT_MODE_RO;
                            else if (strcmp(colon + 1, "rx") == 0) mode = SOFT_MODE_RX;
                            else if (strcmp(colon + 1, "rw") == 0 || strcmp(colon + 1, "rwx") == 0) mode = SOFT_MODE_RW;
                        }
                        size_t path_len = strlen(path);
                        while (path_len > 1 && path[path_len - 1] == '/') {
                            path_len--;
                        }
                        path[path_len] = '\0';

                        char recursive_path[PATH_MAX];
                        if (path_len == 1 && path[0] == '/') {
                            snprintf(recursive_path, sizeof(recursive_path), "/...");
                        } else {
                            snprintf(recursive_path, sizeof(recursive_path), "%.*s/...", (int)path_len, path);
                        }

                        uint32_t access = 0;
                        switch (mode) {
                            case SOFT_MODE_RO: access = SOFT_ACCESS_READ; break;
                            case SOFT_MODE_RX: access = SOFT_ACCESS_READ | SOFT_ACCESS_EXEC; break;
                            case SOFT_MODE_RW: access = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE; break;
                            case SOFT_MODE_RWX: access = SOFT_ACCESS_ALL; break;
                            default: access = 0; break;
                        }
                        soft_ruleset_add_rule_at_layer(user_fs_rules, 2, recursive_path, access,
                                SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
                    }
                    token = strtok_r(NULL, ",", &saveptr);
                }
                free(env_copy);
            }
        }

        if (deny_env && *deny_env) {
            char *env_copy = strdup(deny_env);
            if (env_copy) {
                char *saveptr = NULL;
                char *token = strtok_r(env_copy, ",", &saveptr);
                while (token) {
                    while (*token == ' ' || *token == '\t') token++;
                    size_t len = strlen(token);
                    while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t')) {
                        len--;
                        token[len] = '\0';
                    }
                    if (len > 0) {
                        char *path = token;
                        size_t path_len = strlen(path);
                        while (path_len > 1 && path[path_len - 1] == '/') {
                            path_len--;
                        }
                        path[path_len] = '\0';

                        char recursive_path[PATH_MAX];
                        if (path_len == 1 && path[0] == '/') {
                            snprintf(recursive_path, sizeof(recursive_path), "/...");
                        } else {
                            snprintf(recursive_path, sizeof(recursive_path), "%.*s/...", (int)path_len, path);
                        }

                        soft_ruleset_add_rule_at_layer(user_fs_rules, 2, recursive_path, SOFT_ACCESS_DENY,
                                SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
                    }
                    token = strtok_r(NULL, ",", &saveptr);
                }
                free(env_copy);
            }
        }

        /* Add current user home directory rules at layer 0 */
        if (getuid() != 0) {
            const char *user = getenv("USER");
            if (!user) {
                struct passwd *pw = getpwuid(getuid());
                user = pw ? pw->pw_name : NULL;
            }
            if (user) {
                char path[PATH_MAX];
                snprintf(path, sizeof(path), "/home/%s", user);
                soft_ruleset_add_rule_at_layer(user_fs_rules, 2, path,
                        SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC,
                        SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);

                snprintf(path, sizeof(path), "/run/user/%d", getuid());
                soft_ruleset_add_rule_at_layer(user_fs_rules, 2, path,
                        SOFT_ACCESS_READ | SOFT_ACCESS_WRITE,
                        SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
            }
        }

        /* Add builtin ALLOW rules at layer 1 */
        static const struct {
            const char *path;
            uint32_t access;
        } builtin_allow[] = {
            { "/",                 SOFT_ACCESS_READ },
            { "/usr",              SOFT_ACCESS_READ | SOFT_ACCESS_EXEC },
            { "/lib",              SOFT_ACCESS_READ | SOFT_ACCESS_EXEC },
            { "/lib64",            SOFT_ACCESS_READ | SOFT_ACCESS_EXEC },
            { "/usr/lib",          SOFT_ACCESS_READ | SOFT_ACCESS_EXEC },
            { "/usr/local/lib",    SOFT_ACCESS_READ | SOFT_ACCESS_EXEC },
            { "/etc",              SOFT_ACCESS_READ },
            { "/proc",             SOFT_ACCESS_READ },
            { "/sys",              SOFT_ACCESS_READ },
            { "/dev",              SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
            { "/dev/pts",          SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
            { "/dev/tty",          SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
            { "/dev/null",         SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
            { "/dev/shm",          SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
            { "/tmp",              SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
            { "/var/tmp",          SOFT_ACCESS_READ | SOFT_ACCESS_WRITE },
            { "/var",              SOFT_ACCESS_READ },
            { "/run",              SOFT_ACCESS_READ },
        };
        for (size_t i = 0; i < sizeof(builtin_allow) / sizeof(builtin_allow[0]); i++) {
            char recursive_path[PATH_MAX];
            snprintf(recursive_path, sizeof(recursive_path), "%s/...", builtin_allow[i].path);
            soft_ruleset_add_rule_at_layer(user_fs_rules, 3, recursive_path, builtin_allow[i].access,
                    SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
        }

        /* Add builtin DENY rules at layer 2 */
        static const char *builtin_deny[] = {
            "/home",
            "/root",
            "/var/log",
            "/var/spool",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/securetty",
            "/etc/sudoers",
            "/etc/ssh/ssh_host_rsa_key",
            "/etc/ssh/ssh_host_ecdsa_key",
            "/etc/ssh/ssh_host_ed25519_key",
            "/run/user",
        };
        for (size_t i = 0; i < sizeof(builtin_deny) / sizeof(builtin_deny[0]); i++) {
            char recursive_path[PATH_MAX];
            snprintf(recursive_path, sizeof(recursive_path), "%s/...", builtin_deny[i]);
            soft_ruleset_add_rule_at_layer(user_fs_rules, 4, recursive_path, SOFT_ACCESS_DENY,
                    SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
        }
    }

    unsetenv("READONLYBOX_SOFT_ALLOW");
    unsetenv("READONLYBOX_SOFT_DENY");
    unsetenv("READONLYBOX_SOFT_DEBUG");

    soft_ruleset_t *effective_fs_rules = get_effective_fs_rules();
    if (effective_fs_rules) {
        if (soft_ruleset_compile(effective_fs_rules) != 0) {
            LOG_ERROR("Failed to compile effective filesystem ruleset");
        }
        DEBUG_PRINT("MAIN: Effective filesystem policy active with %zu rules\n",
                soft_ruleset_rule_count(effective_fs_rules));
    }

    /* Check if we're attaching to a running process or spawning new */
    if (attach_pid > 0) {
        /* Attach to existing process */
        fprintf(stderr, "%s: Attaching to process %d\n", g_progname, attach_pid);

        if (getenv("READONLYBOX_HARD_ALLOW") || getenv("READONLYBOX_HARD_DENY") || getenv("READONLYBOX_NO_NETWORK")) {
            LOG_WARN("Sandboxing options (--hard-allow, --hard-deny, --no-network) are ignored in attach mode (-p). Only syscall interception is active.");
        }

        /* Send PTRACE_ATTACH to the target process */
        if (ptrace(PTRACE_ATTACH, attach_pid, NULL, NULL) < 0) {
            if (errno == EPERM) {
                LOG_ERROR("ptrace attach denied for pid %d", attach_pid);
                fprintf(stderr, "This may be due to Yama LSM (/proc/sys/kernel/yama/ptrace_scope).\n");
                fprintf(stderr, "Try: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n");
                fprintf(stderr, "Or run as root.\n");
            } else {
                LOG_ERRNO("ptrace(ATTACH)");
            }
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }

        /* Wait for the process to stop */
        int status;
        if (waitpid(attach_pid, &status, 0) < 0) {
            LOG_ERRNO("waitpid");
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }

        if (!WIFSTOPPED(status)) {
            LOG_ERROR("Process %d did not stop as expected", attach_pid);
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
                   PTRACE_O_TRACEVFORK |
                   PTRACE_O_EXITKILL) < 0) {
            LOG_ERRNO("ptrace(SETOPTIONS)");
            kill(attach_pid, SIGKILL);
            syscall_handler_cleanup();
            validation_shutdown();
            free(cmd_path);
            return 1;
        }

        /* Resume the process with PTRACE_SYSCALL to trap syscall entries/exits */
        if (ptrace(PTRACE_SYSCALL, attach_pid, NULL, NULL) < 0) {
            LOG_ERRNO("ptrace(SYSCALL)");
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

        /* CRITICAL: Resolve command path BEFORE applying sandbox restrictions.
         * Landlock's default-deny policy will block realpath() if the path
         * isn't explicitly allowed, causing immediate child exit. */
        char cmd_path_copy[PATH_MAX];
        if (realpath(cmd_path, cmd_path_copy) == NULL) {
            LOG_ERROR("realpath failed for %s: %s", cmd_path, strerror(errno));
            _exit(1);
        }

        /* Apply sandbox restrictions before dropping privileges.
         * Landlock and seccomp restrictions will be inherited by the execved process. */
        apply_sandboxing();
        drop_privileges_and_apply_env();

        unsetenv("READONLYBOX_SOFT_ALLOW");
        unsetenv("READONLYBOX_SOFT_DENY");
        unsetenv("READONLYBOX_SOFT_DEBUG");
        /* Replace the command name in argv with the resolved path */
        argv[cmd_start] = cmd_path_copy;
        /* Debug: log the command and full argv */
        DEBUG_PRINT("EXEC: about to exec '%s' with argv:\n", cmd_path_copy);
        for (int i = cmd_start; argv[i]; i++) {
            DEBUG_PRINT("  argv[%d] = '%s'\n", i, argv[i]);
        }
        DEBUG_PRINT("EXEC: ---\n");
        execv(cmd_path_copy, &argv[cmd_start]);
        LOG_ERROR("execv failed for %s: %s", cmd_path_copy, strerror(errno));
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
        char *resolved = calloc(1, PATH_MAX);
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
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
            char *resolved = realpath(full_path, NULL);
            free(full_path);
            if (resolved) {
                free(path_copy);
                return resolved;
            }
        }
        free(full_path);
        dir = strtok_r(NULL, ":", &saveptr);
    }

    free(path_copy);
    return NULL;
}
