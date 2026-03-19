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

#include "env_screener.h"

/* Structure to hold flagged environment variable with its score */
typedef struct {
    char *name;
    double score;
} FlaggedEnv;

/* Global storage for flagged env vars with scores (used by run_judge) */
static FlaggedEnv g_flagged_envs[256];
static int g_flagged_env_count = 0;

/* Forward declarations for judge execution */
static const char *get_readonlybox_path(void);
int run_judge(const char *command, const char *caller_info);

#ifdef DEBUG
static FILE *g_debug_file = NULL;

static void debug_init(void) {
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

static const char *g_progname = "readonlybox-ptrace";
static uid_t g_original_uid = 0;
static gid_t g_original_gid = 0;
static char g_original_cwd[4096] = ".";
static bool g_keep_env = true;  /* Keep environment by default */
static bool g_clean_env = false;  /* Only clear environment if explicitly requested */
static char **g_extra_env = NULL;
static int g_extra_env_count = 0;

/* Cleanup function for atexit */
static void cleanup_global_resources(void) {
    /* Free flagged env names */
    for (int i = 0; i < g_flagged_env_count && i < 256; i++) {
        if (g_flagged_envs[i].name) {
            free(g_flagged_envs[i].name);
            g_flagged_envs[i].name = NULL;
        }
    }
    g_flagged_env_count = 0;

    /* Free extra env strings from --env */
    for (int i = 0; i < g_extra_env_count; i++) {
        free(g_extra_env[i]);
        g_extra_env[i] = NULL;
    }
    free(g_extra_env);
    g_extra_env = NULL;
    g_extra_env_count = 0;

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
    fprintf(stderr, "  -h, --help           Show this help\n");
    fprintf(stderr, "  -v, --version        Show version\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "The -- separator is optional and separates options from the command.\n");
}

static bool have_ptrace_capability(void) {
    if (geteuid() == 0) {
        return true;
    }
    return false;
}

static void save_original_user(uid_t provided_uid, const char *provided_cwd) {
    if (provided_uid != 0) {
        g_original_uid = provided_uid;
        struct passwd *pw = getpwuid(g_original_uid);
        g_original_gid = pw ? pw->pw_gid : getgid();
    } else {
        g_original_uid = getuid();
        g_original_gid = getgid();
    }

    if (provided_cwd && provided_cwd[0]) {
        strncpy(g_original_cwd, provided_cwd, sizeof(g_original_cwd) - 1);
        g_original_cwd[sizeof(g_original_cwd) - 1] = '\0';
    } else {
        if (getcwd(g_original_cwd, sizeof(g_original_cwd)) == NULL) {
            strcpy(g_original_cwd, ".");
        }
    }
}

static void drop_privileges(void) {
    if (chdir(g_original_cwd) < 0) {
        perror("chdir");
    }

    /* Always drop privileges if we're running as root with a non-root original UID */
    if (geteuid() == 0 && g_original_uid != 0) {
        struct passwd *pw = getpwuid(g_original_uid);
        gid_t gid = pw ? pw->pw_gid : g_original_gid;
        const char *username = pw ? pw->pw_name : "nobody";
        const char *home = pw ? pw->pw_dir : "/";
        const char *shell = pw ? pw->pw_shell : "/bin/sh";

        if (initgroups(username, gid) < 0) {
            perror("initgroups");
        }
        if (setgid(gid) < 0) {
            perror("setgid");
        }
        if (setuid(g_original_uid) < 0) {
            perror("setuid");
        }
        if (geteuid() != g_original_uid) {
            fprintf(stderr, "ERROR: Failed to drop privileges\n");
            _exit(1);
        }

        /* Prevent gaining new privileges via execve (e.g., setuid binaries) */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            fprintf(stderr, "Warning: failed to set PR_SET_NO_NEW_PRIVS\n");
        }

        if (setenv("HOME", home, 1) != 0) {
            fprintf(stderr, "Warning: failed to set HOME\n");
        }
        if (setenv("USER", username, 1) != 0) {
            fprintf(stderr, "Warning: failed to set USER\n");
        }
        if (setenv("LOGNAME", username, 1) != 0) {
            fprintf(stderr, "Warning: failed to set LOGNAME\n");
        }
        if (setenv("SHELL", shell, 1) != 0) {
            fprintf(stderr, "Warning: failed to set SHELL\n");
        }
        unsetenv("PKEXEC_UID");
        unsetenv("PKEXEC_AGENT");
    }

    if (g_clean_env) {
        /* Clear all environment variables - only when explicitly requested.
         * This prevents LD_PRELOAD and other environment-based attacks.
         * Note: clearenv() is a GNU extension, available on Linux.
         * For other Unix-like systems, one would need to iterate over
         * environ and call unsetenv() for each variable. */
        if (clearenv() != 0) {
            fprintf(stderr, "Warning: clearenv() failed\n");
        }
    }

    /* Apply extra environment variables */
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

/* Helper to extract name from environ entry */
static void extract_env_name(const char *entry, char *name, size_t name_size) {
    const char *eq = strchr(entry, '=');
    if (eq) {
        size_t len = eq - entry;
        if (len >= name_size) len = name_size - 1;
        strncpy(name, entry, len);
        name[len] = '\0';
    } else {
        name[0] = '\0';
    }
}

/* Helper to extract value from environ entry */
static const char *extract_env_value(const char *entry) {
    const char *eq = strchr(entry, '=');
    return eq ? eq + 1 : "";
}

/* Screen environment using shellsplit module - ptrace client handles prompting */
static void screen_environment(void) {
    /* Check if stdin is a terminal - if not, auto-block high-confidence vars */
    int is_terminal = isatty(STDIN_FILENO);

    /* Dynamically grow indices buffer until we have enough space */
    int indices_capacity = 32;
    int *indices = malloc(indices_capacity * sizeof(int));
    if (!indices) {
        return;  /* Memory allocation failed - skip screening */
    }
    int flagged_count = 0;

    env_screener_status_t status;
    while ((status = env_screener_scan(
            indices,
            indices_capacity,
            &flagged_count,
            0.7,   /* posterior_threshold - 0.7 for high confidence */
            12     /* min_length */
            )) == ENV_SCREENER_BUFFER_TOO_SMALL) {
        /* Buffer too small - grow it */
        int *larger = realloc(indices, flagged_count * sizeof(int));
        if (!larger) {
            free(indices);
            return;  /* Memory allocation failed */
        }
        indices = larger;
        indices_capacity = flagged_count;
    }

    if (status != ENV_SCREENER_OK || flagged_count == 0) {
        free(indices);
        return;
    }

    /* Reset the flagged env names list - we'll add only allowed vars */
    for (int i = 0; i < g_flagged_env_count; i++) {
        if (g_flagged_envs[i].name) {
            free(g_flagged_envs[i].name);
            g_flagged_envs[i].name = NULL;
        }
    }
    g_flagged_env_count = 0;

    /* Prompt user for each flagged variable and only add allowed ones */
    for (int i = 0; i < flagged_count; i++) {
        extern char **environ;
        if (indices[i] < 0) continue;
        char *entry = environ[indices[i]];
        if (!entry) continue;

        char name[256];
        const char *value = extract_env_value(entry);
        extract_env_name(entry, name, sizeof(name));

        double score = env_screener_combined_score_name(name, value);

        /* Check if we have room for more flagged envs */
        if (g_flagged_env_count >= 256) {
            /* No more room - unset to block this var */
            unsetenv(name);
            fprintf(stderr, "   → Auto-blocked (capacity): %s\n", name);
            continue;
        }

        if (!is_terminal) {
            /* Non-interactive mode: auto-block high-confidence, allow others */
            if (score > 0.8) {
                fprintf(stderr, "   → Auto-blocked (non-interactive): %s\n", name);
            } else {
                /* Allow low-confidence vars by adding to list */
                g_flagged_envs[g_flagged_env_count].name = strdup(name);
                g_flagged_envs[g_flagged_env_count].score = score;
                g_flagged_env_count++;
            }
            continue;
        }

        /* Interactive mode - prompt user */
        if (score > 0.8) {
            fprintf(stderr, "\n⚠️  High-confidence secret detected:\n");
            fprintf(stderr, "   %s=*** (score: %.2f)\n", name, score);
        } else {
            fprintf(stderr, "\n⚠️  Potential secret detected:\n");
            fprintf(stderr, "   %s=*** (score: %.2f)\n", name, score);
        }

        fprintf(stderr, "   Pass this variable to the command? [y/N]: ");

        /* Read full line to avoid stdin residue issues */
        char *line = NULL;
        size_t line_cap = 0;
        ssize_t line_len = getline(&line, &line_cap, stdin);
        if (line_len > 0 && (line[0] == 'y' || line[0] == 'Y')) {
            /* User allowed this variable */
            g_flagged_envs[g_flagged_env_count].name = strdup(name);
            g_flagged_envs[g_flagged_env_count].score = score;
            g_flagged_env_count++;
        } else {
            /* User blocked this variable or invalid input */
            unsetenv(name);
            fprintf(stderr, "   → Blocked: %s\n", name);
        }
        free(line);
    }

    free(indices);
    fprintf(stderr, "\n✓ Environment screened\n");
}

static int relaunch_with_pkexec(int argc, char *argv[], const char *cmd_path) {
    uid_t original_uid = getuid();
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strcpy(cwd, ".");
    }

    /* Create a temporary file in /dev/shm (tmpfs - memory-backed filesystem).
     * This keeps the environment data in kernel memory, not on disk.
     * The file has a random name and will be cleaned up on reboot. */
    char env_file_template[] = "/dev/shm/readonlybox-env-XXXXXX";
    int env_fd = mkstemp(env_file_template);
    if (env_fd < 0) {
        /* Fallback to regular tmp if /dev/shm is not available */
        char tmp_template[] = "/tmp/readonlybox-env-XXXXXX";
        env_fd = mkstemp(tmp_template);
        if (env_fd < 0) {
            perror("mkstemp");
            return 1;
        }
        strcpy(env_file_template, tmp_template);
    }

    /* Write the screened environment to the temp file */
    extern char **environ;
    FILE *env_file = fdopen(env_fd, "w");
    if (!env_file) {
        close(env_fd);
        return 1;
    }
    for (char **e = environ; *e; e++) {
        fprintf(env_file, "%s\n", *e);
    }
    fclose(env_file);  /* also closes the fd */

    /* Allocate argv: pkexec + our options + args + NULL */
    /* Estimate: 6 pkexec/our options + argc + 1 */
    char **new_argv = malloc((argc + 10) * sizeof(char *));
    if (!new_argv) {
        unlink(env_file_template);
        return 1;
    }

    /* Track allocated strings for cleanup */
#define MAX_ALLOCATED 4
    char **allocated_strings = malloc(MAX_ALLOCATED * sizeof(char *));
    if (!allocated_strings) {
        free(new_argv);
        unlink(env_file_template);
        return 1;
    }
    int allocated_count = 0;

#define ADD_ALLOCATED(str) do { \
        if ((str) && allocated_count < MAX_ALLOCATED) { \
            allocated_strings[allocated_count++] = (str); \
        } \
    } while(0)

#define FREE_ALLOCATED() do { \
        for (int _i = 0; _i < allocated_count; _i++) { \
            free(allocated_strings[_i]); \
        } \
        free(allocated_strings); \
    } while(0)

    int idx = 0;
    new_argv[idx++] = "pkexec";
    new_argv[idx++] = "--disable-internal-agent";
    new_argv[idx++] = argv[0];  /* Our program's path */
    new_argv[idx++] = "--uid";
    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%d", original_uid);
    new_argv[idx] = strdup(uid_str);
    if (!new_argv[idx]) { FREE_ALLOCATED(); free(new_argv); unlink(env_file_template); return 1; }
    ADD_ALLOCATED(new_argv[idx]);
    idx++;
    new_argv[idx++] = "--cwd";
    new_argv[idx] = strdup(cwd);
    if (!new_argv[idx]) { FREE_ALLOCATED(); free(new_argv); unlink(env_file_template); return 1; }
    ADD_ALLOCATED(new_argv[idx]);
    idx++;
    new_argv[idx++] = "--cmd";
    new_argv[idx] = strdup(cmd_path);
    if (!new_argv[idx]) { FREE_ALLOCATED(); free(new_argv); unlink(env_file_template); return 1; }
    ADD_ALLOCATED(new_argv[idx]);
    idx++;

    /* Pass the environment file path so the child can restore the environment */
    new_argv[idx++] = "--env-file";
    new_argv[idx] = strdup(env_file_template);
    if (!new_argv[idx]) { FREE_ALLOCATED(); free(new_argv); unlink(env_file_template); return 1; }
    ADD_ALLOCATED(new_argv[idx]);
    idx++;

    /* Hidden internal flag to indicate we've already screened the environment */
    new_argv[idx++] = "--internal-screened";

    /* Add the actual command arguments (skip argv[0] which is our program). */
    for (int i = 1; i < argc; i++) {
        new_argv[idx++] = argv[i];
    }
    new_argv[idx] = NULL;

    /* Execute pkexec. The env file is in /dev/shm (memory-backed tmpfs).
     * The child (second instance) will read and unlink the file very early
     * after pkexec completes authentication. The file exists only during
     * the brief authentication window - no watchdog needed. */
    execve("/usr/bin/pkexec", new_argv, environ);

    /* If we get here, execve failed */
    fprintf(stderr, "\n%s: Failed to execute pkexec: %s\n", g_progname, strerror(errno));
    FREE_ALLOCATED();
    free(new_argv);
    unlink(env_file_template);
    return 1;
}

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
                g_clean_env = true;
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
                char line[16384];  /* enough for a single env var */
                while (fgets(line, sizeof(line), f)) {
                    size_t len = strlen(line);
                    if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
                    if (line[0] == '\0') continue;
                    /* putenv expects the string to remain valid; strdup copies it */
                    char *env_entry = strdup(line);
                    if (!env_entry) {
                        fprintf(stderr, "Error: out of memory restoring environment\n");
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
                fclose(f);
                unlink(optarg);  /* Clean up the temp file */
                break;
            }
            default:
                print_usage();
                return 1;
        }
    }

    save_original_user(provided_uid, provided_cwd);

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

    /* Screen environment for potential secrets before launching.
     * When g_keep_env is true: screen and unset only flagged variables.
     * When g_keep_env is false: screen and clear everything (legacy behavior).
     * Skip if internal flag is set AND we're running as root (after pkexec relaunch).
     * The flag is only set by the wrapper when it relaunches via pkexec. */
    if (internal_screened && geteuid() == 0) {
        /* Already screened in the first instance; skip to avoid double prompt */
    } else {
        screen_environment();
    }

    if (attach_pid == 0 && provided_uid == 0 && !have_ptrace_capability()) {
        fprintf(stderr, "%s: Requesting elevated privileges...\n", g_progname);
        int ret = relaunch_with_pkexec(argc, argv, cmd_path);
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
            perror("ptrace(ATTACH)");
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
        drop_privileges();
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

/* Run readonlybox --judge to get server decision
 * Returns: 0 = ALLOW, 9 = DENY, -1 = error
 */
int run_judge(const char *command, const char *caller_info) {
    int pipefd[2];
    pid_t pid;

    /* Dynamic buffer for server response - grows as needed */
    size_t cap = 4096;
    char *buffer = malloc(cap);
    if (!buffer) {
        return -1;
    }
    size_t bytes_read = 0;

    /* Clear any stale environment variables from previous decisions
     * This prevents stale values from being used if a later execve is
     * allowed by DFA (bypassing server call) */
    unsetenv("READONLYBOX_ENV_DECISIONS");
    unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

    /* Create pipe for reading output */
    if (pipe(pipefd) < 0) {
        free(buffer);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        free(buffer);
        return -1;
    }

    if (pid == 0) {
        /* Child process - will exec rbox-wrap for server decision */
        /* Note: We don't call PTRACE_DETACH here - the parent will handle detaching
         * this process after fork/clone events are detected */

        /* Child: exec readonlybox --bin --judge for binary protocol */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        /* Set caller info as environment variable for the server request */
        if (caller_info) {
            setenv("READONLYBOX_CALLER", caller_info, 1);
        }

        /* Set flagged env vars so server can make decisions about them */
        /* This must be set BEFORE exec so the Go server can read it */
        /* Format: NAME1:score1,NAME2:score2,... */
        if (g_flagged_env_count > 0) {
            /* 16KB buffer - enough for ~256 flagged vars with typical name lengths */
            char env_buf[16384] = {0};
            char *p = env_buf;
            size_t rem = sizeof(env_buf) - 1;
            int truncated = 0;

            for (int i = 0; i < g_flagged_env_count && rem > 1; i++) {
                if (g_flagged_envs[i].name) {
                    /* Use the actual score stored during screening */
                    double score = g_flagged_envs[i].score;

                    size_t len = strlen(g_flagged_envs[i].name);
                    /* Format: name:score (7 chars for :score + potential comma) */
                    size_t needed = len + 8;

                    if (rem >= needed) {
                        /* Format: name:score */
                        memcpy(p, g_flagged_envs[i].name, len);
                        p += len;
                        rem -= len;

                        /* Add score */
                        int n = snprintf(p, rem, ":%.2f", score);
                        if (n > 0 && (size_t)n < rem) {
                            p += n;
                            rem -= n;
                        }

                        if (rem > 1 && i < g_flagged_env_count - 1) {
                            *p++ = ',';
                            rem--;
                        }
                    } else {
                        truncated = 1;
                    }
                }
            }

            if (env_buf[0]) {
                setenv("READONLYBOX_FLAGGED_ENVS", env_buf, 1);
            }
            if (truncated) {
                fprintf(stderr, "Warning: READONLYBOX_FLAGGED_ENVS was truncated\n");
            }
        }

        /* Find rbox-wrap binary */
        const char *readonlybox_path = get_readonlybox_path();
        
        if (!readonlybox_path) {
            _exit(1);
        }
        
        /* Use binary mode for v8 protocol */
        execl(readonlybox_path, "rbox-wrap", "--bin", "--judge", command, NULL);
        /* If we get here, execl failed */
        _exit(1);
    }

    /* Parent: read binary output */
    /* Read the binary packet from the pipe while the child is running.
     * This avoids potential deadlock if the child writes more than the pipe buffer can hold. */

    /* Close parent's write end - child only needs to write */
    close(pipefd[1]);

    /* Read with dynamically growing buffer (max 64KB for protocol response) */
#define MAX_RESPONSE_SIZE 65536
    ssize_t n;
    while ((n = read(pipefd[0], buffer + bytes_read, cap - bytes_read)) > 0) {
        bytes_read += n;
        if ((size_t)bytes_read == cap) {
            if (cap >= MAX_RESPONSE_SIZE) {
                /* Response too large - reject to prevent memory exhaustion */
                kill(pid, SIGKILL);
                close(pipefd[0]);
                waitpid(pid, NULL, 0);
                free(buffer);
                return -1;
            }
            /* Grow buffer */
            size_t new_cap = cap * 2;
            if (new_cap > MAX_RESPONSE_SIZE) new_cap = MAX_RESPONSE_SIZE;
            char *new_buf = realloc(buffer, new_cap);
            if (!new_buf) {
                /* Realloc failed - kill child and cleanup */
                kill(pid, SIGKILL);
                close(pipefd[0]);
                waitpid(pid, NULL, 0);
                free(buffer);
                return -1;
            }
            buffer = new_buf;
            cap = new_cap;
        }
    }
    close(pipefd[0]);
    /* pipefd[1] already closed by parent before reading */

    /* Wait for child to finish */
    int status;
    waitpid(pid, &status, 0);

    if (bytes_read <= 0) {
        free(buffer);
        return -1;
    }

    /* Do NOT null-terminate - this is binary protocol data */

    /* Check if child exited normally or was killed by signal */
    int exit_code;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = -WTERMSIG(status);  /* Treat signal as error */
    } else {
        exit_code = -1;
    }

    /* Use v8 protocol decode utilities to parse binary response */
    rbox_decoded_header_t header;
    rbox_response_details_t details;
    rbox_env_decisions_t env_decisions;
    memset(&env_decisions, 0, sizeof(env_decisions));

    /* Decode header */
    rbox_decode_header(buffer, bytes_read, &header);
    if (!header.valid) {
        /* Fall back to exit code */
        free(buffer);
        if (exit_code == 0) return 0;
        if (exit_code == 9) return 9;
        return -1;
    }

    /* Decode env decisions FIRST - apply them regardless of allow/deny decision */
    rbox_decode_env_decisions(&header, &details, buffer, bytes_read, &env_decisions);
    if (env_decisions.valid && env_decisions.env_count > 0 && env_decisions.bitmap) {
        /* Build env_decisions string with index:decision format */
        char env_decisions_buf[4096] = {0};
        char *p = env_decisions_buf;
        size_t remaining = sizeof(env_decisions_buf) - 1;

        for (int i = 0; i < env_decisions.env_count && remaining > 1; i++) {
            uint8_t bit = (env_decisions.bitmap[i / 8] >> (i % 8)) & 1;
            int n = snprintf(p, remaining, "%d:%d", i, bit);
            if (n > 0 && (size_t)n < remaining) {
                p += n;
                remaining -= n;
                if (remaining > 1 && i < env_decisions.env_count - 1) {
                    *p++ = ',';
                    remaining--;
                }
            }
        }

        if (env_decisions_buf[0]) {
            setenv("READONLYBOX_ENV_DECISIONS", env_decisions_buf, 1);
        }

        /* Also set the flagged env var names so child can filter */
        if (g_flagged_env_count > 0) {
            char env_names_buf[4096] = {0};
            char *p = env_names_buf;
            size_t rem = sizeof(env_names_buf) - 1;

            for (int i = 0; i < g_flagged_env_count && i < env_decisions.env_count && rem > 1; i++) {
                if (g_flagged_envs[i].name) {
                    size_t len = strlen(g_flagged_envs[i].name);
                    if (len < rem) {
                        memcpy(p, g_flagged_envs[i].name, len);
                        p += len;
                        rem -= len;
                        if (rem > 1 && i < g_flagged_env_count - 1) {
                            *p++ = ',';
                            rem--;
                        }
                    }
                }
            }

            if (env_names_buf[0]) {
                setenv("READONLYBOX_FLAGGED_ENV_NAMES", env_names_buf, 1);
            }
        }

        /* Free bitmap */
        free(env_decisions.bitmap);
    }

    /* Decode response details */
    rbox_decode_response_details(&header, buffer, bytes_read, &details);
    if (details.valid) {
        /* Use decision from response packet - this is the authoritative source */
        /* Decision: RBOX_DECISION_ALLOW=2 means allow, anything else is deny */
        free(buffer);
        if (details.decision == RBOX_DECISION_ALLOW) {
            return 0;  /* Allowed */
        } else {
            return 9;  /* Denied */
        }
    }

    /* Fallback to exit code if details not valid */
    free(buffer);
    if (exit_code == 0) return 0;
    if (exit_code == 9) return 9;
    return -1;
}

/* Get path to readonlybox binary */
static const char *get_readonlybox_path(void) {
    static char path_buf[PATH_MAX];

    /* First, check environment variable for explicit override */
    const char *env_path = getenv("READONLYBOX_WRAP_PATH");
    if (env_path && env_path[0]) {
        if (access(env_path, X_OK) == 0) {
            return env_path;
        }
    }

    /* Try to find relative to our executable location */
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len > 0) {
        self_path[len] = '\0';
        char *dir = dirname(self_path);
        
        /* Try relative to executable: ../rbox-wrap/rbox-wrap */
        snprintf(path_buf, sizeof(path_buf), "%s/../rbox-wrap/rbox-wrap", dir);
        if (access(path_buf, X_OK) == 0) {
            return path_buf;
        }
        
        /* Try relative to executable: ../../rbox-wrap/rbox-wrap */
        snprintf(path_buf, sizeof(path_buf), "%s/../../rbox-wrap/rbox-wrap", dir);
        if (access(path_buf, X_OK) == 0) {
            return path_buf;
        }
        
        /* Also try readonlybox as fallback */
        snprintf(path_buf, sizeof(path_buf), "%s/../readonlybox-ptrace", dir);
        if (access(path_buf, X_OK) == 0) {
            /* This is the ptrace binary itself - check sibling directory */
            snprintf(path_buf, sizeof(path_buf), "%s/../../bin/rbox-wrap", dir);
            if (access(path_buf, X_OK) == 0) {
                return path_buf;
            }
        }
    }
    
    /* Try current working directory */
    if (access("./rbox-wrap/rbox-wrap", X_OK) == 0) {
        return "./rbox-wrap/rbox-wrap";
    }
    
    /* Try PATH */
    char *path_env = getenv("PATH");
    if (path_env) {
        char *path_copy = strdup(path_env);
        char *dir = strtok(path_copy, ":");
        while (dir) {
            snprintf(path_buf, sizeof(path_buf), "%s/rbox-wrap", dir);
            if (access(path_buf, X_OK) == 0) {
                free(path_copy);
                return path_buf;
            }
            dir = strtok(NULL, ":");
        }
        free(path_copy);
    }
    
    return NULL;
}
