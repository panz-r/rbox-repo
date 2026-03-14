/*
 * main.c - Entry point for readonlybox-ptrace
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/prctl.h>
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

#include "syscall_handler.h"
#include "validation.h"
#include "protocol.h"
#include <rbox_protocol_defs.h>
#include <rbox_protocol.h>

#include "env_screener.h"

/* Global storage for flagged env var names (used by run_judge) */
static char *g_flagged_env_names[256];
static int g_flagged_env_count = 0;

/* Forward declarations for judge execution */
static const char *get_readonlybox_path(void);
int run_judge(const char *command, const char *caller_info);

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

static const char *g_progname = "readonlybox-ptrace";
static uid_t g_original_uid = 0;
static gid_t g_original_gid = 0;
static char g_original_cwd[4096] = ".";
static bool g_keep_env = false;
static char **g_extra_env = NULL;
static int g_extra_env_count = 0;

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
    fprintf(stderr, "  --keep-env           Pass through original environment (don't reset)\n");
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

    if (!g_keep_env) {
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
            setenv("HOME", home, 1);
            setenv("USER", username, 1);
            setenv("LOGNAME", username, 1);
            setenv("SHELL", shell, 1);
            unsetenv("PKEXEC_UID");
            unsetenv("PKEXEC_AGENT");
        }
    }

    /* Apply extra environment variables */
    for (int i = 0; i < g_extra_env_count; i++) {
        char *eq = strchr(g_extra_env[i], '=');
        if (eq) {
            *eq = '\0';
            setenv(g_extra_env[i], eq + 1, 1);
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
    int indices[32];
    int flagged_count;
    
    env_screener_status_t status = env_screener_scan(
        indices,
        32,
        &flagged_count,
        0.7,   // posterior_threshold (Bayesian inference) - 0.7 for high confidence
        12     // min_length
    );
    
    if (status == ENV_SCREENER_BUFFER_TOO_SMALL) {
        /* Allocate larger buffer if needed - shouldn't happen often */
        int *larger = malloc(flagged_count * sizeof(int));
        if (larger) {
            env_screener_scan(larger, flagged_count, &flagged_count, 0.7, 12);
            free(larger);
        }
    }
    
    if (status != ENV_SCREENER_OK || flagged_count == 0) {
        return;
    }
    
    /* Store flagged env var names globally for run_judge to access */
    g_flagged_env_count = flagged_count;
    for (int i = 0; i < flagged_count && i < 256; i++) {
        extern char **environ;
        char *entry = environ[indices[i]];
        
        char name[256];
        extract_env_name(entry, name, sizeof(name));
        
        /* Store a copy of the name */
        if (g_flagged_env_names[i]) free(g_flagged_env_names[i]);
        g_flagged_env_names[i] = strdup(name);
    }
    
    /* Collect blocked variable names to remove after prompting */
    char *blocked[32];
    int blocked_count = 0;
    
    /* Prompt user for each flagged variable */
    for (int i = 0; i < flagged_count; i++) {
        extern char **environ;
        char *entry = environ[indices[i]];
        
        char name[256];
        const char *value = extract_env_value(entry);
        extract_env_name(entry, name, sizeof(name));
        
        double score = env_screener_combined_score_name(name, value);
        
        if (score > 0.8) {
            fprintf(stderr, "\n⚠️  High-confidence secret detected:\n");
            fprintf(stderr, "   %s=*** (score: %.2f)\n", name, score);
        } else {
            fprintf(stderr, "\n⚠️  Potential secret detected:\n");
            fprintf(stderr, "   %s=*** (score: %.2f)\n", name, score);
        }
        
        fprintf(stderr, "   Pass this variable to the command? [y/N]: ");
        
        char response[8];
        if (fgets(response, sizeof(response), stdin)) {
            if (response[0] != 'y' && response[0] != 'Y') {
                /* Store name to remove after loop */
                blocked[blocked_count++] = strdup(name);
            }
        }
    }
    
    /* Remove all blocked variables in one pass */
    for (int j = 0; j < blocked_count; j++) {
        unsetenv(blocked[j]);
        fprintf(stderr, "   → Blocked: %s\n", blocked[j]);
        free(blocked[j]);
    }
    
    fprintf(stderr, "\n✓ Environment screened\n");
}

static int relaunch_with_pkexec(int argc, char *argv[], const char *cmd_path) {
    uid_t original_uid = getuid();
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strcpy(cwd, ".");
    }

    /* Count environment variables to pass */
    int env_count = 0;
    for (char **e = environ; *e; e++) {
        env_count++;
    }
    
    /* Allocate argv: pkexec + args + env vars + NULL */
    /* Estimate: 10 pkexec args + argc + env_count + 1 */
    char **new_argv = malloc((argc + env_count + 20) * sizeof(char *));
    if (!new_argv) {
        perror("malloc");
        return 1;
    }

    int idx = 0;
    new_argv[idx++] = "pkexec";
    new_argv[idx++] = "--disable-internal-agent";
    new_argv[idx++] = argv[0];
    new_argv[idx++] = "--uid";
    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%d", original_uid);
    new_argv[idx] = strdup(uid_str);
    if (!new_argv[idx]) {
        free(new_argv);
        return 1;
    }
    idx++;
    new_argv[idx++] = "--cwd";
    new_argv[idx] = strdup(cwd);
    if (!new_argv[idx]) {
        free(new_argv[4]);
        free(new_argv);
        return 1;
    }
    idx++;
    new_argv[idx++] = "--cmd";
    new_argv[idx] = strdup(cmd_path);
    if (!new_argv[idx]) {
        free(new_argv[4]);
        free(new_argv[6]);
        free(new_argv);
        return 1;
    }
    idx++;

    for (char **e = environ; *e; e++) {
        /* Check for valid UTF-8 */
        int valid_utf8 = 1;
        for (char *p = *e; *p; p++) {
            if ((*p & 0x80) == 0) {
                /* ASCII - ok */
            } else if ((*p & 0xE0) == 0xC0) {
                /* 2-byte sequence */
                if ((p[1] & 0xC0) != 0x80) { valid_utf8 = 0; break; }
                p++;
            } else if ((*p & 0xF0) == 0xE0) {
                /* 3-byte sequence */
                if ((p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) { valid_utf8 = 0; break; }
                p += 2;
            } else if ((*p & 0xF8) == 0xF0) {
                /* 4-byte sequence */
                if ((p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 || (p[3] & 0xC0) != 0x80) { valid_utf8 = 0; break; }
                p += 3;
            } else {
                valid_utf8 = 0; break;
            }
        }
        
        if (!valid_utf8) {
            fprintf(stderr, "DEBUG: Skipping non-UTF8 env var: %.50s...\n", *e);
            continue;
        }
        
        /* Use --env=VAR format instead of --env VAR */
        char env_arg[8192];
        snprintf(env_arg, sizeof(env_arg), "--env=%s", *e);
        new_argv[idx++] = strdup(env_arg);
    }

    for (int i = 1; i < argc; i++) {
        new_argv[idx++] = argv[i];
    }
    new_argv[idx] = NULL;

    execvp("pkexec", new_argv);

    fprintf(stderr, "\n%s: Failed to get elevated privileges via pkexec.\n", g_progname);
    /* Cleanup on error - would need to free all strdup'd env vars */
    free(new_argv);
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
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
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
             */
            char parent_exe[256];
            char parent_link[64];
            snprintf(parent_link, sizeof(parent_link), "/proc/%d/exe", pid);
            ssize_t parent_len = readlink(parent_link, parent_exe, sizeof(parent_exe) - 1);
            bool parent_is_readonlybox = false;
            if (parent_len > 0) {
                parent_exe[parent_len] = '\0';
                if (strstr(parent_exe, "readonlybox") != NULL) {
                    parent_is_readonlybox = true;
                }
            }
            
            /* Detach only if parent is readonlybox binary - all other processes
             * should continue to be traced so their execves get validated */
            if (parent_is_readonlybox) {
                DEBUG_PRINT("PARENT: pid=%d is readonlybox binary, detaching child %d\n", pid, (int)child_pid);
                ptrace(PTRACE_DETACH, (pid_t)child_pid, 0, 0);
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
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
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
                    fprintf(stderr, "%s: Process table full\n", g_progname);
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
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

    g_progname = argv[0];

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"uid", required_argument, 0, 'u'},
        {"cwd", required_argument, 0, 'c'},
        {"cmd", required_argument, 0, 'm'},
        {"attach", required_argument, 0, 'p'},
        {"keep-env", no_argument, 0, 'k'},
        {"env", required_argument, 0, 'e'},
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
            case 'e':
                g_extra_env = realloc(g_extra_env, (g_extra_env_count + 1) * sizeof(char *));
                g_extra_env[g_extra_env_count++] = strdup(optarg);
                break;
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

    /* Screen environment for potential secrets before launching (unless --keep-env) */
    if (!g_keep_env) {
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
        
        /* Resume the process - it will be traced and we'll intercept its execves */
        if (ptrace(PTRACE_CONT, attach_pid, NULL, NULL) < 0) {
            perror("ptrace(CONT)");
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
    char buffer[4096];
    ssize_t bytes_read;

    /* Create pipe for reading output */
    if (pipe(pipefd) < 0) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: detach from tracer before exec to avoid re-intercepting */
        ptrace(PTRACE_DETACH, 0, NULL, 0);
        
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
            char env_buf[4096] = {0};
            char *p = env_buf;
            size_t rem = sizeof(env_buf) - 1;
            
            for (int i = 0; i < g_flagged_env_count && rem > 1; i++) {
                if (g_flagged_env_names[i]) {
                    /* Get the score from process state if available, otherwise use default */
                    float score = 0.7;  /* Default score for screened vars */
                    
                    size_t len = strlen(g_flagged_env_names[i]);
                    if (len < rem) {
                        /* Format: name:score */
                        memcpy(p, g_flagged_env_names[i], len);
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
                    }
                }
            }
            
            if (env_buf[0]) {
                setenv("READONLYBOX_FLAGGED_ENVS", env_buf, 1);
            }
        }

        /* Find readonlybox binary */
        const char *readonlybox_path = get_readonlybox_path();
        
        /* Use binary mode for v8 protocol */
        execl(readonlybox_path, "readonlybox", "--bin", "--judge", command, NULL);
        /* If we get here, execl failed */
        _exit(1);
    }

    /* Parent: read binary output */
    /* Wait for child to finish first - this ensures all data is written */
    int status;
    waitpid(pid, &status, 0);
    
    /* Now read the binary packet from the closed pipe */
    bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1);
    close(pipefd[0]);
    close(pipefd[1]);
    
    if (bytes_read <= 0) {
        return -1;
    }

    buffer[bytes_read] = '\0';
    
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
    
    /* Decode header */
    rbox_decode_header(buffer, bytes_read, &header);
    if (!header.valid) {
        DEBUG_PRINT("JUDGE: invalid header for '%s'\n", command);
        /* Fall back to exit code */
        if (exit_code == 0) return 0;
        if (exit_code == 9) return 9;
        return -1;
    }
    
    /* Decode response details */
    rbox_decode_response_details(&header, buffer, bytes_read, &details);
    if (!details.valid) {
        DEBUG_PRINT("JUDGE: invalid details for '%s'\n", command);
        if (exit_code == 0) return 0;
        if (exit_code == 9) return 9;
        return -1;
    }
    
    /* Decode env decisions if present */
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
            DEBUG_PRINT("JUDGE: env_decisions: '%s'\n", env_decisions_buf);
            setenv("READONLYBOX_ENV_DECISIONS", env_decisions_buf, 1);
        }
        
        /* Also set the flagged env var names so child can filter */
        if (g_flagged_env_count > 0) {
            char env_names_buf[4096] = {0};
            char *p = env_names_buf;
            size_t rem = sizeof(env_names_buf) - 1;
            
            for (int i = 0; i < g_flagged_env_count && i < env_decisions.env_count && rem > 1; i++) {
                if (g_flagged_env_names[i]) {
                    size_t len = strlen(g_flagged_env_names[i]);
                    if (len < rem) {
                        memcpy(p, g_flagged_env_names[i], len);
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
                DEBUG_PRINT("JUDGE: flagged env names: '%s'\n", env_names_buf);
                setenv("READONLYBOX_FLAGGED_ENV_NAMES", env_names_buf, 1);
            }
        }
        
        /* Free bitmap */
        rbox_free_env_decisions(&env_decisions);
    }
    
    /* Return based on decision */
    DEBUG_PRINT("JUDGE: decision=%d for '%s'\n", details.decision, command);
    if (details.decision == 2) return 0;   /* ALLOW */
    if (details.decision == 3) return 9;   /* DENY */
    
    /* Fallback to exit code */
    if (exit_code == 0) return 0;
    if (exit_code == 9) return 9;
    
    DEBUG_PRINT("JUDGE: Unknown response for '%s'\n", command);
    return -1;  /* Error */
}

/* Get path to readonlybox binary */
static const char *get_readonlybox_path(void) {
    static char path_buf[PATH_MAX];
    
    /* First try production path */
    if (access("/usr/local/bin/readonlybox", X_OK) == 0) {
        return "/usr/local/bin/readonlybox";
    }
    
    /* Try to find relative to our executable location */
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len > 0) {
        self_path[len] = '\0';
        char *dir = dirname(self_path);
        
        /* Try relative to executable: ../../bin/readonlybox */
        snprintf(path_buf, sizeof(path_buf), "%s/../../bin/readonlybox", dir);
        if (access(path_buf, X_OK) == 0) {
            return path_buf;
        }
        
        /* Try relative to executable: ../bin/readonlybox */
        snprintf(path_buf, sizeof(path_buf), "%s/../bin/readonlybox", dir);
        if (access(path_buf, X_OK) == 0) {
            return path_buf;
        }
    }
    
    /* Try current working directory */
    if (access("./bin/readonlybox", X_OK) == 0) {
        return "./bin/readonlybox";
    }
    
    /* Try absolute path */
    if (access("/w/rbox-copy/bin/readonlybox", X_OK) == 0) {
        return "/w/rbox-copy/bin/readonlybox";
    }
    
    /* Fall back to PATH lookup */
    return "readonlybox";
}
