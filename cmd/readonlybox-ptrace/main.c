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
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>

#include "syscall_handler.h"
#include "validation.h"
#include "protocol.h"

#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

static const char *g_progname = "readonlybox-ptrace";
static uid_t g_original_uid = 0;
static gid_t g_original_gid = 0;
static char g_original_cwd[4096] = ".";

static void print_usage(void) {
    fprintf(stderr, "Usage: %s wrap <command> [args...]\n", g_progname);
    fprintf(stderr, "       %s <command> [args...]\n", g_progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Run a command with ptrace-based command interception.\n");
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

static int relaunch_with_pkexec(int argc, char *argv[], const char *cmd_path) {
    uid_t original_uid = getuid();
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strcpy(cwd, ".");
    }

    char **new_argv = malloc((argc + 9) * sizeof(char *));
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

    for (int i = 1; i < argc; i++) {
        new_argv[idx++] = argv[i];
    }
    new_argv[idx] = NULL;

    execvp("pkexec", new_argv);

    fprintf(stderr, "\n%s: Failed to get elevated privileges via pkexec.\n", g_progname);
    free(new_argv[4]);
    free(new_argv[6]);
    free(new_argv[8]);
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

            /* Check if parent is readonlybox - if so, don't trace its children.
             * 
             * Why: When a command is redirected to readonlybox for validation,
             * readonlybox contacts the server and gets approval. Then readonlybox
             * forks a child process to execute the actual command. Without this
             * check, we would trace that child and send a duplicate request to
             * the server. By detaching children of readonlybox, we avoid this
             * duplicate request while still allowing the command to execute.
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
            
            ProcessState *parent_state = syscall_get_process_state(pid);
            if (parent_state && parent_state->detached) {
                DEBUG_PRINT("PARENT: pid=%d fork/clone, parent detached - detaching child\n", pid);
                ptrace(PTRACE_DETACH, (pid_t)child_pid, 0, 0);
            } else if (parent_is_readonlybox) {
                DEBUG_PRINT("PARENT: pid=%d is readonlybox, detaching child %d\n", pid, (int)child_pid);
                ptrace(PTRACE_DETACH, (pid_t)child_pid, 0, 0);
            } else {
                DEBUG_PRINT("PARENT: pid=%d fork/clone, resuming child %d\n", pid, (int)child_pid);
                /* Set options on child for grandchildren tracing */
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

    g_progname = argv[0];

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"uid", required_argument, 0, 'u'},
        {"cwd", required_argument, 0, 'c'},
        {"cmd", required_argument, 0, 'm'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "+hvu:c:m:", long_options, NULL)) != -1) {
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
            default:
                print_usage();
                return 1;
        }
    }

    save_original_user(provided_uid, provided_cwd);

    int cmd_start = optind;
    if (cmd_start < argc && strcmp(argv[cmd_start], "wrap") == 0) {
        cmd_start++;
    }

    if (cmd_start >= argc) {
        print_usage();
        return 1;
    }

    char *cmd_path = NULL;
    if (provided_cmd_path) {
        cmd_path = strdup(provided_cmd_path);
    } else {
        cmd_path = resolve_command_path(argv[cmd_start]);
    }

    if (!cmd_path) {
        fprintf(stderr, "%s: Command not found: %s\n", g_progname, argv[cmd_start]);
        return 1;
    }

    if (provided_uid == 0 && !have_ptrace_capability()) {
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
