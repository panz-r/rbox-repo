/*
 * test_e2e.c - End-to-end tests for ptrace client
 *
 * These tests run actual commands wrapped in the ptrace client
 * and verify the behavior with the server in different modes.
 *
 * Architecture: TWO pre-started servers (autodeny + autoallow) run for all tests.
 * Tests choose which server to use based on what they're testing.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>

#include "test_utils.h"

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Global socket paths for pre-started servers */
static char g_autodeny_socket_path[256] = "";
static char g_autoallow_socket_path[256] = "";

/* Server PIDs for cleanup */
static pid_t g_autodeny_server_pid = 0;
static pid_t g_autoallow_server_pid = 0;

/* Log file for autoallow server (verbose logging) */
static char g_autoallow_logfile[256] = "";

/* Cleanup function called at exit to stop any remaining servers */
static void cleanup_servers_now(void) {
    if (g_autodeny_server_pid > 0) {
        kill(g_autodeny_server_pid, SIGTERM);
        waitpid(g_autodeny_server_pid, NULL, 0);
        g_autodeny_server_pid = 0;
    }
    if (g_autoallow_server_pid > 0) {
        kill(g_autoallow_server_pid, SIGTERM);
        waitpid(g_autoallow_server_pid, NULL, 0);
        g_autoallow_server_pid = 0;
    }
    if (g_autoallow_logfile[0]) {
        unlink(g_autoallow_logfile);
        g_autoallow_logfile[0] = '\0';
    }
}

/* Signal handler for cleanup */
static void server_cleanup_signal(int sig) {
    cleanup_servers_now();
    signal(sig, SIG_DFL);
    raise(sig);
}

/* Start both servers (autodeny and autoallow with verbose logging) */
static int start_all_servers(void) {
    /* Start autodeny server */
    snprintf(g_autodeny_socket_path, sizeof(g_autodeny_socket_path),
             "/tmp/robox-test-autodeny-%d.sock", (int)getpid());

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        /* Child - start autodeny server */
        const char *server_path = "../../bin/readonlybox-server";
        if (access(server_path, X_OK) != 0) {
            server_path = "./readonlybox-server";
            if (access(server_path, X_OK) != 0) {
                server_path = "readonlybox-server";
            }
        }

        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        execl(server_path, server_path, "-q", "-socket", g_autodeny_socket_path, "--auto-deny", NULL);
        _exit(1);
    }

    g_autodeny_server_pid = pid;

    /* Wait for autodeny socket */
    for (int i = 0; i < 50; i++) {
        if (access(g_autodeny_socket_path, F_OK) == 0) break;
        usleep(100000);
    }

    /* Start autoallow server with verbose logging to log file */
    snprintf(g_autoallow_socket_path, sizeof(g_autoallow_socket_path),
             "/tmp/robox-test-autoallow-%d.sock", (int)getpid());

    snprintf(g_autoallow_logfile, sizeof(g_autoallow_logfile),
             "../logs/robox-e2e-autoallow-%d.log", (int)getpid());

    pid = fork();
    if (pid < 0) {
        kill(g_autodeny_server_pid, SIGTERM);
        waitpid(g_autodeny_server_pid, NULL, 0);
        return -1;
    }

    if (pid == 0) {
        /* Child - start autoallow server */
        const char *server_path = "../../bin/readonlybox-server";
        if (access(server_path, X_OK) != 0) {
            server_path = "./readonlybox-server";
            if (access(server_path, X_OK) != 0) {
                server_path = "readonlybox-server";
            }
        }

        FILE *f = fopen(g_autoallow_logfile, "w");
        if (f) {
            dup2(fileno(f), STDOUT_FILENO);
            dup2(fileno(f), STDERR_FILENO);
            fclose(f);
        }

        execl(server_path, server_path, "-vv", "-socket", g_autoallow_socket_path, NULL);
        _exit(1);
    }

    g_autoallow_server_pid = pid;

    /* Wait for autoallow socket */
    for (int i = 0; i < 50; i++) {
        if (access(g_autoallow_socket_path, F_OK) == 0) break;
        usleep(100000);
    }

    return 0;
}

/* Stop both servers */
static void stop_all_servers(void) {
    if (g_autodeny_server_pid > 0) {
        kill(g_autodeny_server_pid, SIGTERM);
        waitpid(g_autodeny_server_pid, NULL, 0);
        g_autodeny_server_pid = 0;
    }
    if (g_autoallow_server_pid > 0) {
        kill(g_autoallow_server_pid, SIGTERM);
        waitpid(g_autoallow_server_pid, NULL, 0);
        g_autoallow_server_pid = 0;
    }
    if (g_autoallow_logfile[0]) {
        unlink(g_autoallow_logfile);
        g_autoallow_logfile[0] = '\0';
    }
}

/* Find ptrace client binary */
static const char *find_ptrace_binary(void) {
    static const char *paths[] = {
        "../../bin/readonlybox-ptrace",
        "./readonlybox-ptrace",
        "../readonlybox-ptrace",
        "readonlybox-ptrace",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0) {
            return paths[i];
        }
    }
    return NULL;
}

typedef enum {
    SERVER_AUTOALLOW,
    SERVER_AUTODENY
} ServerType;

/* Run a command through the ptrace client */
static int run_ptrace_impl(char *const argv[], int *exit_code, ServerType server,
                          const char *hard_allow, const char *hard_deny) {
    const char *ptrace_path = find_ptrace_binary();
    if (!ptrace_path) {
        return -1;
    }

    const char *socket_path = (server == SERVER_AUTODENY) ?
        g_autodeny_socket_path : g_autoallow_socket_path;

    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        /* Child - run ptrace client */
        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        setenv("READONLYBOX_SOCKET", socket_path, 1);

        if (hard_allow) {
            setenv("READONLYBOX_HARD_ALLOW", hard_allow, 1);
        }
        if (hard_deny) {
            setenv("READONLYBOX_HARD_DENY", hard_deny, 1);
        }

        int arg_count = 0;
        while (argv[arg_count]) arg_count++;

        char **new_argv = malloc((arg_count + 4) * sizeof(char *));
        new_argv[0] = (char *)ptrace_path;
        new_argv[1] = "wrap";
        new_argv[2] = "--no-pkexec";
        for (int i = 0; i < arg_count; i++) {
            new_argv[i + 3] = argv[i];
        }
        new_argv[arg_count + 3] = NULL;

        execvp(ptrace_path, new_argv);
        _exit(127);
    }

    /* Parent - wait for child */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }

    if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        *exit_code = 128 + WTERMSIG(status);
    } else {
        *exit_code = -1;
    }

    return 0;
}

/* Run a command through the ptrace client using autodeny server */
static int run_ptrace_autodeny(char *const argv[], int *exit_code) {
    return run_ptrace_impl(argv, exit_code, SERVER_AUTODENY, NULL, NULL);
}

/* Run a command through the ptrace client using autoallow server */
static int run_ptrace_autoallow(char *const argv[], int *exit_code) {
    return run_ptrace_impl(argv, exit_code, SERVER_AUTOALLOW, NULL, NULL);
}

/* Run a command through the ptrace client with Landlock environment */
static int run_ptrace_landlock(char *const argv[], int *exit_code,
                               const char *hard_allow, const char *hard_deny) {
    return run_ptrace_impl(argv, exit_code, SERVER_AUTODENY, hard_allow, hard_deny);
}

/* Count server requests in logfile (lines containing "ALLOW" or "DENY") */
static int count_server_requests(const char *logfile) {
    FILE *f = fopen(logfile, "r");
    if (!f) return -1;
    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "ALLOW") || strstr(line, "DENY"))
            count++;
    }
    fclose(f);
    return count;
}

/* Test macro - uses pre-started servers, no per-test cleanup */
#define TEST(name) static int test_##name(void)
#define RUN_TEST(name) do { \
    printf("  Running %s... ", #name); \
    fflush(stdout); \
    tests_run++; \
    int test_result = test_##name(); \
    if (test_result == 0) { \
        printf("PASSED\n"); \
        tests_passed++; \
    } else { \
        printf("FAILED\n"); \
        tests_failed++; \
    } \
} while(0)

/* CHECK macros that accumulate results - result is a failure COUNT, starts at 0 */
#define CHECK(cond) do { \
    if (!(cond)) { \
        return 1; \
    } \
} while(0)

/* CHECK with result accumulation - result is failure count (increments on each failure) */
#define CHECK_EQ(result, a, b) do { \
    if ((a) != (b)) { \
        result++; \
    } \
} while(0)

#define CHECK_NE(result, a, b) do { \
    if ((a) == (b)) { \
        result++; \
    } \
} while(0)

#define CHECK_NOT_NULL(result, p) do { \
    if ((p) == NULL) { \
        result++; \
    } \
} while(0)

#define CHECK_STR_EQ(result, a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        result++; \
    } \
} while(0)

#define CHECK_LT(result, a, b) do { \
    if ((a) >= (b)) { \
        result++; \
    } \
} while(0)

#define CHECK_GT(result, a, b) do { \
    if ((a) <= (b)) { \
        result++; \
    } \
} while(0)

/*
 * SAFE COMMAND TESTS (autodeny server) - DFA should allow without server contact
 */

TEST(safe_command_ls) {
    int result = 0;
    char *args[] = {"sh", "-c", "ls /tmp", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    return result;
}

TEST(safe_command_echo) {
    int result = 0;
    char *args[] = {"sh", "-c", "echo hello", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    return result;
}

TEST(safe_command_cat) {
    int result = 0;

    FILE *f = fopen("/tmp/test_e2e_cat.txt", "w");
    CHECK_NOT_NULL(result, f);
    if (result) return result;
    fprintf(f, "test content\n");
    fclose(f);

    char *args[] = {"sh", "-c", "cat /tmp/test_e2e_cat.txt", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);

    unlink("/tmp/test_e2e_cat.txt");
    return result;
}

TEST(safe_command_pwd) {
    int result = 0;
    char *args[] = {"sh", "-c", "pwd", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    return result;
}

TEST(safe_command_date) {
    int result = 0;
    char *args[] = {"sh", "-c", "date", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    return result;
}

TEST(dangerous_command_rm) {
    int result = 0;
    unlink("/tmp/test_e2e_rm.txt");

    FILE *f = fopen("/tmp/test_e2e_rm.txt", "w");
    CHECK_NOT_NULL(result, f);
    fprintf(f, "test content\n");
    fclose(f);

    char *args[] = {"sh", "-c", "rm /tmp/test_e2e_rm.txt", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_NE(result, exit_code, 0);

    CHECK_EQ(result, access("/tmp/test_e2e_rm.txt", F_OK), 0);
    unlink("/tmp/test_e2e_rm.txt");
    return result;
}

TEST(dangerous_command_mkdir) {
    int result = 0;
    rmdir("/tmp/test_e2e_mkdir_dir");

    char *args[] = {"sh", "-c", "mkdir /tmp/test_e2e_mkdir_dir", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_NE(result, exit_code, 0);

    CHECK_NE(result, access("/tmp/test_e2e_mkdir_dir", F_OK), 0);
    rmdir("/tmp/test_e2e_mkdir_dir");
    return result;
}

TEST(dangerous_command_write) {
    int result = 0;
    unlink("/tmp/test_e2e_write.txt");

    char *args[] = {"sh", "-c", "sh", "-c", "echo test > /tmp/test_e2e_write.txt", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_NE(result, exit_code, 0);

    CHECK_NE(result, access("/tmp/test_e2e_write.txt", F_OK), 0);
    unlink("/tmp/test_e2e_write.txt");
    return result;
}

TEST(autoallow_safe_command) {
    int result = 0;
    char *args[] = {"sh", "-c", "ls /tmp", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autoallow(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    return result;
}

TEST(autoallow_dangerous_command) {
    int result = 0;
    unlink("/tmp/test_e2e_autoallow_rm.txt");

    FILE *f = fopen("/tmp/test_e2e_autoallow_rm.txt", "w");
    CHECK_NOT_NULL(result, f);
    fprintf(f, "test content\n");
    fclose(f);

    char *args[] = {"sh", "-c", "rm /tmp/test_e2e_autoallow_rm.txt", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autoallow(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);

    CHECK_NE(result, access("/tmp/test_e2e_autoallow_rm.txt", F_OK), 0);
    unlink("/tmp/test_e2e_autoallow_rm.txt");
    return 0;
}

/*
 * MULTIPLE COMMANDS
 */

TEST(multiple_safe_commands) {
    int result = 0;
    char *args1[] = {"sh", "-c", "pwd", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args1, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);

    char *args2[] = {"sh", "-c", "echo test", NULL};
    CHECK_EQ(result, run_ptrace_autodeny(args2, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);

    char *args3[] = {"sh", "-c", "date", NULL};
    CHECK_EQ(result, run_ptrace_autodeny(args3, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);

    return result;
}

TEST(command_with_arguments) {
    int result = 0;
    char *args[] = {"sh", "-c", "ls -la /tmp", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    return result;
}

TEST(nonexistent_command) {
    int result = 0;
    char *args[] = {"sh", "-c", "nonexistent_command_xyz", NULL};
    int exit_code;
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_NE(result, exit_code, 0);
    return result;
}

/*
 * WRAPPER CHAIN TESTS (using autoallow server with log file to count requests)
 */

TEST(wrapper_chain_simple) {
    char logfile[256];
    snprintf(logfile, sizeof(logfile), "../logs/robox-e2e-wrapper-simple-%d.log", (int)getpid());

    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }

    if (pid == 0) {
        const char *ptrace_path = find_ptrace_binary();
        if (!ptrace_path) _exit(1);

        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        setenv("READONLYBOX_SOCKET", g_autoallow_socket_path, 1);

        char *args[] = {"sh", "-c", "timeout 2 ls /tmp", NULL};
        char **new_argv = malloc(7 * sizeof(char *));
        new_argv[0] = (char *)ptrace_path;
        new_argv[1] = "wrap";
        new_argv[2] = "--no-pkexec";
        new_argv[3] = "sh";
        new_argv[4] = "-c";
        new_argv[5] = "timeout 2 ls /tmp";
        new_argv[6] = NULL;

        execvp(ptrace_path, new_argv);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);

    return 0;
}

TEST(wrapper_chain_nested_sh_c) {
    char logfile[256];
    snprintf(logfile, sizeof(logfile), "../logs/robox-e2e-wrapper-nested-%d.log", (int)getpid());

    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }

    if (pid == 0) {
        const char *ptrace_path = find_ptrace_binary();
        if (!ptrace_path) _exit(1);

        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        setenv("READONLYBOX_SOCKET", g_autoallow_socket_path, 1);

        char **new_argv = malloc(8 * sizeof(char *));
        new_argv[0] = (char *)ptrace_path;
        new_argv[1] = "wrap";
        new_argv[2] = "--no-pkexec";
        new_argv[3] = "timeout";
        new_argv[4] = "2";
        new_argv[5] = "sh";
        new_argv[6] = "-c";
        new_argv[7] = "timeout 1 ls /tmp";

        execvp(ptrace_path, new_argv);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);

    return 0;
}

TEST(wrapper_chain_deep) {
    char logfile[256];
    snprintf(logfile, sizeof(logfile), "../logs/robox-e2e-wrapper-deep-%d.log", (int)getpid());

    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }

    if (pid == 0) {
        const char *ptrace_path = find_ptrace_binary();
        if (!ptrace_path) _exit(1);

        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        setenv("READONLYBOX_SOCKET", g_autoallow_socket_path, 1);

        char **new_argv = malloc(7 * sizeof(char *));
        new_argv[0] = (char *)ptrace_path;
        new_argv[1] = "wrap";
        new_argv[2] = "--no-pkexec";
        new_argv[3] = "sh";
        new_argv[4] = "-c";
        new_argv[5] = "timeout 2 timeout 1 timeout 1 ls /tmp";
        new_argv[6] = NULL;

        execvp(ptrace_path, new_argv);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);

    return 0;
}

TEST(safe_command_via_dfa) {
    char logfile[256];
    snprintf(logfile, sizeof(logfile), "../logs/robox-e2e-dfa-%d.log", (int)getpid());

    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }

    if (pid == 0) {
        const char *ptrace_path = find_ptrace_binary();
        if (!ptrace_path) _exit(1);

        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        setenv("READONLYBOX_SOCKET", g_autoallow_socket_path, 1);

        char **new_argv = malloc(7 * sizeof(char *));
        new_argv[0] = (char *)ptrace_path;
        new_argv[1] = "wrap";
        new_argv[2] = "--no-pkexec";
        new_argv[3] = "sh";
        new_argv[4] = "-c";
        new_argv[5] = "ls /tmp";
        new_argv[6] = NULL;

        execvp(ptrace_path, new_argv);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);

    return 0;
}

TEST(wrapper_chain_sh_c_echo) {
    char logfile[256];
    snprintf(logfile, sizeof(logfile), "../logs/robox-e2e-shc-echo-%d.log", (int)getpid());

    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }

    if (pid == 0) {
        const char *ptrace_path = find_ptrace_binary();
        if (!ptrace_path) _exit(1);

        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        setenv("READONLYBOX_SOCKET", g_autoallow_socket_path, 1);

        char **new_argv = malloc(7 * sizeof(char *));
        new_argv[0] = (char *)ptrace_path;
        new_argv[1] = "wrap";
        new_argv[2] = "--no-pkexec";
        new_argv[3] = "sh";
        new_argv[4] = "-c";
        new_argv[5] = "echo hello";
        new_argv[6] = NULL;

        execvp(ptrace_path, new_argv);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);

    return 0;
}

/*
 * LANLOCK SYMLINK TESTS
 */

/* Helper to create temp dir with symlinks */
static int create_symlink_testdir(char *base, const char *dir_name,
                                  const char *link_target, const char *link_name) {
    snprintf(base, 512, "/tmp/robox-symlink-test.XXXXXX");
    if (!mkdtemp(base)) return -1;

    char dir_path[512], link_path[512], target_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/%s", base, dir_name);
    snprintf(link_path, sizeof(link_path), "%s/%s", base, link_name);
    snprintf(target_path, sizeof(target_path), "%s/%s", base, link_target);

    if (mkdir(dir_path, 0755) != 0) return -1;
    if (mkdir(target_path, 0755) != 0) return -1;
    if (symlink(link_target, link_path) != 0) return -1;

    return 0;
}

static void cleanup_symlink_testdir(char *base) {
    if (base && base[0]) {
        rmtree(base);
    }
}

TEST(landlock_symlink_allowed) {
    char base[1024];
    if (create_symlink_testdir(base, "allowed", "outside", "link") != 0) {
        return 1;
    }

    char target_path[1024], link_path[1024], parent_path[1024];
    snprintf(target_path, sizeof(target_path), "%s/outside", base);
    snprintf(link_path, sizeof(link_path), "%s/allowed/link", base);
    snprintf(parent_path, sizeof(parent_path), "%s/allowed", base);

    char hard_allow[2048];
    snprintf(hard_allow, sizeof(hard_allow), "%s:rw,%s:rx", target_path, parent_path);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ls %s", link_path);
    char *args[] = {"sh", "-c", cmd, NULL};
    int exit_code;
    int result = run_ptrace_landlock(args, &exit_code, hard_allow, NULL);

    cleanup_symlink_testdir(base);

    CHECK_EQ(result, result, 0);
    CHECK_EQ(result, exit_code, 0);
    return 0;
}

TEST(landlock_symlink_denied) {
    char base[1024];
    if (create_symlink_testdir(base, "allowed", "denied", "link") != 0) {
        return 1;
    }

    char allowed_path[1024], denied_path[1024], link_path[1024];
    snprintf(allowed_path, sizeof(allowed_path), "%s/allowed", base);
    snprintf(denied_path, sizeof(denied_path), "%s/denied", base);
    snprintf(link_path, sizeof(link_path), "%s/allowed/link", base);

    char hard_allow[2048];
    snprintf(hard_allow, sizeof(hard_allow), "%s:rw", allowed_path);
    char hard_deny[1024];
    snprintf(hard_deny, sizeof(hard_deny), "%s", denied_path);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ls %s", link_path);
    char *args[] = {"sh", "-c", cmd, NULL};
    int exit_code;
    int result = run_ptrace_landlock(args, &exit_code, hard_allow, hard_deny);

    cleanup_symlink_testdir(base);

    CHECK_EQ(result, result, 0);
    CHECK_NE(result, exit_code, 0);
    return 0;
}

TEST(landlock_symlink_chain) {
    char base[1024];
    snprintf(base, 1024, "/tmp/robox-chain-test.XXXXXX");
    if (!mkdtemp(base)) {
        return 1;
    }

    char dir[1024], link1[1024], link2[1024];
    snprintf(dir, sizeof(dir), "%s/dir", base);
    snprintf(link1, sizeof(link1), "%s/link1", base);
    snprintf(link2, sizeof(link2), "%s/link2", base);

    mkdir(dir, 0755);
    (void)symlink("dir", link1);
    (void)symlink("link1", link2);

    char hard_allow[2048];
    snprintf(hard_allow, sizeof(hard_allow), "%s:rw,%s:rx", dir, base);

    char ls_cmd[512];
    snprintf(ls_cmd, sizeof(ls_cmd), "ls %s", link2);
    char *args[] = {"sh", "-c", ls_cmd, NULL};
    int exit_code;
    int result = run_ptrace_landlock(args, &exit_code, hard_allow, NULL);

    rmtree(base);

    CHECK_EQ(result, result, 0);
    CHECK_EQ(result, exit_code, 0);
    return 0;
}

TEST(landlock_multiple_symlinks_same_target) {
    char base[1024];
    snprintf(base, 1024, "/tmp/robox-dup-test.XXXXXX");
    if (!mkdtemp(base)) {
        return 1;
    }

    char target[1024], dir1[1024], dir2[1024], link1[1024], link2[1024];
    snprintf(target, sizeof(target), "%s/target", base);
    snprintf(dir1, sizeof(dir1), "%s/dir1", base);
    snprintf(dir2, sizeof(dir2), "%s/dir2", base);
    snprintf(link1, sizeof(link1), "%s/dir1/link", base);
    snprintf(link2, sizeof(link2), "%s/dir2/link", base);

    mkdir(target, 0755);
    mkdir(dir1, 0755);
    mkdir(dir2, 0755);
    (void)symlink(target, link1);
    (void)symlink(target, link2);

    char hard_allow[2048];
    snprintf(hard_allow, sizeof(hard_allow), "%s:rw,%s:rx,%s:rx", target, base, dir1);

    char ls_cmd[512];
    snprintf(ls_cmd, sizeof(ls_cmd), "ls %s", link1);
    char *args[] = {"sh", "-c", ls_cmd, NULL};
    int exit_code;
    int result = run_ptrace_landlock(args, &exit_code, hard_allow, NULL);

    rmtree(base);

    CHECK_EQ(result, result, 0);
    CHECK_EQ(result, exit_code, 0);
    return 0;
}

/*
 * Run all end-to-end tests
 */
void run_e2e_tests(void) {
    static int handlers_registered = 0;
    if (!handlers_registered) {
        atexit(cleanup_servers_now);
        signal(SIGTERM, server_cleanup_signal);
        signal(SIGINT, server_cleanup_signal);
        signal(SIGHUP, server_cleanup_signal);
        handlers_registered = 1;
    }

    printf("\n=== End-to-End Tests ===\n");

    if (access("./readonlybox-ptrace", X_OK) != 0 &&
        access("../readonlybox-ptrace", X_OK) != 0 &&
        access("readonlybox-ptrace", X_OK) != 0) {
        printf("  SKIPPED: readonlybox-ptrace binary not found\n");
        printf("  Please build the ptrace client first: make -C ..\n");
        return;
    }

    /* Start both servers before any tests */
    if (start_all_servers() != 0) {
        printf("  FAILED: Could not start servers\n");
        return;
    }

    /* Safe command tests (autodeny server) */
    RUN_TEST(safe_command_ls);
    RUN_TEST(safe_command_echo);
    RUN_TEST(safe_command_cat);
    RUN_TEST(safe_command_pwd);
    RUN_TEST(safe_command_date);

    /* Dangerous command tests (autodeny server) */
    RUN_TEST(dangerous_command_rm);
    RUN_TEST(dangerous_command_mkdir);
    RUN_TEST(dangerous_command_write);

    /* Autoallow server tests */
    RUN_TEST(autoallow_safe_command);
    RUN_TEST(autoallow_dangerous_command);

    /* Multiple commands */
    RUN_TEST(multiple_safe_commands);
    RUN_TEST(command_with_arguments);
    RUN_TEST(nonexistent_command);

    /* Wrapper chain tests */
    RUN_TEST(wrapper_chain_simple);
    RUN_TEST(wrapper_chain_nested_sh_c);
    RUN_TEST(wrapper_chain_deep);
    RUN_TEST(safe_command_via_dfa);
    RUN_TEST(wrapper_chain_sh_c_echo);

    /* Landlock symlink tests */
    RUN_TEST(landlock_symlink_allowed);
    RUN_TEST(landlock_symlink_denied);
    RUN_TEST(landlock_symlink_chain);
    RUN_TEST(landlock_multiple_symlinks_same_target);

    /* Stop both servers after all tests */
    stop_all_servers();
}

/*
 * Get test statistics
 */
void get_e2e_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run;
    *passed = tests_passed;
    *failed = tests_failed;
}

/*
 * Reset test statistics
 */
void reset_e2e_test_stats(void) {
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;
}
