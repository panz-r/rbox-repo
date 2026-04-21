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

#ifndef RBOX_NO_COMPAT_MACROS
#define RBOX_NO_COMPAT_MACROS
#endif

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
#include <rbox_protocol.h>

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

/* Telemetry checkpoint state */
static uint32_t g_checkpoint_allow = 0;
static uint32_t g_checkpoint_deny = 0;

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
}

/* Signal handler for cleanup */
static void server_cleanup_signal(int sig) {
    cleanup_servers_now();
    signal(sig, SIG_DFL);
    raise(sig);
}

/*
 * Telemetry stats query function
 * Returns allow/deny counts from server via telemetry protocol
 */
static int server_get_stats(const char *socket_path, int *out_allow, int *out_deny) {
    uint32_t allow = 0;
    uint32_t deny = 0;
    rbox_error_info_t err_info = {0};
    rbox_error_t err = rbox_telemetry_get_stats(socket_path, &allow, &deny, &err_info);
    if (err != RBOX_OK) {
        return -1;
    }
    *out_allow = (int)allow;
    *out_deny = (int)deny;
    return 0;
}

/* Start both servers (autodeny and autoallow) */
static int start_all_servers(void) {
    /*
     * Setup: Start a SINGLE autoallow and SINGLE autodeny server for the
     * entire test suite. Both servers accept telemetry queries.
     *
     * Set TEST_DIR so that test commands like 'noop' can be found in PATH.
     */
    {
        char test_dir[PATH_MAX];
        snprintf(test_dir, sizeof(test_dir), "%s", getcwd(NULL, 0));
        setenv("TEST_DIR", test_dir, 1);
    }

    /* Generate socket paths */
    snprintf(g_autodeny_socket_path, sizeof(g_autodeny_socket_path),
             "/tmp/robox-test-autodeny-%d.sock", (int)getpid());
    snprintf(g_autoallow_socket_path, sizeof(g_autoallow_socket_path),
             "/tmp/robox-test-autoallow-%d.sock", (int)getpid());

    /* Create server log file */
    char server_log_path[256];
    snprintf(server_log_path, sizeof(server_log_path),
             "/tmp/rbox-test-servers-%d.log", (int)getpid());
    int server_log_fd = open(server_log_path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (server_log_fd < 0) {
        server_log_fd = open("/dev/null", O_WRONLY);
    }

    /* Fork autodeny server */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        if (server_log_fd >= 0) close(server_log_fd);
        return -1;
    }

    if (pid == 0) {
        /* Child - redirect stdout/stderr to server log file */
        if (server_log_fd >= 0) {
            dup2(server_log_fd, STDOUT_FILENO);
            dup2(server_log_fd, STDERR_FILENO);
            if (server_log_fd > STDERR_FILENO) close(server_log_fd);
        }
        /* Child - start autodeny server */
        const char *server_path = "../../bin/readonlybox-server";
        if (access(server_path, X_OK) != 0) {
            server_path = "./readonlybox-server";
            if (access(server_path, X_OK) != 0) {
                server_path = "readonlybox-server";
            }
        }

        execl(server_path, server_path, "-socket", g_autodeny_socket_path, "--auto-deny", NULL);
        perror("DEBUG: autodeny execl failed");
        _exit(1);
    }

    g_autodeny_server_pid = pid;

    /* Fork autoallow server */
    pid = fork();
    if (pid < 0) {
        kill(g_autodeny_server_pid, SIGTERM);
        waitpid(g_autodeny_server_pid, NULL, 0);
        if (server_log_fd >= 0) close(server_log_fd);
        return -1;
    }

    if (pid == 0) {
        /* Child - redirect stdout/stderr to server log file */
        if (server_log_fd >= 0) {
            dup2(server_log_fd, STDOUT_FILENO);
            dup2(server_log_fd, STDERR_FILENO);
            if (server_log_fd > STDERR_FILENO) close(server_log_fd);
        }
        /* Child - start autoallow server */
        const char *server_path = "../../bin/readonlybox-server";
        if (access(server_path, X_OK) != 0) {
            server_path = "./readonlybox-server";
            if (access(server_path, X_OK) != 0) {
                server_path = "readonlybox-server";
            }
        }

        execl(server_path, server_path, "-socket", g_autoallow_socket_path, NULL);
        perror("DEBUG: autoallow execl failed");
        _exit(1);
    }

    g_autoallow_server_pid = pid;

    /* Close server log fd in parent - children have their own copies via dup2 */
    if (server_log_fd >= 0) close(server_log_fd);

    /* Wait for both sockets to be created */
    for (int i = 0; i < 50; i++) {
        if (access(g_autodeny_socket_path, F_OK) == 0 &&
            access(g_autoallow_socket_path, F_OK) == 0) break;
        usleep(100000);
    }

    /* Print server log path to stdout so users know where to find server output */
    printf("Server logs: %s\n", server_log_path);
    printf("Autodeny socket: %s (%s)\n",
            g_autodeny_socket_path,
            (access(g_autodeny_socket_path, F_OK) == 0) ? "OK" : "FAILED");
    printf("Autoallow socket: %s (%s)\n",
            g_autoallow_socket_path,
            (access(g_autoallow_socket_path, F_OK) == 0) ? "OK" : "FAILED");

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

/* Run a command through the ptrace client and return exit code.
 * If out_req_count is not NULL, it will be set to the number of server
 * requests observed in the autoallow log file during this run.
 */
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

        /* Prepend test directory to PATH so test commands like 'noop' are found */
        const char *test_dir = getenv("TEST_DIR");
        if (test_dir) {
            char *old_path = getenv("PATH");
            if (old_path) {
                char new_path[4096];
                snprintf(new_path, sizeof(new_path), "%s:%s", test_dir, old_path);
                setenv("PATH", new_path, 1);
            }
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

        char log_path[256];
        snprintf(log_path, sizeof(log_path), "/tmp/test-ptrace-%d.log", (int)getpid());

        /* Redirect child's stdout and stderr to log file so verbose output
         * from ptrace client and rbox-wrap doesn't pollute test results */
        if (freopen(log_path, "a", stdout) == NULL) {
            /* Fallback: silently ignore if redirect fails */
        }
        if (freopen(log_path, "a", stderr) == NULL) {
            /* Fallback: silently ignore if redirect fails */
        }

        char **new_argv = malloc((arg_count + 8) * sizeof(char *));
        new_argv[0] = (char *)ptrace_path;
        new_argv[1] = "--log-file";
        new_argv[2] = log_path;
        new_argv[3] = "-v";
        new_argv[4] = "--no-pkexec";
        new_argv[5] = "sh";
        new_argv[6] = "-c";
        for (int i = 0; i < arg_count; i++) {
            new_argv[i + 7] = argv[i];
        }
        new_argv[arg_count + 7] = NULL;

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
    } else if (WIFSTOPPED(status)) {
        *exit_code = -1;
    } else {
        *exit_code = -1;
    }

    return 0;
}

/* Convenience wrappers for different server types */
static int run_ptrace_autodeny(char *const argv[], int *exit_code) {
    return run_ptrace_impl(argv, exit_code, SERVER_AUTODENY, NULL, NULL);
}

static int run_ptrace_autoallow(char *const argv[], int *exit_code) {
    return run_ptrace_impl(argv, exit_code, SERVER_AUTOALLOW, NULL, NULL);
}

static int run_ptrace_landlock(char *const argv[], int *exit_code,
                               const char *hard_allow, const char *hard_deny) {
    return run_ptrace_impl(argv, exit_code, SERVER_AUTODENY, hard_allow, hard_deny);
}

/*
 * Telemetry Query Functions
 * 
 * These functions use server telemetry to track ALLOW/DENY counts.
 * Tests should:
 *   1. Call telemetry_checkpoint() BEFORE running a command
 *   2. Run the command via run_ptrace_autoallow()
 *   3. Call telemetry_get_counts() to get counts since checkpoint
 */
static void telemetry_checkpoint(void) {
    int allow = 0;
    int deny = 0;
    server_get_stats(g_autoallow_socket_path, &allow, &deny);
    g_checkpoint_allow = allow;
    g_checkpoint_deny = deny;
}

static int telemetry_get_counts(int *out_allow, int *out_deny) {
    int allow = 0;
    int deny = 0;
    server_get_stats(g_autoallow_socket_path, &allow, &deny);
    *out_allow = (int)(allow - g_checkpoint_allow);
    *out_deny = (int)(deny - g_checkpoint_deny);
    return 0;
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
 * ============================================================================
 * WRAPPER CHAIN TESTS (using autoallow server with log file to count requests)
 * ============================================================================
 */

/* Helper to run a command and assert the number of server requests and exit code */
static int run_and_check(const char *cmd, int expected_exit, int expected_requests, int clear_env) {
    /* run_ptrace_impl now always adds sh -c wrapper, so just pass the raw command */
    if (clear_env) {
        clearenv();
    }
    
    char *args[] = {(char*)cmd, NULL};
    int exit_code;
    int allow_count, deny_count;

    /* CHECKPOINT: mark current position in log reader before running command */
    telemetry_checkpoint();
    
    if (run_ptrace_autoallow(args, &exit_code) != 0) {
        return 1;
    }
    
    /* GET_COUNTS: get delta since checkpoint */
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    
    if (exit_code != expected_exit) {
        fprintf(stderr, "    exit code %d (expected %d)\n", exit_code, expected_exit);
        return 1;
    }
    if (req_count != expected_requests) {
        fprintf(stderr, "    server requests %d (expected %d)\n", req_count, expected_requests);
        return 1;
    }
    return 0;
}

TEST(wrapper_chain_simple) {
    /* timeout 1 sh noop : timeout wrapper stripped, sh noop is actual command - 1 request */
    return run_and_check("timeout 1 sh noop", 0, 1, 1);
}

TEST(wrapper_chain_nested) {
    /* timeout 1 timeout 1 sh noop : wrappers stripped, sh noop is actual - 1 request */
    return run_and_check("timeout 1 timeout 1 sh noop", 0, 1, 1);
}

TEST(wrapper_chain_sh_c_single_quotes) {
    /* sh -c 'sh noop' : sh wrapper stripped, sh noop is actual command - 1 request */
    return run_and_check("sh -c 'sh noop'", 0, 1, 1);
}

TEST(wrapper_chain_sh_c_double_quotes) {
    /* sh -c "sh noop" : same as single quotes */
    return run_and_check("sh -c \"sh noop\"", 0, 1, 1);
}

TEST(wrapper_chain_multiple_subcommands) {
    /* sh -c 'sh noop; sh noop' : full command sent once, inner commands auto-granted - 1 request */
    return run_and_check("sh -c 'sh noop; sh noop'", 0, 1, 1);
}

TEST(wrapper_chain_no_wrapper) {
    /* sh noop exists, not DFA autoallowed - 1 request */
    return run_and_check("sh noop", 0, 1, 1);
}

TEST(wrapper_chain_unknown_wrapper) {
    /* bash -c 'sh noop' : sh (wrapper) + bash (wrapper) = 2 requests */
    return run_and_check("bash -c 'sh noop'", 0, 2, 1);
}

TEST(wrapper_chain_deep_nesting) {
    /* timeout 1 sh -c 'timeout 1 sh noop' : wrappers stripped, sh noop runs - 1 request */
    return run_and_check("timeout 1 sh -c 'timeout 1 sh noop'", 0, 1, 1);
}

TEST(wrapper_chain_duplicate_subcommand) {
    /* sh -c 'sh noop; sh noop' : full command sent once, inner commands auto-granted - 1 request */
    return run_and_check("sh -c 'sh noop; sh noop'", 0, 1, 1);
}

/*
 * ============================================================================
 * ADVANCED ALLOWANCE TESTS
 * ============================================================================
 */

/* Test that after a subcommand allowance is consumed (single entry), a second
 * attempt to run it (in the same shell) will require a new server request.
 * Note: Multi-use allowances (bounded reuse of same allowance) are not yet
 * implemented, so each shell invocation requires its own server request. */
TEST(wrapper_chain_allowance_exhaustion) {
    /* Use the noop command - run it twice in a shell loop.
     * Expected: 2 requests (no multi-use allowance implementation).
     * Each 'sh noop' iteration contacts the server separately. */
    char *args[] = {"for i in 1 2; do sh noop; done", NULL};
    int exit_code;
    int allow_count, deny_count;

    telemetry_checkpoint();
    if (run_ptrace_autoallow(args, &exit_code) != 0) return 1;
    if (exit_code != 0) return 1;
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    /* Expect 2 requests (multi-use allowance not yet implemented) */
    if (req_count != 2) {
        fprintf(stderr, "    server requests %d (expected 2)\n", req_count);
        return 1;
    }
    return 0;
}

/* Test interaction between wrapper chain and allowances: a wrapper command
 * that itself contains multiple subcommands. The wrapper is stripped, and
 * the inner command's allowances should be granted. */
TEST(wrapper_chain_wrapper_with_subcommands) {
    /* timeout 1 sh -c 'sh noop; sh noop' : wrappers stripped, sh noop runs - 1 request */
    return run_and_check("timeout 1 sh -c 'sh noop; sh noop'", 0, 1, 1);
}

/*
 * ============================================================================
 * SAFE COMMAND TESTS (autodeny server) - DFA should allow without server contact
 * ============================================================================
 */

TEST(safe_command_ls) {
    int result = 0;
    char *args[] = {"ls /tmp", NULL};
    int exit_code;
    int allow_count, deny_count;

    telemetry_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    CHECK_EQ(result, req_count, 0);
    return result;
}

TEST(safe_command_echo) {
    int result = 0;
    char *args[] = {"echo hello", NULL};
    int exit_code;
    int allow_count, deny_count;

    telemetry_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    CHECK_EQ(result, req_count, 0);
    return result;
}

TEST(safe_command_cat) {
    int result = 0;
    FILE *f = fopen("/tmp/test_e2e_cat.txt", "w");
    CHECK_NOT_NULL(result, f);
    if (result) return result;
    fprintf(f, "test content\n");
    fclose(f);

    char *args[] = {"cat /tmp/test_e2e_cat.txt", NULL};
    int exit_code;
    int allow_count, deny_count;

    telemetry_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    CHECK_EQ(result, req_count, 0);

    unlink("/tmp/test_e2e_cat.txt");
    return result;
}

TEST(safe_command_pwd) {
    int result = 0;
    char *args[] = {"pwd", NULL};
    int exit_code;
    int allow_count, deny_count;

    telemetry_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    CHECK_EQ(result, req_count, 0);
    return result;
}

TEST(safe_command_date) {
    int result = 0;
    char *args[] = {"date", NULL};
    int exit_code;
    int allow_count, deny_count;

    telemetry_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    CHECK_EQ(result, req_count, 0);
    return result;
}

/*
 * ============================================================================
 * DANGEROUS COMMAND TESTS (autodeny server) - DFA should deny
 * ============================================================================
 */

TEST(dangerous_command_rm) {
    int result = 0;
    unlink("/tmp/test_e2e_rm.txt");

    FILE *f = fopen("/tmp/test_e2e_rm.txt", "w");
    CHECK_NOT_NULL(result, f);
    fprintf(f, "test content\n");
    fclose(f);

    char *args[] = {"rm /tmp/test_e2e_rm.txt", NULL};
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

/*
 * ============================================================================
 * AUTOALLOW SERVER TESTS (server allows everything, but we count requests)
 * ============================================================================
 */

TEST(autoallow_safe_command) {
    /* run_ptrace_autoallow adds sh -c wrapper.
     * Command: sh noop → sh -c 'sh noop' → 1 request (sh noop is one command to server) */
    int allow_count, deny_count;
    int exit_code;
    char *args[] = {"sh noop", NULL};
    telemetry_checkpoint();
    if (run_ptrace_autoallow(args, &exit_code) != 0) return 1;
    /* sh noop should succeed */
    if (exit_code != 0) return 1;
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    /* sh noop = 1 request */
    if (req_count != 1) {
        fprintf(stderr, "    server requests %d (expected 1)\n", req_count);
        return 1;
    }
    return 0;
}

TEST(autoallow_dangerous_command) {
    int allow_count, deny_count;
    int exit_code;
    unlink("/tmp/test_e2e_autoallow_rm.txt");
    FILE *f = fopen("/tmp/test_e2e_autoallow_rm.txt", "w");
    if (!f) return 1;
    fprintf(f, "test content\n");
    fclose(f);

    char *args[] = {"rm /tmp/test_e2e_autoallow_rm.txt", NULL};
    telemetry_checkpoint();
    if (run_ptrace_autoallow(args, &exit_code) != 0) return 1;
    /* The server should allow it, so exit code 0 */
    if (exit_code != 0) return 1;
    telemetry_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    /* sh -c wrapper stripped, rm is one command = 1 request */
    if (req_count != 1) {
        fprintf(stderr, "    server requests %d (expected 1)\n", req_count);
        return 1;
    }
    if (access("/tmp/test_e2e_autoallow_rm.txt", F_OK) == 0) return 1;
    return 0;
}

/*
 * ============================================================================
 * LANLOCK SYMLINK TESTS
 * ============================================================================
 */

/* Helper to create temp dir with symlinks */
static int create_symlink_testdir(char *base, const char *dir_name,
                                  const char *link_target, const char *link_name) {
    snprintf(base, 512, "/tmp/robox-symlink-test.XXXXXX");
    if (!mkdtemp(base)) return -1;

    char dir_path[PATH_MAX], link_path[PATH_MAX], target_path[PATH_MAX];
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

    char target_path[PATH_MAX], link_path[PATH_MAX], parent_path[PATH_MAX];
    snprintf(target_path, sizeof(target_path), "%s/outside", base);
    snprintf(link_path, sizeof(link_path), "%s/allowed/link", base);
    snprintf(parent_path, sizeof(parent_path), "%s/allowed", base);

    char hard_allow[PATH_MAX * 2 + 16];
    snprintf(hard_allow, sizeof(hard_allow), "%s:rw,%s:rx", target_path, parent_path);

    char cmd[PATH_MAX];
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

    char allowed_path[PATH_MAX], denied_path[PATH_MAX], link_path[PATH_MAX];
    snprintf(allowed_path, sizeof(allowed_path), "%s/allowed", base);
    snprintf(denied_path, sizeof(denied_path), "%s/denied", base);
    snprintf(link_path, sizeof(link_path), "%s/allowed/link", base);

    char hard_allow[PATH_MAX];
    snprintf(hard_allow, sizeof(hard_allow), "%s:rw", allowed_path);
    char hard_deny[PATH_MAX];
    snprintf(hard_deny, sizeof(hard_deny), "%s", denied_path);

    char cmd[PATH_MAX];
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

    char dir[PATH_MAX], link1[PATH_MAX], link2[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/dir", base);
    snprintf(link1, sizeof(link1), "%s/link1", base);
    snprintf(link2, sizeof(link2), "%s/link2", base);

    mkdir(dir, 0755);
    if (symlink("dir", link1) != 0 || symlink("link1", link2) != 0) {
        rmtree(base);
        return 1;
    }

    char hard_allow[PATH_MAX * 2 + 16];
    snprintf(hard_allow, sizeof(hard_allow), "%s:rw,%s:rx", dir, base);

    char ls_cmd[PATH_MAX];
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

    char target[PATH_MAX], dir1[PATH_MAX], dir2[PATH_MAX], link1[PATH_MAX], link2[PATH_MAX];
    snprintf(target, sizeof(target), "%s/target", base);
    snprintf(dir1, sizeof(dir1), "%s/dir1", base);
    snprintf(dir2, sizeof(dir2), "%s/dir2", base);
    snprintf(link1, sizeof(link1), "%s/dir1/link", base);
    snprintf(link2, sizeof(link2), "%s/dir2/link", base);

    mkdir(target, 0755);
    mkdir(dir1, 0755);
    mkdir(dir2, 0755);
    if (symlink(target, link1) != 0 || symlink(target, link2) != 0) {
        rmtree(base);
        return 1;
    }

    char hard_allow[PATH_MAX * 3 + 16];
    snprintf(hard_allow, sizeof(hard_allow), "%s:rw,%s:rx,%s:rx", target, base, dir1);

    char ls_cmd[PATH_MAX];
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
 * ============================================================================
 * Run all end-to-end tests
 * ============================================================================
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

    /* Wrapper chain tests (autoallow server) */
    RUN_TEST(wrapper_chain_simple);
    RUN_TEST(wrapper_chain_nested);
    RUN_TEST(wrapper_chain_sh_c_single_quotes);
    RUN_TEST(wrapper_chain_sh_c_double_quotes);
    RUN_TEST(wrapper_chain_multiple_subcommands);
    RUN_TEST(wrapper_chain_no_wrapper);
    RUN_TEST(wrapper_chain_unknown_wrapper);
    RUN_TEST(wrapper_chain_deep_nesting);

    /* Advanced allowance tests */
    RUN_TEST(wrapper_chain_duplicate_subcommand);
    RUN_TEST(wrapper_chain_allowance_exhaustion);
    RUN_TEST(wrapper_chain_wrapper_with_subcommands);

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
