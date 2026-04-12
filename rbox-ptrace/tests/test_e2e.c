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

/*
 * Log Reader State - tracks ALLOW/DENY counts from both servers via pipes.
 *
 * Architecture:
 *   Autoallow Server ──pipe1──▶ Log Reader ◀──pipe2─── Autodeny Server
 *                                  │
 *              parent_to_log[1] ──▶│◀── log_to_parent[0]
 *                                  │
 *                              Test Runner
 *
 * The log reader parses machine-readable output (ALLOW:/DENY:) from both
 * servers and maintains counts. Parent sends commands (CHECKPOINT/GET_COUNTS)
 * via pipe, log reader sends responses back via another pipe.
 */
typedef struct {
    int allow_count;      /* Total ALLOW lines seen */
    int deny_count;       /* Total DENY lines seen */
    int checkpoint_allow; /* ALLOW count at last checkpoint */
    int checkpoint_deny;  /* DENY count at last checkpoint */
    int pipe1_fd;         /* Pipe from autoallow server (read end) */
    int pipe2_fd;         /* Pipe from autodeny server (read end) */
    int write_fd1;        /* Pipe1 write end (in parent, for server) */
    int write_fd2;        /* Pipe2 write end (in parent, for server) */
    int parent_to_log[2]; /* Parent to log reader commands */
    int log_to_parent[2]; /* Log reader to parent responses */
    pid_t pid;            /* Log reader process PID */
} LogReaderState;

static LogReaderState g_log_reader = {0};

/* Forward declarations */
static int log_reader_get_counts(int *out_allow, int *out_deny);
static void log_reader_checkpoint(void);

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
 * Log Reader Process - reads ALLOW/DENY lines from server pipes,
 * maintains counts. Parent communicates via pipes.
 *
 * Architecture:
 *   Autoallow Server ──pipe1──▶ Log Reader ◀──pipe2─── Autodeny Server
 *                                  │
 *              parent_to_log[1] ──▶│◀── log_to_parent[0]
 *                                  │
 *                              Test Runner
 *
 * Commands from parent:
 *   CHECKPOINT - save current counts as checkpoint
 *   GET_COUNTS - get counts since last checkpoint, format: "ALLOW:<count> DENY:<count>\n"
 */
static int start_log_reader_process(LogReaderState *state) {
    /* Create pipe1: autoallow stdout → log reader stdin */
    int pipe1[2];
    if (pipe(pipe1) < 0) return -1;
    
    /* Create pipe2: autodeny stdout → log reader */
    int pipe2[2];
    if (pipe(pipe2) < 0) {
        close(pipe1[0]); close(pipe1[1]);
        return -1;
    }
    
    /* Create pipes for parent <-> log reader communication */
    if (pipe(state->parent_to_log) < 0) {
        close(pipe1[0]); close(pipe1[1]);
        close(pipe2[0]); close(pipe2[1]);
        return -1;
    }
    if (pipe(state->log_to_parent) < 0) {
        close(pipe1[0]); close(pipe1[1]);
        close(pipe2[0]); close(pipe2[1]);
        close(state->parent_to_log[0]); close(state->parent_to_log[1]);
        return -1;
    }
    
    /* Fork log reader process */
    pid_t log_pid = fork();
    if (log_pid < 0) {
        close(pipe1[0]); close(pipe1[1]);
        close(pipe2[0]); close(pipe2[1]);
        close(state->parent_to_log[0]); close(state->parent_to_log[1]);
        close(state->log_to_parent[0]); close(state->log_to_parent[1]);
        return -1;
    }
    
    if (log_pid == 0) {
        /* Child: log reader process */
        /* Close unnecessary ends */
        close(pipe1[1]);  /* Close write ends of server pipes */
        close(pipe2[1]);
        close(state->parent_to_log[1]);  /* Close write end of parent->log */
        close(state->log_to_parent[0]);   /* Close read end of log->parent */
        
        /* Set non-blocking on server pipes */
        fcntl(pipe1[0], F_SETFL, O_NONBLOCK);
        fcntl(pipe2[0], F_SETFL, O_NONBLOCK);
        
        /* Initialize counts */
        int allow_count = 0;
        int deny_count = 0;
        int checkpoint_allow = 0;
        int checkpoint_deny = 0;
        
        /* Read loop */
        char line[1024];
        char cmd[64];
        int running = 1;
        int pipe1_eof = 0;
        int pipe2_eof = 0;
        
        while (running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            int max_fd = -1;
            
            if (!pipe1_eof) { FD_SET(pipe1[0], &read_fds); max_fd = (max_fd < pipe1[0]) ? pipe1[0] : max_fd; }
            if (!pipe2_eof) { FD_SET(pipe2[0], &read_fds); max_fd = (max_fd < pipe2[0]) ? pipe2[0] : max_fd; }
            FD_SET(state->parent_to_log[0], &read_fds);  /* Command pipe from parent */
            if (state->parent_to_log[0] > max_fd) max_fd = state->parent_to_log[0];
            
            struct timeval tv = {0, 100000}; /* 100ms timeout */
            int ready = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
            
            if (ready > 0) {
                /* Read from pipe1 (autoallow server) */
                if (!pipe1_eof && FD_ISSET(pipe1[0], &read_fds)) {
                    ssize_t n = read(pipe1[0], line, sizeof(line) - 1);
                    if (n > 0) {
                        line[n] = '\0';
                        /* Count only machine-readable format: ALLOW:command (no space after colon) */
                        char *p = line;
                        while ((p = strstr(p, "ALLOW:"))) {
                            /* Only count if NOT followed by space (verbose has "ALLOW: command") */
                            if (p[6] != ' ') { allow_count++; }
                            p += 6;
                        }
                        p = line;
                        while ((p = strstr(p, "DENY:"))) {
                            /* Only count if NOT followed by space (verbose has "DENY: command") */
                            if (p[5] != ' ') { deny_count++; }
                            p += 5;
                        }
                    } else if (n == 0) {
                        pipe1_eof = 1;
                    }
                }
                
                /* Read from pipe2 (autodeny server) */
                if (!pipe2_eof && FD_ISSET(pipe2[0], &read_fds)) {
                    ssize_t n = read(pipe2[0], line, sizeof(line) - 1);
                    if (n > 0) {
                        line[n] = '\0';
                        /* Count only machine-readable format: DENY:command (no space after colon) */
                        char *p = line;
                        while ((p = strstr(p, "ALLOW:"))) {
                            if (p[6] != ' ') { allow_count++; }
                            p += 6;
                        }
                        p = line;
                        while ((p = strstr(p, "DENY:"))) {
                            if (p[5] != ' ') { deny_count++; }
                            p += 5;
                        }
                    } else if (n == 0) {
                        pipe2_eof = 1;
                    }
                }
                
                /* Read command from parent */
                if (FD_ISSET(state->parent_to_log[0], &read_fds)) {
                    ssize_t n = read(state->parent_to_log[0], cmd, sizeof(cmd) - 1);
                    if (n > 0) {
                        cmd[n] = '\0';
                        /* Remove trailing newline */
                        char *nl = strchr(cmd, '\n');
                        if (nl) *nl = '\0';
                        
                        if (strcmp(cmd, "CHECKPOINT") == 0) {
                            checkpoint_allow = allow_count;
                            checkpoint_deny = deny_count;
                            /* Respond */
                            write(state->log_to_parent[1], "OK\n", 3);
                        } else if (strcmp(cmd, "GET_COUNTS") == 0) {
                            char resp[64];
                            int delta_allow = allow_count - checkpoint_allow;
                            int delta_deny = deny_count - checkpoint_deny;
                            snprintf(resp, sizeof(resp), "ALLOW:%d DENY:%d\n", delta_allow, delta_deny);
                            write(state->log_to_parent[1], resp, strlen(resp));
                        }
                    }
                }
            }
            
            /* Exit when both server pipes are EOF and no more commands expected */
            if (pipe1_eof && pipe2_eof) {
                /* Check if parent closed command pipe */
                fd_set test_fds;
                FD_ZERO(&test_fds);
                FD_SET(state->parent_to_log[0], &test_fds);
                struct timeval ttv = {0, 0};
                if (select(state->parent_to_log[0] + 1, &test_fds, NULL, NULL, &ttv) == 0) {
                    /* No data available, parent likely closed */
                    running = 0;
                }
            }
        }
        
        close(pipe1[0]);
        close(pipe2[0]);
        close(state->parent_to_log[0]);
        close(state->log_to_parent[1]);
        _exit(0);
    }
    
    /* Parent */
    state->pid = log_pid;
    state->pipe1_fd = pipe1[0];
    state->pipe2_fd = pipe2[0];
    state->write_fd1 = pipe1[1];
    state->write_fd2 = pipe2[1];
    
    /* Close child ends in parent */
    close(pipe1[0]);
    close(pipe2[0]);
    close(state->parent_to_log[0]);  /* Close read end of parent->log */
    close(state->log_to_parent[1]); /* Close write end of log->parent */
    
    return 0;
}

/* Start both servers (autodeny and autoallow) with log reader */
static int start_all_servers(void) {
    /*
     * Setup: Start a SINGLE autoallow and SINGLE autodeny server for the
     * entire test suite. Both servers output machine-readable logs via
     * pipes to a log reader process.
     *
     * Set TEST_DIR so that test commands like 'noop' can be found in PATH.
     */
    {
        char test_dir[512];
        /* Get the directory where the test binary is located */
        snprintf(test_dir, sizeof(test_dir), "%s", getcwd(NULL, 0));
        setenv("TEST_DIR", test_dir, 1);
        fprintf(stderr, "DEBUG: TEST_DIR=%s\n", test_dir);
    }
    
    /*
     *
     * Architecture:
     *   Autoallow Server ──pipe1──▶ Log Reader ◀──pipe2─── Autodeny Server
     *                                                    │
     *                              Test Runner ◀──socket─┘
     *
     * The log reader parses ALLOW/DENY lines from both servers and maintains
     * counts. Tests query the log reader via Unix socket to get counts.
     */
    
    /* Start log reader process first */
    if (start_log_reader_process(&g_log_reader) < 0) {
        fprintf(stderr, "DEBUG: failed to start log reader\n");
        return -1;
    }
    
    /* Generate socket paths */
    snprintf(g_autodeny_socket_path, sizeof(g_autodeny_socket_path),
             "/tmp/robox-test-autodeny-%d.sock", (int)getpid());
    snprintf(g_autoallow_socket_path, sizeof(g_autoallow_socket_path),
             "/tmp/robox-test-autoallow-%d.sock", (int)getpid());
    
    /* Fork autodeny server - stdout/stderr goes to pipe2 (log reader) */
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
        
        /* Redirect stdout and stderr to pipe2 write end */
        dup2(g_log_reader.write_fd2, STDOUT_FILENO);
        dup2(g_log_reader.write_fd2, STDERR_FILENO);
        close(g_log_reader.write_fd2);
        close(g_log_reader.write_fd1);  /* Don't use pipe1 */
        
        execl(server_path, server_path, "-q", "-socket", g_autodeny_socket_path, "--auto-deny", "--log-reader", NULL);
        perror("DEBUG: autodeny execl failed");
        _exit(1);
    }
    
    g_autodeny_server_pid = pid;
    
    /* Fork autoallow server - stdout/stderr goes to pipe1 (log reader) */
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
        
        /* Redirect stdout and stderr to pipe1 write end */
        dup2(g_log_reader.write_fd1, STDOUT_FILENO);
        dup2(g_log_reader.write_fd1, STDERR_FILENO);
        close(g_log_reader.write_fd1);
        close(g_log_reader.write_fd2);  /* Don't use pipe2 */
        
        execl(server_path, server_path, "-vv", "-socket", g_autoallow_socket_path, "--log-reader", NULL);
        perror("DEBUG: autoallow execl failed");
        _exit(1);
    }
    
    g_autoallow_server_pid = pid;
    
    /* Close parent's pipe write ends - servers have them now */
    close(g_log_reader.write_fd1);
    close(g_log_reader.write_fd2);
    
    /* Wait for both sockets to be created */
    for (int i = 0; i < 50; i++) {
        if (access(g_autodeny_socket_path, F_OK) == 0 &&
            access(g_autoallow_socket_path, F_OK) == 0) break;
        usleep(100000);
    }
    
    fprintf(stderr, "DEBUG: autodeny socket: %s (%s)\n",
            g_autodeny_socket_path,
            (access(g_autodeny_socket_path, F_OK) == 0) ? "OK" : "FAILED");
    fprintf(stderr, "DEBUG: autoallow socket: %s (%s)\n",
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
    if (g_log_reader.pid > 0) {
        kill(g_log_reader.pid, SIGTERM);
        waitpid(g_log_reader.pid, NULL, 0);
        g_log_reader.pid = 0;
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
        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

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

        /* Close log reader pipes in child to avoid interference with exec */
        if (g_log_reader.parent_to_log[0] > 0) close(g_log_reader.parent_to_log[0]);
        if (g_log_reader.parent_to_log[1] > 0) close(g_log_reader.parent_to_log[1]);
        if (g_log_reader.log_to_parent[0] > 0) close(g_log_reader.log_to_parent[0]);
        if (g_log_reader.log_to_parent[1] > 0) close(g_log_reader.log_to_parent[1]);

        char **new_argv = malloc((arg_count + 5) * sizeof(char *));
        new_argv[0] = (char *)ptrace_path;
        new_argv[1] = "--no-pkexec";
        new_argv[2] = "sh";
        new_argv[3] = "-c";
        for (int i = 0; i < arg_count; i++) {
            new_argv[i + 4] = argv[i];
        }
        new_argv[arg_count + 4] = NULL;

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
 * Log Reader Query Functions
 * 
 * The log reader process tracks ALLOW/DENY counts from both servers.
 * Tests should:
 *   1. Call log_reader_checkpoint() BEFORE running a command
 *   2. Run the command via run_ptrace_autoallow()
 *   3. Call log_reader_get_counts() to get counts since checkpoint
 */
static void log_reader_checkpoint(void) {
    /* Send CHECKPOINT command to log reader */
    write(g_log_reader.parent_to_log[1], "CHECKPOINT\n", 11);
    /* Read response */
    char resp[64];
    read(g_log_reader.log_to_parent[0], resp, sizeof(resp));
}

static int log_reader_get_counts(int *out_allow, int *out_deny) {
    /* Send GET_COUNTS command to log reader */
    write(g_log_reader.parent_to_log[1], "GET_COUNTS\n", 12);
    /* Read response: "ALLOW:<count> DENY:<count>\n" */
    char resp[64];
    ssize_t n = read(g_log_reader.log_to_parent[0], resp, sizeof(resp));
    if (n > 0) {
        resp[n] = '\0';
        sscanf(resp, "ALLOW:%d DENY:%d", out_allow, out_deny);
    }
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
static int run_and_check(const char *cmd, int expected_exit, int expected_requests) {
    /* run_ptrace_impl now always adds sh -c wrapper, so just pass the raw command */
    char *args[] = {(char*)cmd, NULL};
    int exit_code;
    int allow_count, deny_count;

    /* CHECKPOINT: mark current position in log reader before running command */
    log_reader_checkpoint();
    
    if (run_ptrace_autoallow(args, &exit_code) != 0) {
        return 1;
    }
    
    /* GET_COUNTS: get delta since checkpoint */
    log_reader_get_counts(&allow_count, &deny_count);
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
    return run_and_check("timeout 1 sh noop", 0, 1);
}

TEST(wrapper_chain_nested) {
    /* timeout 1 timeout 1 sh noop : wrappers stripped, sh noop is actual - 1 request */
    return run_and_check("timeout 1 timeout 1 sh noop", 0, 1);
}

TEST(wrapper_chain_sh_c_single_quotes) {
    /* sh -c 'sh noop' : sh wrapper stripped, sh noop is actual command - 1 request */
    return run_and_check("sh -c 'sh noop'", 0, 1);
}

TEST(wrapper_chain_sh_c_double_quotes) {
    return run_and_check("sh -c \"sh noop\"", 0, 1);
}

TEST(wrapper_chain_multiple_subcommands) {
    /* sh -c 'sh noop; sh noop' : full command sent once, inner commands auto-granted - 1 request */
    return run_and_check("sh -c 'sh noop; sh noop'", 0, 1);
}

TEST(wrapper_chain_no_wrapper) {
    /* sh noop exists, not DFA autoallowed - 1 request */
    return run_and_check("sh noop", 0, 1);
}

TEST(wrapper_chain_unknown_wrapper) {
    /* bash -c 'sh noop' : sh (wrapper) + bash (wrapper) = 2 requests */
    return run_and_check("bash -c 'sh noop'", 0, 2);
}

TEST(wrapper_chain_deep_nesting) {
    /* timeout 1 sh -c 'timeout 1 sh noop' : wrappers stripped, sh noop runs - 1 request */
    return run_and_check("timeout 1 sh -c 'timeout 1 sh noop'", 0, 1);
}

/*
 * ============================================================================
 * ADVANCED ALLOWANCE TESTS
 * ============================================================================
 */

/* Test that a subcommand can be run twice (two identical entries) and both
 * succeed without extra server requests. */
TEST(wrapper_chain_duplicate_subcommand) {
    /* sh -c 'sh noop; sh noop' : full command sent once, inner commands auto-granted - 1 request */
    return run_and_check("sh -c 'sh noop; sh noop'", 0, 1);
}

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

    log_reader_checkpoint();
    if (run_ptrace_autoallow(args, &exit_code) != 0) return 1;
    if (exit_code != 0) return 1;
    log_reader_get_counts(&allow_count, &deny_count);
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
    return run_and_check("timeout 1 sh -c 'sh noop; sh noop'", 0, 1);
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

    log_reader_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    log_reader_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    CHECK_EQ(result, req_count, 0);
    return result;
}

TEST(safe_command_echo) {
    int result = 0;
    char *args[] = {"echo hello", NULL};
    int exit_code;
    int allow_count, deny_count;

    log_reader_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    log_reader_get_counts(&allow_count, &deny_count);
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

    log_reader_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    log_reader_get_counts(&allow_count, &deny_count);
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

    log_reader_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    log_reader_get_counts(&allow_count, &deny_count);
    int req_count = allow_count + deny_count;
    CHECK_EQ(result, req_count, 0);
    return result;
}

TEST(safe_command_date) {
    int result = 0;
    char *args[] = {"date", NULL};
    int exit_code;
    int allow_count, deny_count;

    log_reader_checkpoint();
    CHECK_EQ(result, run_ptrace_autodeny(args, &exit_code), 0);
    CHECK_EQ(result, exit_code, 0);
    log_reader_get_counts(&allow_count, &deny_count);
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
    log_reader_checkpoint();
    if (run_ptrace_autoallow(args, &exit_code) != 0) return 1;
    /* sh noop should succeed */
    if (exit_code != 0) return 1;
    log_reader_get_counts(&allow_count, &deny_count);
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
    log_reader_checkpoint();
    if (run_ptrace_autoallow(args, &exit_code) != 0) return 1;
    /* The server should allow it, so exit code 0 */
    if (exit_code != 0) return 1;
    log_reader_get_counts(&allow_count, &deny_count);
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
