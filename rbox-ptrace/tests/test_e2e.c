/*
 * test_e2e.c - End-to-end tests for ptrace client
 *
 * These tests run actual commands wrapped in the ptrace client
 * and verify the behavior with the server in different modes.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test macro */
#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  Running %s... ", #name); \
    fflush(stdout); \
    tests_run++; \
    test_##name(); \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAILED\n    Assertion failed: %s at line %d\n", #cond, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define SKIP_IF_NO_SERVER do { \
    if (access("./readonlybox-server", X_OK) != 0 && \
        access("../readonlybox-server/readonlybox-server", X_OK) != 0 && \
        access("readonlybox-server", X_OK) != 0) { \
        printf("SKIPPED: server binary not found\n"); \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Server process info */
typedef struct {
    pid_t pid;
    int auto_deny;
    int debug_tui;
    char *logfile;  /* If set, redirect output to this file */
} ServerInfo;

/* Start the readonlybox-server in headless mode */
static int start_server(ServerInfo *info) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        /* Child process - start server */
        /* Find server binary */
        const char *server_path = "./readonlybox-server";
        if (access(server_path, X_OK) != 0) {
            server_path = "../readonlybox-server/readonlybox-server";
            if (access(server_path, X_OK) != 0) {
                server_path = "readonlybox-server";
            }
        }

        /* Build arguments */
        char *args[10];
        int arg_idx = 0;
        args[arg_idx++] = (char *)server_path;
        args[arg_idx++] = "-q";  /* Quiet mode */

        if (info->auto_deny) {
            args[arg_idx++] = "-auto-deny";
        }
        if (info->debug_tui) {
            args[arg_idx++] = "-debug-tui";
            args[arg_idx++] = "-v";  /* verbose for logging */
        }

        args[arg_idx] = NULL;

        /* Redirect output to logfile or /dev/null */
        if (info->logfile) {
            FILE *f = fopen(info->logfile, "w");
            if (f) {
                dup2(fileno(f), STDOUT_FILENO);
                dup2(fileno(f), STDERR_FILENO);
                fclose(f);
            }
        } else {
            int dev_null = open("/dev/null", O_WRONLY);
            if (dev_null >= 0) {
                dup2(dev_null, STDOUT_FILENO);
                dup2(dev_null, STDERR_FILENO);
                close(dev_null);
            }
        }

        execvp(server_path, args);
        _exit(1);  /* If exec fails */
    }

    /* Parent - save PID and wait for server to start */
    info->pid = pid;
    usleep(500000);  /* Wait 500ms for server to start */
    return 0;
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

/* Stop the server */
static void stop_server(ServerInfo *info) {
    if (info->pid > 0) {
        kill(info->pid, SIGTERM);
        waitpid(info->pid, NULL, 0);
        info->pid = 0;
    }
}

/* Run a command through the ptrace client */
static int run_ptrace_command(const char *cmd, char *const argv[], int *exit_code) {
    /* Find ptrace client binary */
    const char *ptrace_path = "./readonlybox-ptrace";
    if (access(ptrace_path, X_OK) != 0) {
        ptrace_path = "../readonlybox-ptrace";
        if (access(ptrace_path, X_OK) != 0) {
            ptrace_path = "readonlybox-ptrace";
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        /* Child - run ptrace client */
        /* Build arguments: readonlybox-ptrace wrap --no-pkexec <cmd> [args...] */
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
        _exit(127);  /* Command not found */
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

/*
 * Test safe command (ls) with auto-deny server
 * Safe commands should be allowed by DFA without contacting server
 */
TEST(safe_command_ls_auto_deny) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run ls - should succeed (allowed by DFA) */
    char *args[] = {"ls", "/tmp", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("ls", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
}

/*
 * Test safe command (echo) with auto-deny server
 */
TEST(safe_command_echo_auto_deny) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run echo - should succeed (allowed by DFA) */
    char *args[] = {"echo", "hello", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("echo", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
}

/*
 * Test safe command (cat) with auto-deny server
 */
TEST(safe_command_cat_auto_deny) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Create a test file */
    FILE *f = fopen("/tmp/test_e2e_cat.txt", "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "test content\n");
    fclose(f);

    /* Run cat - should succeed (allowed by DFA) */
    char *args[] = {"cat", "/tmp/test_e2e_cat.txt", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("cat", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    /* Cleanup */
    unlink("/tmp/test_e2e_cat.txt");
    stop_server(&server);
}

/*
 * Test safe command (pwd) with auto-deny server
 */
TEST(safe_command_pwd_auto_deny) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run pwd - should succeed (allowed by DFA) */
    char *args[] = {"pwd", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("pwd", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
}

/*
 * Test safe command (date) with auto-deny server
 */
TEST(safe_command_date_auto_deny) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run date - should succeed (allowed by DFA) */
    char *args[] = {"date", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("date", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
}

/*
 * Test dangerous command (rm) with auto-deny server
 * Should be denied by server
 */
TEST(dangerous_command_rm_auto_deny) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Create a test file */
    FILE *f = fopen("/tmp/test_e2e_rm.txt", "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "test content\n");
    fclose(f);

    /* Run rm - should fail (denied by server) */
    char *args[] = {"rm", "/tmp/test_e2e_rm.txt", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("rm", args, &exit_code), 0);
    ASSERT_NE(exit_code, 0);  /* Should fail */

    /* Verify file still exists (wasn't deleted) */
    ASSERT_EQ(access("/tmp/test_e2e_rm.txt", F_OK), 0);

    /* Cleanup */
    unlink("/tmp/test_e2e_rm.txt");
    stop_server(&server);
}

/*
 * Test dangerous command (mkdir) with auto-deny server
 */
TEST(dangerous_command_mkdir_auto_deny) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run mkdir - should fail (denied by server) */
    char *args[] = {"mkdir", "/tmp/test_e2e_mkdir_dir", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("mkdir", args, &exit_code), 0);
    ASSERT_NE(exit_code, 0);  /* Should fail */

    /* Verify directory wasn't created */
    ASSERT_NE(access("/tmp/test_e2e_mkdir_dir", F_OK), 0);

    stop_server(&server);
}

/*
 * Test write operation with auto-deny server
 * Should be denied by server
 */
TEST(write_operation_auto_deny) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run echo with redirection - should fail (write operation) */
    char *args[] = {"sh", "-c", "echo 'test' > /tmp/test_e2e_write.txt", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("sh", args, &exit_code), 0);
    ASSERT_NE(exit_code, 0);  /* Should fail */

    /* Verify file wasn't created */
    ASSERT_NE(access("/tmp/test_e2e_write.txt", F_OK), 0);

    stop_server(&server);
}

/*
 * Test safe command with debug-tui (auto-allow) server
 */
TEST(safe_command_with_debug_tui) {
    ServerInfo server = {0, .debug_tui = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run ls - should succeed */
    char *args[] = {"ls", "/tmp", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("ls", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
}

/*
 * Test multiple safe commands in sequence
 */
TEST(multiple_safe_commands) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run multiple safe commands */
    char *args1[] = {"pwd", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("pwd", args1, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    char *args2[] = {"echo", "test", NULL};
    ASSERT_EQ(run_ptrace_command("echo", args2, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    char *args3[] = {"date", NULL};
    ASSERT_EQ(run_ptrace_command("date", args3, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
}

/*
 * Test command with arguments
 */
TEST(command_with_arguments) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run ls with multiple arguments */
    char *args[] = {"ls", "-la", "/tmp", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("ls", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
}

/*
 * Test non-existent command
 */
TEST(nonexistent_command) {
    ServerInfo server = {0, .auto_deny = 1};
    ASSERT_EQ(start_server(&server), 0);

    /* Run non-existent command - should fail with command not found */
    char *args[] = {"nonexistent_command_xyz", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("nonexistent_command_xyz", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 127);  /* Command not found */

    stop_server(&server);
}

/*
 * Test simple wrapper chain: timeout 2 ls
 * Should result in 1 server request (for timeout 2 ls), then ls allowed via chain.
 */
TEST(wrapper_chain_simple) {
    char logfile[] = "/tmp/robox-e2e-wrapper-simple.log.XXXXXX";
    int fd = mkstemp(logfile);
    close(fd);

    ServerInfo server = {0, .debug_tui = 1, .logfile = logfile};
    ASSERT_EQ(start_server(&server), 0);

    char *args[] = {"timeout", "2", "ls", "/tmp", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("timeout", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
    int reqs = count_server_requests(logfile);
    unlink(logfile);
    ASSERT_EQ(reqs, 1);
}

/*
 * Test nested wrapper chain: timeout 2 sh -c 'timeout 1 ls'
 * Should result in 1 server request for the initial command.
 */
TEST(wrapper_chain_nested_sh_c) {
    char logfile[] = "/tmp/robox-e2e-wrapper-nested.log.XXXXXX";
    int fd = mkstemp(logfile);
    close(fd);

    ServerInfo server = {0, .debug_tui = 1, .logfile = logfile};
    ASSERT_EQ(start_server(&server), 0);

    char *args[] = {"timeout", "2", "sh", "-c", "timeout 1 ls /tmp", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("timeout", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
    int reqs = count_server_requests(logfile);
    unlink(logfile);
    ASSERT_EQ(reqs, 1);
}

/*
 * Test deep nested wrapper chain: timeout 2 timeout 1 timeout 1 ls
 * Should result in 1 server request.
 */
TEST(wrapper_chain_deep) {
    char logfile[] = "/tmp/robox-e2e-wrapper-deep.log.XXXXXX";
    int fd = mkstemp(logfile);
    close(fd);

    ServerInfo server = {0, .debug_tui = 1, .logfile = logfile};
    ASSERT_EQ(start_server(&server), 0);

    char *args[] = {"timeout", "2", "timeout", "1", "timeout", "1", "ls", "/tmp", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("timeout", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
    int reqs = count_server_requests(logfile);
    unlink(logfile);
    ASSERT_EQ(reqs, 1);
}

/*
 * Test safe command via DFA - should result in 0 server requests.
 */
TEST(safe_command_via_dfa) {
    char logfile[] = "/tmp/robox-e2e-dfa.log.XXXXXX";
    int fd = mkstemp(logfile);
    close(fd);

    ServerInfo server = {0, .debug_tui = 1, .logfile = logfile};
    ASSERT_EQ(start_server(&server), 0);

    char *args[] = {"ls", "/tmp", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("ls", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
    int reqs = count_server_requests(logfile);
    unlink(logfile);
    ASSERT_EQ(reqs, 0);
}

/*
 * Test sh -c with echo (wrapper chain)
 * Should result in 1 server request.
 */
TEST(wrapper_chain_sh_c_echo) {
    char logfile[] = "/tmp/robox-e2e-shc-echo.log.XXXXXX";
    int fd = mkstemp(logfile);
    close(fd);

    ServerInfo server = {0, .debug_tui = 1, .logfile = logfile};
    ASSERT_EQ(start_server(&server), 0);

    char *args[] = {"sh", "-c", "echo hello", NULL};
    int exit_code;
    ASSERT_EQ(run_ptrace_command("sh", args, &exit_code), 0);
    ASSERT_EQ(exit_code, 0);

    stop_server(&server);
    int reqs = count_server_requests(logfile);
    unlink(logfile);
    ASSERT_EQ(reqs, 1);
}

/*
 * Run all end-to-end tests
 */
void run_e2e_tests(void) {
    printf("\n=== End-to-End Tests ===\n");

    /* Check if binaries exist */
    if (access("./readonlybox-ptrace", X_OK) != 0 &&
        access("../readonlybox-ptrace", X_OK) != 0 &&
        access("readonlybox-ptrace", X_OK) != 0) {
        printf("  SKIPPED: readonlybox-ptrace binary not found\n");
        printf("  Please build the ptrace client first: make -C ..\n");
        return;
    }

    RUN_TEST(safe_command_ls_auto_deny);
    RUN_TEST(safe_command_echo_auto_deny);
    RUN_TEST(safe_command_cat_auto_deny);
    RUN_TEST(safe_command_pwd_auto_deny);
    RUN_TEST(safe_command_date_auto_deny);
    RUN_TEST(dangerous_command_rm_auto_deny);
    RUN_TEST(dangerous_command_mkdir_auto_deny);
    RUN_TEST(write_operation_auto_deny);
    RUN_TEST(safe_command_with_debug_tui);
    RUN_TEST(multiple_safe_commands);
    RUN_TEST(command_with_arguments);
    RUN_TEST(nonexistent_command);

    /* Wrapper chain tests */
    RUN_TEST(wrapper_chain_simple);
    RUN_TEST(wrapper_chain_nested_sh_c);
    RUN_TEST(wrapper_chain_deep);
    RUN_TEST(safe_command_via_dfa);
    RUN_TEST(wrapper_chain_sh_c_echo);
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
