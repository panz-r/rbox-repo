/*
 * test_validation.c - Unit tests for validation module
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <setjmp.h>
#include <signal.h>

#include "../validation.h"
#include "../protocol.h"

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test macro */
#define TEST(name) static int test_##name(void)
#define RUN_TEST(name) do { \
    printf("  Running %s... ", #name); \
    fflush(stdout); \
    tests_run++; \
    if (test_##name() == 0) { \
        printf("PASSED\n"); \
        tests_passed++; \
    } else { \
        printf("FAILED\n"); \
        tests_failed++; \
    } \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAILED\n    Assertion failed: %s at line %d\n", #cond, __LINE__); \
        return 1; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)
#define ASSERT_STR_EQ(a, b) ASSERT(strcmp((a), (b)) == 0)

/*
 * Test validation_init
 */
TEST(validation_init_basic) {
    int result = validation_init();
    ASSERT_EQ(result, 0);

    /* Cleanup */
    validation_shutdown();
    return 0;

    return 0;
}

/*
 * Test validation_shutdown without init
 */
TEST(validation_shutdown_no_init) {
    /* Should not crash */
    validation_shutdown();
    ASSERT(1);  /* If we get here, test passed */

    return 0;
}

/*
 * Test validation_init and shutdown cycle
 */
TEST(validation_init_shutdown_cycle) {
    for (int i = 0; i < 5; i++) {
        int result = validation_init();
        ASSERT_EQ(result, 0);
        validation_shutdown();
    
    return 0;
}
    ASSERT(1);  /* If we get here, all cycles passed */
    return 0;
}

TEST(validation_get_socket_path_default) {
    /* Unset XDG_RUNTIME_DIR to test pure default behavior */
    unsetenv("XDG_RUNTIME_DIR");
    validation_init();

    const char *path = validation_get_socket_path();
    ASSERT_NOT_NULL(path);
    ASSERT_STR_EQ(path, "/run/readonlybox/readonlybox.sock");

    validation_shutdown();
    return 0;

    return 0;
}

/*
 * Test validation_get_socket_path with environment variable
 */
TEST(validation_get_socket_path_env) {
    /* Set custom socket path */
    setenv(ROBO_ENV_SOCKET, "/tmp/test_socket.sock", 1);

    validation_init();

    const char *path = validation_get_socket_path();
    ASSERT_NOT_NULL(path);
    ASSERT_STR_EQ(path, "/tmp/test_socket.sock");

    validation_shutdown();

    /* Clean up environment */
    unsetenv(ROBO_ENV_SOCKET);
    return 0;

    return 0;
}

/*
 * Test validation_get_socket_path with --system flag (should override XDG_RUNTIME_DIR)
 */
TEST(validation_get_socket_path_system) {
    /* Set XDG_RUNTIME_DIR to a custom path */
    setenv("XDG_RUNTIME_DIR", "/custom/xdg/path", 1);

    /* Set system mode */
    validation_set_system_mode();

    validation_init();

    const char *path = validation_get_socket_path();
    ASSERT_NOT_NULL(path);
    /* --system should force /run/readonlybox even when XDG_RUNTIME_DIR is set */
    ASSERT_STR_EQ(path, "/run/readonlybox/readonlybox.sock");

    validation_shutdown();

    /* Clean up environment */
    unsetenv("XDG_RUNTIME_DIR");
    return 0;

    return 0;
}

TEST(validation_get_socket_path_user) {
    /* Set XDG_RUNTIME_DIR to a custom path */
    setenv("XDG_RUNTIME_DIR", "/custom/xdg/path", 1);

    /* Set user mode */
    validation_set_user_mode();

    validation_init();

    const char *path = validation_get_socket_path();
    ASSERT_NOT_NULL(path);
    /* --user-socket should use XDG_RUNTIME_DIR when set */
    ASSERT_STR_EQ(path, "/custom/xdg/path/readonlybox.sock");

    validation_shutdown();

    /* Clean up environment */
    unsetenv("XDG_RUNTIME_DIR");

    return 0;
}

/*
 * Test validation_get_socket_path with --user-socket when XDG_RUNTIME_DIR is not set
 */
TEST(validation_get_socket_path_user_no_xdg) {
    /* Ensure XDG_RUNTIME_DIR is not set */
    unsetenv("XDG_RUNTIME_DIR");

    /* Set user mode */
    validation_set_user_mode();

    validation_init();

    const char *path = validation_get_socket_path();
    ASSERT_NOT_NULL(path);
    /* --user-socket should fall back to system path when XDG_RUNTIME_DIR is not set */
    ASSERT_STR_EQ(path, "/run/readonlybox/readonlybox.sock");

    validation_shutdown();

    return 0;
}

/*
 * Test validation_check_dfa with NULL command
 */
TEST(validation_check_dfa_null) {
    validation_init();

    int result = validation_check_dfa(NULL);
    ASSERT_EQ(result, VALIDATION_DENY);

    validation_shutdown();

    return 0;
}

/*
 * Test validation_check_dfa with empty command
 */
TEST(validation_check_dfa_empty) {
    validation_init();

    int result = validation_check_dfa("");
    ASSERT_EQ(result, VALIDATION_DENY);

    validation_shutdown();

    return 0;
}

/*
 * Test validation_check_dfa with simple command
 */
TEST(validation_check_dfa_simple_command) {
    validation_init();

    /* This will depend on the DFA data, but we can test it doesn't crash */
    int result = validation_check_dfa("ls");
    /* Result could be ALLOW, DENY, or ASK depending on DFA */
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    validation_shutdown();

    return 0;
}

/*
 * Test validation_check_dfa with complex command
 */
TEST(validation_check_dfa_complex_command) {
    validation_init();

    /* Test with a more complex command */
    int result = validation_check_dfa("ls -la /tmp");
    /* Result could be ALLOW, DENY, or ASK depending on DFA */
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    validation_shutdown();

    return 0;
}

/*
 * Test validation constants
 */
TEST(validation_constants) {
    ASSERT_EQ(VALIDATION_ALLOW, 0);
    ASSERT_EQ(VALIDATION_DENY, 1);
    ASSERT_EQ(VALIDATION_ASK, 2);

    return 0;
}

/*
 * Test protocol constants
 */
TEST(protocol_constants) {
    ASSERT_EQ(ROBO_MAGIC, 0x524F424F);
    ASSERT_EQ(ROBO_VERSION, 4);
    ASSERT_EQ(ROBO_MSG_LOG, 0);
    ASSERT_EQ(ROBO_MSG_REQ, 1);
    ASSERT_EQ(ROBO_DECISION_UNKNOWN, 0);
    ASSERT_EQ(ROBO_DECISION_ALLOW, 2);
    ASSERT_EQ(ROBO_DECISION_DENY, 3);
    ASSERT_EQ(ROBO_DECISION_ERROR, 4);

    return 0;
}

/*
 * Test protocol limits
 */
TEST(protocol_limits) {
    ASSERT(ROBO_MAX_CMD > 0);
    ASSERT(ROBO_MAX_ARGS > 0);
    ASSERT(ROBO_MAX_ENV > 0);
    ASSERT(ROBO_MAX_PATH > 0);
    ASSERT_EQ(ROBO_MAX_CMD, 4096);
    ASSERT_EQ(ROBO_MAX_ARGS, 128);
    ASSERT_EQ(ROBO_MAX_ENV, 256);
    ASSERT_EQ(ROBO_MAX_PATH, 1024);

    return 0;
}

/*
 * Test default socket path
 */
TEST(default_socket_path) {
    ASSERT_STR_EQ(ROBO_DEFAULT_SOCKET, "/run/readonlybox/readonlybox.sock");

    return 0;
}

/*
 * Test environment variable names
 */
TEST(environment_variable_names) {
    ASSERT_STR_EQ(ROBO_ENV_SOCKET, "READONLYBOX_SOCKET");
    ASSERT_STR_EQ(ROBO_ENV_CALLER, "READONLYBOX_CALLER");
    ASSERT_STR_EQ(ROBO_ENV_SYSCALL, "READONLYBOX_SYSCALL");
    ASSERT_STR_EQ(ROBO_ENV_CWD, "READONLYBOX_CWD");

    return 0;
}

/*
 * Test validation with long command
 */
TEST(validation_check_dfa_long_command) {
    validation_init();

    /* Create a long command */
    char long_cmd[1024];
    strcpy(long_cmd, "echo ");
    for (int i = 0; i < 100; i++) {
        strcat(long_cmd, "a");
    }
    
    int result = validation_check_dfa(long_cmd);
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    validation_shutdown();
    return 0;
}

/*
 * Test validation with command containing special characters
 */
TEST(validation_check_dfa_special_chars) {
    validation_init();

    int result = validation_check_dfa("echo 'hello world'");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    result = validation_check_dfa("echo \"hello world\"");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    result = validation_check_dfa("ls -la; echo done");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    validation_shutdown();

    return 0;
}

/*
 * Test validation with path commands
 */
TEST(validation_check_dfa_path_commands) {
    validation_init();

    int result = validation_check_dfa("/bin/ls");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    result = validation_check_dfa("/usr/bin/cat");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    result = validation_check_dfa("./script.sh");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    validation_shutdown();

    return 0;
}

/*
 * Test validation with piped commands
 */
TEST(validation_check_dfa_piped_commands) {
    validation_init();

    int result = validation_check_dfa("ls | grep test");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    result = validation_check_dfa("cat file | sort | uniq");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    validation_shutdown();

    return 0;
}

/*
 * Test validation with environment variable in command
 */
TEST(validation_check_dfa_env_var) {
    validation_init();

    int result = validation_check_dfa("echo $HOME");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    result = validation_check_dfa("echo ${USER}");
    ASSERT(result == VALIDATION_ALLOW || result == VALIDATION_DENY || result == VALIDATION_ASK);

    validation_shutdown();
    return 0;
}

/*
 * Run all validation tests
 */
void run_validation_tests(void) {
    printf("\n=== Validation Tests ===\n");

    RUN_TEST(validation_init_basic);
    RUN_TEST(validation_shutdown_no_init);
    RUN_TEST(validation_init_shutdown_cycle);
    RUN_TEST(validation_get_socket_path_default);
    RUN_TEST(validation_get_socket_path_env);
    RUN_TEST(validation_get_socket_path_system);
    RUN_TEST(validation_get_socket_path_user);
    RUN_TEST(validation_get_socket_path_user_no_xdg);
    RUN_TEST(validation_check_dfa_null);
    RUN_TEST(validation_check_dfa_empty);
    RUN_TEST(validation_check_dfa_simple_command);
    RUN_TEST(validation_check_dfa_complex_command);
    RUN_TEST(validation_constants);
    RUN_TEST(protocol_constants);
    RUN_TEST(protocol_limits);
    RUN_TEST(default_socket_path);
    RUN_TEST(environment_variable_names);
    RUN_TEST(validation_check_dfa_long_command);
    RUN_TEST(validation_check_dfa_special_chars);
    RUN_TEST(validation_check_dfa_path_commands);
    RUN_TEST(validation_check_dfa_piped_commands);
    RUN_TEST(validation_check_dfa_env_var);
}

/*
 * Get test statistics
 */
void get_validation_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run;
    *passed = tests_passed;
    *failed = tests_failed;
}

/*
 * Reset test statistics
 */
void reset_validation_test_stats(void) {
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;
}
