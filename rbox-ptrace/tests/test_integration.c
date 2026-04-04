/*
 * test_integration.c - Integration tests for ptrace client
 *
 * These tests verify the interaction between different components
 * and test more complex scenarios.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <signal.h>
#include <errno.h>

#include "../memory.h"
#include "../syscall_handler.h"
#include "../validation.h"
#include "../protocol.h"

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

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)
#define ASSERT_STR_EQ(a, b) ASSERT(strcmp((a), (b)) == 0)

/*
 * Test initialization sequence
 */
TEST(full_initialization_sequence) {
    /* Initialize all subsystems in order */
    int result = validation_init();
    ASSERT_EQ(result, 0);

    result = syscall_handler_init();
    ASSERT_EQ(result, 0);

    /* Cleanup in reverse order */
    syscall_handler_cleanup();
    validation_shutdown();
}

/*
 * Test multiple init/shutdown cycles
 */
TEST(multiple_init_shutdown_cycles) {
    for (int i = 0; i < 10; i++) {
        ASSERT_EQ(validation_init(), 0);
        ASSERT_EQ(syscall_handler_init(), 0);

        syscall_handler_cleanup();
        validation_shutdown();
    }
}

/*
 * Test process state with execve simulation
 */
TEST(process_state_execve_simulation) {
    syscall_handler_init();

    pid_t fake_pid = 88888;
    ProcessState *state = syscall_get_process_state(fake_pid);
    ASSERT_NOT_NULL(state);

    /* Simulate execve entry */
    state->in_execve = 1;
    state->execve_pathname = strdup("/bin/ls");

    char **argv = malloc(3 * sizeof(char *));
    argv[0] = strdup("ls");
    argv[1] = strdup("-la");
    argv[2] = NULL;
    state->execve_argv = argv;

    /* Verify state */
    ASSERT_EQ(state->in_execve, 1);
    ASSERT_STR_EQ(state->execve_pathname, "/bin/ls");
    ASSERT_STR_EQ(state->execve_argv[0], "ls");
    ASSERT_STR_EQ(state->execve_argv[1], "-la");

    /* Cleanup */
    syscall_remove_process_state(fake_pid);
    syscall_handler_cleanup();
}

/*
 * Test multiple processes with different states
 */
TEST(multiple_processes_different_states) {
    syscall_handler_init();

    /* Create multiple process states */
    pid_t pids[5] = {88880, 88881, 88882, 88883, 88884};

    for (int i = 0; i < 5; i++) {
        ProcessState *state = syscall_get_process_state(pids[i]);
        ASSERT_NOT_NULL(state);

        /* Set different states */
        state->in_execve = i % 2;
    }

    /* Verify all states */
    for (int i = 0; i < 5; i++) {
        ProcessState *state = syscall_get_process_state(pids[i]);
        ASSERT_NOT_NULL(state);
        ASSERT_EQ(state->pid, pids[i]);
        ASSERT_EQ(state->in_execve, i % 2);
    }

    /* Cleanup */
    for (int i = 0; i < 5; i++) {
        syscall_remove_process_state(pids[i]);
    }
    syscall_handler_cleanup();
}

/*
 * Test validation with various command types
 */
TEST(validation_various_commands) {
    validation_init();

    /* Test various command patterns */
    const char *commands[] = {
        "ls",
        "ls -la",
        "cat file.txt",
        "echo hello",
        "pwd",
        "whoami",
        "date",
        "uname -a",
        "ps aux",
        "grep pattern file",
        "find /tmp -name '*.txt'",
        "tar -czf archive.tar.gz dir/",
        "ssh user@host",
        "rm -rf /",
        NULL
    };

    for (int i = 0; commands[i] != NULL; i++) {
        int result = validation_check_dfa(commands[i]);
        /* Result should be one of the valid values */
        ASSERT(result == VALIDATION_ALLOW ||
               result == VALIDATION_DENY ||
               result == VALIDATION_ASK);
    }

    validation_shutdown();
}

/*
 * Test memory context with simulated stack
 */
TEST(memory_context_simulated_stack) {
    MemoryContext ctx;
    unsigned long simulated_stack = 0x7fffffffe000;

    int result = memory_init(&ctx, getpid(), simulated_stack);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(ctx.pid, getpid());
    ASSERT_EQ(ctx.stack_base, simulated_stack);
    ASSERT_EQ(ctx.free_addr, simulated_stack - 8192);
}

/*
 * Test protocol header structure
 */
TEST(protocol_header_structure) {
    /* Verify protocol header layout */
    ASSERT_EQ(sizeof(uint32_t), 4);
    ASSERT_EQ(ROBO_MAGIC, 0x524F424F);
    ASSERT_EQ(ROBO_VERSION, 4);

    /* Verify message types */
    ASSERT_EQ(ROBO_MSG_LOG, 0);
    ASSERT_EQ(ROBO_MSG_REQ, 1);

    /* Verify decision codes */
    ASSERT_EQ(ROBO_DECISION_UNKNOWN, 0);
    ASSERT_EQ(ROBO_DECISION_ALLOW, 2);
    ASSERT_EQ(ROBO_DECISION_DENY, 3);
    ASSERT_EQ(ROBO_DECISION_ERROR, 4);
}

/*
 * Test environment variable handling
 */
TEST(environment_variable_handling) {
    /* Save original value */
    char *original = getenv(ROBO_ENV_SOCKET);
    char *saved = original ? strdup(original) : NULL;

    /* Test with custom path */
    setenv(ROBO_ENV_SOCKET, "/custom/path.sock", 1);
    validation_init();

    const char *path = validation_get_socket_path();
    ASSERT_STR_EQ(path, "/custom/path.sock");

    validation_shutdown();

    /* Test with another path */
    setenv(ROBO_ENV_SOCKET, "/another/path.sock", 1);
    validation_init();

    path = validation_get_socket_path();
    ASSERT_STR_EQ(path, "/another/path.sock");

    validation_shutdown();

    /* Restore original value */
    if (saved) {
        setenv(ROBO_ENV_SOCKET, saved, 1);
        free(saved);
    } else {
        unsetenv(ROBO_ENV_SOCKET);
    }
}

/*
 * Test syscall detection with realistic scenarios
 */
TEST(syscall_detection_realistic) {
    USER_REGS regs;

    /* Test execve detection */
    memset(&regs, 0, sizeof(regs));
#ifdef __x86_64__
    regs.orig_rax = 59;  /* execve on x86_64 */
#else
    regs.orig_eax = 11;  /* execve on i386 */
#endif
    ASSERT(syscall_is_execve(&regs));
    ASSERT(!syscall_is_fork(&regs));

    /* Test clone detection */
    memset(&regs, 0, sizeof(regs));
#ifdef __x86_64__
    regs.orig_rax = 56;  /* clone on x86_64 */
#else
    regs.orig_eax = 120; /* clone on i386 */
#endif
    ASSERT(!syscall_is_execve(&regs));
    ASSERT(syscall_is_fork(&regs));

    /* Test regular syscall (write) */
    memset(&regs, 0, sizeof(regs));
#ifdef __x86_64__
    regs.orig_rax = 1;   /* write on x86_64 */
#else
    regs.orig_eax = 4;   /* write on i386 */
#endif
    ASSERT(!syscall_is_execve(&regs));
    ASSERT(!syscall_is_fork(&regs));
}

/*
 * Test process hash table collision handling
 */
TEST(process_hash_collision_handling) {
    syscall_handler_init();

    /* Create PIDs to test hash table collision handling */
    pid_t pid1 = 1024;
    pid_t pid2 = 2048;
    pid_t pid3 = 3072;

    ProcessState *state1 = syscall_get_process_state(pid1);
    ProcessState *state2 = syscall_get_process_state(pid2);
    ProcessState *state3 = syscall_get_process_state(pid3);

    ASSERT_NOT_NULL(state1);
    ASSERT_NOT_NULL(state2);
    ASSERT_NOT_NULL(state3);

    /* They should all be different states */
    ASSERT_NE(state1, state2);
    ASSERT_NE(state2, state3);
    ASSERT_NE(state1, state3);

    /* Set unique values to verify */
    state1->in_execve = 1;
    state2->in_execve = 2;
    state3->in_execve = 3;

    /* Retrieve and verify */
    ASSERT_EQ(syscall_get_process_state(pid1)->in_execve, 1);
    ASSERT_EQ(syscall_get_process_state(pid2)->in_execve, 2);
    ASSERT_EQ(syscall_get_process_state(pid3)->in_execve, 3);

    /* Cleanup */
    syscall_remove_process_state(pid1);
    syscall_remove_process_state(pid2);
    syscall_remove_process_state(pid3);
    syscall_handler_cleanup();
}

/*
 * Test string building functionality
 */
TEST(command_string_building) {
    /* This tests the internal build_command_string function indirectly
     * through validation_check_dfa */
    validation_init();

    /* Simple command */
    int result1 = validation_check_dfa("ls");
    ASSERT(result1 == VALIDATION_ALLOW || result1 == VALIDATION_DENY || result1 == VALIDATION_ASK);

    /* Command with arguments */
    int result2 = validation_check_dfa("ls -la /tmp");
    ASSERT(result2 == VALIDATION_ALLOW || result2 == VALIDATION_DENY || result2 == VALIDATION_ASK);

    /* Complex command */
    int result3 = validation_check_dfa("find /home -name '*.txt' -type f");
    ASSERT(result3 == VALIDATION_ALLOW || result3 == VALIDATION_DENY || result3 == VALIDATION_ASK);

    validation_shutdown();
}

/*
 * Test error handling paths
 */
TEST(error_handling_paths) {
    /* Test NULL handling in various functions */

    /* Memory functions with NULL */
    ASSERT_EQ(memory_init(NULL, 0, 0), -1);
    ASSERT_NULL(memory_read_string(0, 0));
    ASSERT_NULL(memory_read_string_array(0, 0));

    /* These should not crash */
    memory_free_string(NULL);
    memory_free_string_array(NULL);

    /* Validation with NULL/empty */
    validation_init();
    ASSERT_EQ(validation_check_dfa(NULL), VALIDATION_DENY);
    ASSERT_EQ(validation_check_dfa(""), VALIDATION_DENY);
    validation_shutdown();
}

/*
 * Test concurrent process state access simulation
 */
TEST(concurrent_process_simulation) {
    syscall_handler_init();

    /* Simulate multiple processes being tracked */
    const int num_processes = 100;
    pid_t base_pid = 90000;

    /* Create states */
    for (int i = 0; i < num_processes; i++) {
        ProcessState *state = syscall_get_process_state(base_pid + i);
        ASSERT_NOT_NULL(state);
        state->in_execve = i % 2;
    }

    /* Verify all states */
    for (int i = 0; i < num_processes; i++) {
        ProcessState *state = syscall_get_process_state(base_pid + i);
        ASSERT_NOT_NULL(state);
        ASSERT_EQ(state->in_execve, i % 2);
    }

    /* Remove every other process */
    for (int i = 0; i < num_processes; i += 2) {
        syscall_remove_process_state(base_pid + i);
    }

    /* Verify remaining processes */
    for (int i = 1; i < num_processes; i += 2) {
        ProcessState *state = syscall_get_process_state(base_pid + i);
        ASSERT_NOT_NULL(state);
        ASSERT_EQ(state->in_execve, i % 2);
    }

    /* Cleanup remaining */
    for (int i = 1; i < num_processes; i += 2) {
        syscall_remove_process_state(base_pid + i);
    }

    syscall_handler_cleanup();
}

/*
 * Run all integration tests
 */
void run_integration_tests(void) {
    printf("\n=== Integration Tests ===\n");

    RUN_TEST(full_initialization_sequence);
    RUN_TEST(multiple_init_shutdown_cycles);
    RUN_TEST(process_state_execve_simulation);
    RUN_TEST(multiple_processes_different_states);
    RUN_TEST(validation_various_commands);
    RUN_TEST(memory_context_simulated_stack);
    RUN_TEST(protocol_header_structure);
    RUN_TEST(environment_variable_handling);
    RUN_TEST(syscall_detection_realistic);
    RUN_TEST(process_hash_collision_handling);
    RUN_TEST(command_string_building);
    RUN_TEST(error_handling_paths);
    RUN_TEST(concurrent_process_simulation);
}

/*
 * Get test statistics
 */
void get_integration_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run;
    *passed = tests_passed;
    *failed = tests_failed;
}

/*
 * Reset test statistics
 */
void reset_integration_test_stats(void) {
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;
}
