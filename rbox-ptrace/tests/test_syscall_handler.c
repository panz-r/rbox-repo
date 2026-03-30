/*
 * test_syscall_handler.c - Unit tests for syscall handler
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/user.h>

#include "../syscall_handler.h"

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
 * Test syscall_handler_init
 */
TEST(syscall_handler_init_basic) {
    int result = syscall_handler_init();
    ASSERT_EQ(result, 0);

    /* Cleanup */
    syscall_handler_cleanup();
    return 0;
}

/*
 * Test syscall_handler_cleanup with no init
 */
TEST(syscall_handler_cleanup_no_init) {
    /* Should not crash even without init */
    syscall_handler_cleanup();
    ASSERT(1);  /* If we get here, test passed */
    return 0;
}

/*
 * Test syscall_handler_init and cleanup cycle
 */
TEST(syscall_handler_init_cleanup_cycle) {
    for (int i = 0; i < 5; i++) {
        int result = syscall_handler_init();
        ASSERT_EQ(result, 0);
        syscall_handler_cleanup();
    }
    ASSERT(1);  /* If we get here, all cycles passed */
    return 0;
}

/*
 * Test syscall_is_execve with execve syscall number
 */
TEST(syscall_is_execve_execve) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.orig_rax = SYSCALL_EXECVE;
#else
    regs.orig_eax = SYSCALL_EXECVE;
#endif

    int result = syscall_is_execve(&regs);
    ASSERT_EQ(result, 1);
    return 0;
}

TEST(syscall_is_execve_non_execve) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.orig_rax = 1;  /* write syscall */
#else
    regs.orig_eax = 4;  /* write syscall */
#endif

    int result = syscall_is_execve(&regs);
    ASSERT_EQ(result, 0);
    return 0;
}

/*
 * Test syscall_is_execve with execveat syscall
 */
TEST(syscall_is_execve_execveat) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.orig_rax = SYSCALL_EXECVEAT;
#else
    regs.orig_eax = SYSCALL_EXECVEAT;
#endif

    int result = syscall_is_execve(&regs);
    /* execveat IS now detected as execve-like (returns 1) */
    ASSERT_EQ(result, 1);  
    return 0;
}

TEST(syscall_is_fork_clone) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.orig_rax = SYSCALL_CLONE;
#else
    regs.orig_eax = SYSCALL_CLONE;
#endif

    int result = syscall_is_fork(&regs);
    ASSERT_EQ(result, 1);
    return 0;
}

TEST(syscall_is_fork_fork) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.orig_rax = SYSCALL_FORK;
#else
    regs.orig_eax = SYSCALL_FORK;
#endif

    int result = syscall_is_fork(&regs);
    ASSERT_EQ(result, 1);
    return 0;
}

/*
 * Test syscall_is_fork with vfork syscall
 */
TEST(syscall_is_fork_vfork) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.orig_rax = SYSCALL_VFORK;
#else
    regs.orig_eax = SYSCALL_VFORK;
#endif

    int result = syscall_is_fork(&regs);
    ASSERT_EQ(result, 1);
    return 0;
}

TEST(syscall_is_fork_non_fork) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.orig_rax = 1;  /* write syscall */
#else
    regs.orig_eax = 4;  /* write syscall */
#endif

    int result = syscall_is_fork(&regs);
    ASSERT_EQ(result, 0);
    return 0;
}

TEST(syscall_get_process_state_new_pid) {
    syscall_handler_init();

    /* Use a fake pid that doesn't exist */
    pid_t fake_pid = 99999;

    ProcessState *state = syscall_get_process_state(fake_pid);
    ASSERT_NOT_NULL(state);
    ASSERT_EQ(state->pid, fake_pid);
    ASSERT_EQ(state->in_execve, 0);
    ASSERT_NULL(state->execve_pathname);
    ASSERT_NULL(state->execve_argv);
    ASSERT_NULL(state->execve_envp);

    /* Cleanup */
    syscall_remove_process_state(fake_pid);
    syscall_handler_cleanup();
    return 0;
}

TEST(syscall_get_process_state_same_pid) {
    syscall_handler_init();

    pid_t fake_pid = 99998;

    ProcessState *state1 = syscall_get_process_state(fake_pid);
    ASSERT_NOT_NULL(state1);

    ProcessState *state2 = syscall_get_process_state(fake_pid);
    ASSERT_NOT_NULL(state2);
    ASSERT_EQ(state1, state2);

    /* Cleanup */
    syscall_remove_process_state(fake_pid);
    syscall_handler_cleanup();
    return 0;
}

/*
 * Test syscall_remove_process_state
 */
TEST(syscall_remove_process_state_basic) {
    syscall_handler_init();

    pid_t fake_pid = 99997;

    /* Create state */
    ProcessState *state = syscall_get_process_state(fake_pid);
    ASSERT_NOT_NULL(state);

    /* Remove state */
    syscall_remove_process_state(fake_pid);

    /* Getting state again should create new one */
    ProcessState *state2 = syscall_get_process_state(fake_pid);
    ASSERT_NOT_NULL(state2);
    /* Note: state2 might be at same address due to reuse */

    /* Cleanup */
    syscall_remove_process_state(fake_pid);
    syscall_handler_cleanup();
    return 0;
}

TEST(syscall_remove_process_state_nonexistent) {
    syscall_handler_init();

    /* Should not crash */
    syscall_remove_process_state(99996);
    ASSERT(1);  /* If we get here, test passed */

    syscall_handler_cleanup();
    return 0;
}

TEST(process_state_manipulation) {
    syscall_handler_init();

    pid_t fake_pid = 99995;
    ProcessState *state = syscall_get_process_state(fake_pid);
    ASSERT_NOT_NULL(state);

    /* Set some values */
    state->in_execve = 1;
    state->execve_pathname = strdup("/bin/ls");

    /* Verify values */
    ASSERT_EQ(state->in_execve, 1);
    ASSERT_STR_EQ(state->execve_pathname, "/bin/ls");

    /* Cleanup - syscall_remove_process_state frees the pathname */
    syscall_remove_process_state(fake_pid);
    syscall_handler_cleanup();
    return 0;
}

TEST(multiple_process_states) {
    syscall_handler_init();

    pid_t pid1 = 99990;
    pid_t pid2 = 99991;
    pid_t pid3 = 99992;

    ProcessState *state1 = syscall_get_process_state(pid1);
    ProcessState *state2 = syscall_get_process_state(pid2);
    ProcessState *state3 = syscall_get_process_state(pid3);

    ASSERT_NOT_NULL(state1);
    ASSERT_NOT_NULL(state2);
    ASSERT_NOT_NULL(state3);

    /* Verify they are different */
    ASSERT_NE(state1, state2);
    ASSERT_NE(state2, state3);
    ASSERT_NE(state1, state3);

    /* Verify pids */
    ASSERT_EQ(state1->pid, pid1);
    ASSERT_EQ(state2->pid, pid2);
    ASSERT_EQ(state3->pid, pid3);

    /* Cleanup */
    syscall_remove_process_state(pid1);
    syscall_remove_process_state(pid2);
    syscall_remove_process_state(pid3);
    syscall_handler_cleanup();
    return 0;
}

/*
 * Test syscall numbers are defined correctly
 */
TEST(syscall_numbers_defined) {
#ifdef __x86_64__
    ASSERT_EQ(SYSCALL_EXECVE, 59);
    ASSERT_EQ(SYSCALL_EXECVEAT, 322);
    ASSERT_EQ(SYSCALL_CLONE, 56);
    ASSERT_EQ(SYSCALL_FORK, 57);
    ASSERT_EQ(SYSCALL_VFORK, 58);
    ASSERT_EQ(SYSCALL_EXIT_GROUP, 231);
#elif __i386__
    ASSERT_EQ(SYSCALL_EXECVE, 11);
    ASSERT_EQ(SYSCALL_EXECVEAT, 358);
    ASSERT_EQ(SYSCALL_CLONE, 120);
    ASSERT_EQ(SYSCALL_FORK, 2);
    ASSERT_EQ(SYSCALL_VFORK, 190);
    ASSERT_EQ(SYSCALL_EXIT_GROUP, 252);
#else
    /* Unsupported architecture - skip */
    ASSERT(1);
#endif
    return 0;
}

TEST(reg_syscall_macro) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.orig_rax = 123;
    ASSERT_EQ(REG_SYSCALL(&regs), 123);
#elif __i386__
    regs.orig_eax = 456;
    ASSERT_EQ(REG_SYSCALL(&regs), 456);
#else
    ASSERT(1);
#endif
    return 0;
}

TEST(reg_arg_macros) {
    USER_REGS regs;
    memset(&regs, 0, sizeof(regs));

#ifdef __x86_64__
    regs.rdi = 1;
    regs.rsi = 2;
    regs.rdx = 3;
    regs.r10 = 4;
    ASSERT_EQ(REG_ARG1(&regs), 1);
    ASSERT_EQ(REG_ARG2(&regs), 2);
    ASSERT_EQ(REG_ARG3(&regs), 3);
    ASSERT_EQ(REG_ARG4(&regs), 4);
#elif __i386__
    regs.ebx = 1;
    regs.ecx = 2;
    regs.edx = 3;
    regs.esi = 4;
    ASSERT_EQ(REG_ARG1(&regs), 1);
    ASSERT_EQ(REG_ARG2(&regs), 2);
    ASSERT_EQ(REG_ARG3(&regs), 3);
    ASSERT_EQ(REG_ARG4(&regs), 4);
#else
    ASSERT(1);
#endif
    return 0;
}

TEST(process_table_dynamic_scaling) {
    ASSERT_EQ(syscall_handler_init(), 0);

    const size_t num_processes = 10000;
    ProcessState *states[10000];

    for (size_t i = 0; i < num_processes; i++) {
        pid_t pid = 1000 + (pid_t)i;
        states[i] = syscall_get_process_state(pid);
        ASSERT_NOT_NULL(states[i]);
        ASSERT_EQ(states[i]->pid, pid);
    }

    for (size_t i = 0; i < num_processes; i++) {
        pid_t pid = 1000 + (pid_t)i;
        ProcessState *found = syscall_find_process_state(pid);
        ASSERT_NOT_NULL(found);
        ASSERT_EQ(found->pid, pid);
    }

    for (size_t i = 0; i < num_processes / 2; i++) {
        pid_t pid = 1000 + (pid_t)i;
        syscall_remove_process_state(pid);
    }

    for (size_t i = 0; i < num_processes / 2; i++) {
        pid_t pid = 1000 + (pid_t)i;
        ProcessState *found = syscall_find_process_state(pid);
        ASSERT_NULL(found);
    }

    for (size_t i = num_processes / 2; i < num_processes; i++) {
        pid_t pid = 1000 + (pid_t)i;
        ProcessState *found = syscall_find_process_state(pid);
        ASSERT_NOT_NULL(found);
    }

    for (size_t i = num_processes / 2; i < num_processes; i++) {
        pid_t pid = 1000 + (pid_t)i;
        syscall_remove_process_state(pid);
    }

    ASSERT_EQ(syscall_find_process_state(9999), NULL);

    syscall_handler_cleanup();
    return 0;
}

/*
 * Run all syscall handler tests
 */
void run_syscall_handler_tests(void) {
    printf("\n=== Syscall Handler Tests ===\n");

    RUN_TEST(syscall_handler_init_basic);
    RUN_TEST(syscall_handler_cleanup_no_init);
    RUN_TEST(syscall_handler_init_cleanup_cycle);
    RUN_TEST(syscall_is_execve_execve);
    RUN_TEST(syscall_is_execve_non_execve);
    RUN_TEST(syscall_is_execve_execveat);
    RUN_TEST(syscall_is_fork_clone);
    RUN_TEST(syscall_is_fork_fork);
    RUN_TEST(syscall_is_fork_vfork);
    RUN_TEST(syscall_is_fork_non_fork);
    RUN_TEST(syscall_get_process_state_new_pid);
    RUN_TEST(syscall_get_process_state_same_pid);
    RUN_TEST(syscall_remove_process_state_basic);
    RUN_TEST(syscall_remove_process_state_nonexistent);
    RUN_TEST(process_state_manipulation);
    RUN_TEST(multiple_process_states);
    RUN_TEST(process_table_dynamic_scaling);
    RUN_TEST(syscall_numbers_defined);
    RUN_TEST(reg_syscall_macro);
    RUN_TEST(reg_arg_macros);
}

/*
 * Get test statistics
 */
void get_syscall_handler_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run;
    *passed = tests_passed;
    *failed = tests_failed;
}

/*
 * Reset test statistics
 */
void reset_syscall_handler_test_stats(void) {
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;
}
