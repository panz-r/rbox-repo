/*
 * test_trampoline_allowance.c - Unit tests for trampoline allowance
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include "trampoline_allowance.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

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

#define ASSERT(cond) do { if (!(cond)) return 1; } while(0)
#define ASSERT_EQ(a,b) ASSERT((a)==(b))

/* ==================== get_command_continuation tests ==================== */

TEST(getcc_simple_no_wrapper) {
    char buf[4096];
    const char *cont = get_command_continuation("ls", buf, sizeof(buf));
    ASSERT_EQ(cont == NULL, 1);
    return 0;
}

TEST(getcc_sh_c_wrapper) {
    char buf[4096];
    const char *cont = get_command_continuation("sh -c 'ls ; sh ls'", buf, sizeof(buf));
    ASSERT(cont != NULL);
    ASSERT_EQ(strcmp(cont, "ls ; sh ls"), 0);
    return 0;
}

TEST(getcc_timeout_wrapper) {
    char buf[4096];
    const char *cont = get_command_continuation("timeout 1 sh -c 'ls ; sh ls'", buf, sizeof(buf));
    ASSERT(cont != NULL);
    ASSERT_EQ(strcmp(cont, "sh -c 'ls ; sh ls'"), 0);
    return 0;
}

TEST(getcc_nested_timeout_sh_c) {
    char buf[4096];
    const char *cont = get_command_continuation("timeout 1 sh -c 'ls ; sh ls'", buf, sizeof(buf));
    ASSERT(cont != NULL);
    ASSERT_EQ(strcmp(cont, "sh -c 'ls ; sh ls'"), 0);

    char buf2[4096];
    const char *cont2 = get_command_continuation(cont, buf2, sizeof(buf2));
    ASSERT(cont2 != NULL);
    ASSERT_EQ(strcmp(cont2, "ls ; sh ls"), 0);
    return 0;
}

TEST(getcc_nice_wrapper) {
    char buf[4096];
    const char *cont = get_command_continuation("nice -n 10 ls", buf, sizeof(buf));
    ASSERT(cont != NULL);
    ASSERT_EQ(strcmp(cont, "ls"), 0);
    return 0;
}

TEST(getcc_no_match) {
    char buf[4096];
    const char *cont = get_command_continuation("echo hello", buf, sizeof(buf));
    ASSERT_EQ(cont == NULL, 1);
    return 0;
}

/* ==================== Core scenario tests ==================== */

TEST(nested_wrapper_compound) {
    AllowSet a;
    allowset_init(&a);

    allowset_grant(&a, "timeout 1 sh -c 'ls ; sh ls'");

    /* First: consume sh -c 'ls ; sh ls' (the continuation of timeout) */
    const char *argv1[] = {"sh", "-c", "ls ; sh ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 1);

    /* Then subcommands become available: "ls" and "sh ls" (both after sh -c) */
    const char *argv2[] = {"ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv2), 1);
    const char *argv3[] = {"sh", "ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv3), 1);

    /* No more allowances */
    ASSERT_EQ(allowset_consume_argv(&a, argv2), 0);

    allowset_deinit(&a);
    return 0;
}

TEST(nested_wrapper_compound_reverse_order) {
    AllowSet a;
    allowset_init(&a);

    allowset_grant(&a, "timeout 1 sh -c 'ls ; sh ls'");

    /* First: sh -c wrapper */
    const char *argv1[] = {"sh", "-c", "ls ; sh ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 1);

    /* Then subcommands (any order) */
    const char *argv2[] = {"sh", "ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv2), 1);
    const char *argv3[] = {"ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv3), 1);

    allowset_deinit(&a);
    return 0;
}

TEST(consume_wrapper_before_subcommands_only) {
    AllowSet a;
    allowset_init(&a);

    allowset_grant(&a, "timeout 1 sh -c 'ls ; sh ls'");

    /* Trying to consume a subcommand before the wrapper should fail */
    const char *argv1[] = {"ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 0);

    allowset_deinit(&a);
    return 0;
}

/* ==================== Basic direct commands ==================== */

TEST(direct_single_command) {
    AllowSet a;
    allowset_init(&a);

    allowset_grant(&a, "ls -la");
    const char *argv1[] = {"ls", "-la", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 1);
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 0);

    allowset_deinit(&a);
    return 0;
}

TEST(direct_multiple_subcommands) {
    AllowSet a;
    allowset_init(&a);

    allowset_grant(&a, "echo a; echo b; echo c");
    const char *argv1[] = {"echo", "b", NULL};
    const char *argv2[] = {"echo", "a", NULL};
    const char *argv3[] = {"echo", "c", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 1);
    ASSERT_EQ(allowset_consume_argv(&a, argv2), 1);
    ASSERT_EQ(allowset_consume_argv(&a, argv3), 1);
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 0);

    allowset_deinit(&a);
    return 0;
}

/* ==================== Single wrapper ==================== */

TEST(single_wrapper) {
    AllowSet a;
    allowset_init(&a);

    allowset_grant(&a, "timeout 1 ls");

    /* Only ls is available (continuation of timeout) */
    const char *argv1[] = {"ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 1);

    allowset_deinit(&a);
    return 0;
}

/* ==================== Expiry ==================== */

TEST(expiry_removes_chain) {
    AllowSet a;
    allowset_init(&a);

    allowset_grant(&a, "ls");

    /* Age the allowance and try to expire */
    a.expiration.tv_sec -= ALLOWANCE_TIMEOUT_SECONDS + 1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int expired = allowset_expire(&a, &now);
    ASSERT_EQ(expired, 1);

    const char *argv1[] = {"ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 0);

    allowset_deinit(&a);
    return 0;
}

/* ==================== Quoted arguments ==================== */

TEST(quoted_wrapper_argument) {
    AllowSet a;
    allowset_init(&a);

    /* nice "sh noop" - nice is the outer command that runs directly */
    allowset_grant(&a, "nice \"sh noop\"");

    /* Only the content after nice is consumable */
    const char *argv1[] = {"sh", "noop", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 1);

    allowset_deinit(&a);
    return 0;
}

TEST(nested_wrappers_three_levels) {
    AllowSet a;
    allowset_init(&a);

    /* nice -> timeout -> sh -c with quoted content */
    allowset_grant(&a, "nice timeout 10 sh -c 'ls ; sh ls'");

    /* timeout sh -c 'ls ; sh ls' consumed first */
    const char *argv1[] = {"timeout", "10", "sh", "-c", "ls ; sh ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 1);

    /* Then sh -c 'ls ; sh ls' consumed */
    const char *argv2[] = {"sh", "-c", "ls ; sh ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv2), 1);

    /* Then subcommands become available (any order) */
    const char *argv3[] = {"ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv3), 1);
    const char *argv4[] = {"sh", "ls", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv4), 1);

    allowset_deinit(&a);
    return 0;
}

TEST(quoted_subcommand) {
    AllowSet a;
    allowset_init(&a);

    allowset_grant(&a, "echo \"hello world\"");
    const char *argv1[] = {"echo", "hello world", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 0);

    allowset_deinit(&a);
    return 0;
}

/* ==================== Multiple commands ==================== */

TEST(multiple_commands) {
    AllowSet a;
    allowset_init(&a);

    /* Grant multiple separate commands */
    allowset_grant(&a, "cmd0");
    allowset_grant(&a, "cmd1");
    allowset_grant(&a, "cmd2");

    /* Should be able to consume each */
    const char *argv0[] = {"cmd0", NULL};
    const char *argv1[] = {"cmd1", NULL};
    const char *argv2[] = {"cmd2", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv0), 1);
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 1);
    ASSERT_EQ(allowset_consume_argv(&a, argv2), 1);

    allowset_deinit(&a);
    return 0;
}

/* ==================== Empty command ==================== */

TEST(empty_command) {
    AllowSet a;
    allowset_init(&a);

    int ret = allowset_grant(&a, "sh -c ''");
    ASSERT_EQ(ret, 0);

    /* The empty sh -c should not match */
    const char *argv1[] = {"sh", "-c", "", NULL};
    ASSERT_EQ(allowset_consume_argv(&a, argv1), 0);

    allowset_deinit(&a);
    return 0;
}

/* ==================== Run all tests ==================== */

void run_allowance_chain_tests(void) {
    printf("\n=== Trampoline Allowance Tests ===\n");
    RUN_TEST(getcc_simple_no_wrapper);
    RUN_TEST(getcc_sh_c_wrapper);
    RUN_TEST(getcc_timeout_wrapper);
    RUN_TEST(getcc_nested_timeout_sh_c);
    RUN_TEST(getcc_nice_wrapper);
    RUN_TEST(getcc_no_match);
    RUN_TEST(nested_wrapper_compound);
    RUN_TEST(nested_wrapper_compound_reverse_order);
    RUN_TEST(consume_wrapper_before_subcommands_only);
    RUN_TEST(direct_single_command);
    RUN_TEST(direct_multiple_subcommands);
    RUN_TEST(single_wrapper);
    RUN_TEST(expiry_removes_chain);
    RUN_TEST(quoted_wrapper_argument);
    RUN_TEST(nested_wrappers_three_levels);
    RUN_TEST(quoted_subcommand);
    RUN_TEST(multiple_commands);
    RUN_TEST(empty_command);
}

void get_allowance_chain_test_stats(int *run, int *passed, int *failed) {
    if (run) *run = tests_run;
    if (passed) *passed = tests_passed;
    if (failed) *failed = tests_failed;
}

void reset_allowance_chain_test_stats(void) {
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;
}
