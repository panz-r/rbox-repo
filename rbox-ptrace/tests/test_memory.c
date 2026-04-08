/*
 * test_memory.c - Unit tests for memory operations
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

#include "../memory.h"

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
 * Test memory_init with valid parameters
 */
TEST(memory_init_valid) {
    MemoryContext ctx;
    pid_t pid = getpid();
    unsigned long stack_ptr = 0x7fff0000;

    int result = memory_init(&ctx, pid, stack_ptr);

    ASSERT_EQ(result, 0);
    ASSERT_EQ(ctx.pid, pid);
    ASSERT_EQ(ctx.stack_base, stack_ptr);
    ASSERT_EQ(ctx.free_addr, stack_ptr - 8192);
    return 0;
}

/*
 * Test memory_init with NULL context
 */
TEST(memory_init_null_context) {
    int result = memory_init(NULL, getpid(), 0x7fff0000);
    ASSERT_EQ(result, -1);
    return 0;
}

/*
 * Test memory_read_string with NULL address
 */
TEST(memory_read_string_null_addr) {
    char *result = memory_read_string(getpid(), 0);
    ASSERT_NULL(result);
    return 0;
}

TEST(memory_read_string_array_null_addr) {
    char **result = memory_read_string_array(getpid(), 0);
    ASSERT_NULL(result);
    return 0;
}

/*
 * Test memory_write_string with NULL context
 */
TEST(memory_write_string_null_context) {
    unsigned long addr;
    int result = memory_write_string(NULL, "test", &addr);
    ASSERT_EQ(result, -1);
    return 0;
}

TEST(memory_write_string_null_string) {
    MemoryContext ctx;
    memory_init(&ctx, getpid(), 0x7fff0000);

    unsigned long addr;
    int result = memory_write_string(&ctx, NULL, &addr);
    ASSERT_EQ(result, -1);
    return 0;
}

TEST(memory_write_pointer_array_null_context) {
    unsigned long pointers[] = {0x1000, 0x2000};
    unsigned long addr;
    int result = memory_write_pointer_array(NULL, pointers, 2, &addr);
    ASSERT_EQ(result, -1);
    return 0;
}

TEST(memory_write_pointer_array_null_pointers) {
    MemoryContext ctx;
    memory_init(&ctx, getpid(), 0x7fff0000);

    unsigned long addr;
    int result = memory_write_pointer_array(&ctx, NULL, 2, &addr);
    ASSERT_EQ(result, -1);
    return 0;
}

TEST(memory_write_pointer_array_negative_count) {
    MemoryContext ctx;
    memory_init(&ctx, getpid(), 0x7fff0000);

    unsigned long pointers[] = {0x1000, 0x2000};
    unsigned long addr;
    int result = memory_write_pointer_array(&ctx, pointers, -1, &addr);
    ASSERT_EQ(result, -1);
    return 0;
}

/*
 * Test memory_free_string with NULL
 */
TEST(memory_free_string_null) {
    /* Should not crash */
    memory_free_string(NULL);
    ASSERT(1);  /* If we get here, test passed */
    return 0;
}

TEST(memory_free_string_array_null) {
    /* Should not crash */
    memory_free_string_array(NULL);
    ASSERT(1);  /* If we get here, test passed */
    return 0;
}

TEST(memory_free_string_array_empty) {
    char **array = calloc(1, sizeof(char *));
    ASSERT_NOT_NULL(array);

    /* Should not crash */
    memory_free_string_array(array);
    ASSERT(1);  /* If we get here, test passed */
    return 0;
}

TEST(memory_free_string_array_valid) {
    char **array = malloc(3 * sizeof(char *));
    ASSERT_NOT_NULL(array);

    array[0] = strdup("string1");
    array[1] = strdup("string2");
    array[2] = NULL;

    /* Should not crash */
    memory_free_string_array(array);
    ASSERT(1);  /* If we get here, test passed */
    return 0;
}

TEST(memory_context_lifecycle) {
    MemoryContext ctx;
    pid_t pid = getpid();
    unsigned long stack_ptr = 0x7fff0000;

    /* Initialize */
    int result = memory_init(&ctx, pid, stack_ptr);
    ASSERT_EQ(result, 0);

    /* Verify initial state */
    ASSERT_EQ(ctx.pid, pid);
    ASSERT_EQ(ctx.stack_base, stack_ptr);
    ASSERT_EQ(ctx.free_addr, stack_ptr - 8192);
    return 0;
}

/*
 * Run all memory tests
 */
void run_memory_tests(void) {
    printf("\n=== Memory Tests ===\n");

    RUN_TEST(memory_init_valid);
    RUN_TEST(memory_init_null_context);
    RUN_TEST(memory_read_string_null_addr);
    RUN_TEST(memory_read_string_array_null_addr);
    RUN_TEST(memory_write_string_null_context);
    RUN_TEST(memory_write_string_null_string);
    RUN_TEST(memory_write_pointer_array_null_context);
    RUN_TEST(memory_write_pointer_array_null_pointers);
    RUN_TEST(memory_write_pointer_array_negative_count);
    RUN_TEST(memory_free_string_null);
    RUN_TEST(memory_free_string_array_null);
    RUN_TEST(memory_free_string_array_empty);
    RUN_TEST(memory_free_string_array_valid);
    RUN_TEST(memory_context_lifecycle);
}

/*
 * Get test statistics
 */
void get_memory_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run;
    *passed = tests_passed;
    *failed = tests_failed;
}

/*
 * Reset test statistics
 */
void reset_memory_test_stats(void) {
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;
}
