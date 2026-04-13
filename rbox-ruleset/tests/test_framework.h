/**
 * @file test_framework.h
 * @brief Minimal unit test framework.
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global test counters */
extern int tests_run;
extern int tests_passed;
extern int tests_failed;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        tests_failed++; \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
    } else { \
        tests_passed++; \
    } \
} while (0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    long long _a = (long long)(a); \
    long long _b = (long long)(b); \
    tests_run++; \
    if (_a != _b) { \
        tests_failed++; \
        fprintf(stderr, "  FAIL [%s:%d]: %s (expected %lld, got %lld)\n", \
                __FILE__, __LINE__, msg, _b, _a); \
    } else { \
        tests_passed++; \
    } \
} while (0)

#define TEST_ASSERT_STR_EQ(a, b, msg) do { \
    const char *_a = (a); \
    const char *_b = (b); \
    tests_run++; \
    if (!_a || !_b || strcmp(_a, _b) != 0) { \
        tests_failed++; \
        fprintf(stderr, "  FAIL [%s:%d]: %s (expected \"%s\", got \"%s\")\n", \
                __FILE__, __LINE__, msg, _b ? _b : "(null)", _a ? _a : "(null)"); \
    } else { \
        tests_passed++; \
    } \
} while (0)

#define TEST_ASSERT_NOT_NULL(ptr, msg) do { \
    tests_run++; \
    if (!(ptr)) { \
        tests_failed++; \
        fprintf(stderr, "  FAIL [%s:%d]: %s (got NULL)\n", \
                __FILE__, __LINE__, msg); \
    } else { \
        tests_passed++; \
    } \
} while (0)

#define RUN_TEST(name) do { \
    printf("  Running %s...\n", #name); \
    name(); \
} while (0)

static void print_summary(void) __attribute__((unused));
static void print_summary(void)
{
    printf("\n--- Test Summary ---\n");
    printf("  Run:     %d\n", tests_run);
    printf("  Passed:  %d\n", tests_passed);
    printf("  Failed:  %d\n", tests_failed);
    if (tests_failed > 0) {
        printf("  RESULT: FAIL\n");
    } else {
        printf("  RESULT: PASS\n");
    }
    printf("--------------------\n");
}

#endif /* TEST_FRAMEWORK_H */
