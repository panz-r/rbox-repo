/**
 * @file test_main.c
 * @brief Test runner entry point — runs all test suites.
 */

#include "test_framework.h"
#include <stdio.h>

/* Define global test counters */
int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

/* Declared in each test module */
extern void test_radix_tree_run(void);
extern void test_builder_run(void);
extern void test_mock_fs_run(void);
extern void test_radix_tree_extended_run(void);
extern void test_builder_extended_run(void);

int main(void)
{
    printf("========================================\n");
    printf("  liblandlock-builder — Test Suite\n");
    printf("========================================\n\n");

    test_mock_fs_run();
    printf("\n");

    test_radix_tree_run();
    printf("\n");

    test_radix_tree_extended_run();
    printf("\n");

    test_builder_run();
    printf("\n");

    test_builder_extended_run();
    printf("\n");

    print_summary();

    return tests_failed > 0 ? 1 : 0;
}
