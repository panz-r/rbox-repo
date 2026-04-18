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
extern void test_vfs_filter_run(void);
extern void test_rule_engine_run(void);
extern void test_rule_engine_parser_run(void);
extern void test_arena_run(void);
extern void test_builder_edge_run(void);
extern void test_radix_tree_edge_run(void);
extern void test_landlock_bridge_run(void);
extern void test_compilation_core_run(void);
extern void test_compilation_internal_run(void);
extern void test_compilation_remaining2_run(void);
extern void test_compilation_remaining3_run(void);
extern void test_compilation_final_gaps_run(void);
extern void test_compilation_extra_run(void);
extern void test_compilation_gaps_run(void);
extern void test_compilation_binary_run(void);
extern void test_compilation_layered_run(void);
extern void test_fuzz_edge_run(void);
extern void test_ruleset_management_run(void);
extern void test_cache_associativity_run(void);

int main(void)
{
    printf("========================================\n");
    printf("  liblandlock-builder — Test Suite\n");
    printf("========================================\n\n");

    test_arena_run();
    printf("\n");

    test_mock_fs_run();
    printf("\n");

    test_radix_tree_run();
    printf("\n");

    test_radix_tree_edge_run();
    printf("\n");

    test_radix_tree_extended_run();
    printf("\n");

    test_vfs_filter_run();
    printf("\n");

    test_rule_engine_run();
    test_rule_engine_parser_run();
    printf("\n");

    test_builder_run();
    printf("\n");

    test_builder_edge_run();
    printf("\n");

    test_builder_extended_run();
    printf("\n");

    test_landlock_bridge_run();
    printf("\n");

    test_compilation_core_run();
    printf("\n");

    test_compilation_internal_run();
    printf("\n");

    test_compilation_remaining2_run();
    printf("\n");

    test_compilation_remaining3_run();
    printf("\n");

    test_compilation_final_gaps_run();
    printf("\n");

    test_compilation_extra_run();
    printf("\n");

    test_compilation_gaps_run();
    printf("\n");

    test_compilation_binary_run();
    printf("\n");

    test_compilation_layered_run();
    printf("\n");

    test_fuzz_edge_run();
    printf("\n");

    test_ruleset_management_run();
    printf("\n");

    test_cache_associativity_run();
    printf("\n");

    print_summary();

    return tests_failed > 0 ? 1 : 0;
}
