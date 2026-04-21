/*
 * test_main.c - Main test runner for ptrace client unit tests
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* External test functions */
extern void run_memory_tests(void);
extern void get_memory_test_stats(int *run, int *passed, int *failed);
extern void reset_memory_test_stats(void);

extern void run_syscall_handler_tests(void);
extern void get_syscall_handler_test_stats(int *run, int *passed, int *failed);
extern void reset_syscall_handler_test_stats(void);

extern void run_validation_tests(void);
extern void get_validation_test_stats(int *run, int *passed, int *failed);
extern void reset_validation_test_stats(void);

extern void run_integration_tests(void);
extern void get_integration_test_stats(int *run, int *passed, int *failed);
extern void reset_integration_test_stats(void);

extern void run_e2e_tests(void);
extern void get_e2e_test_stats(int *run, int *passed, int *failed);
extern void reset_e2e_test_stats(void);

extern void run_sandbox_tests(void);
extern void get_sandbox_test_stats(int *run, int *passed, int *failed);
extern void reset_sandbox_test_stats(void);

extern void run_allowance_chain_tests(void);
extern void get_allowance_chain_test_stats(int *run, int *passed, int *failed);
extern void reset_allowance_chain_test_stats(void);

/* Print test banner */
static void print_banner(void) {
    printf("\n");
    printf("=================================================\n");
    printf("  ReadOnlyBox Ptrace Client Unit Tests\n");
    printf("=================================================\n");
    printf("\n");
}

/* Print test summary */
static void print_summary(int total_run, int total_passed, int total_failed) {
    printf("\n");
    printf("=================================================\n");
    printf("  Test Summary\n");
    printf("=================================================\n");
    printf("  Total tests run:    %d\n", total_run);
    printf("  Tests passed:       %d\n", total_passed);
    printf("  Tests failed:       %d\n", total_failed);
    printf("\n");

    if (total_failed == 0) {
        printf("  ALL TESTS PASSED!\n");
    } else {
        printf("  SOME TESTS FAILED!\n");
    }

    printf("=================================================\n");
    printf("\n");
}

/* Print usage */
static void print_usage(const char *progname) {
    printf("Usage: %s [options] [test_suite...]\n", progname);
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -l, --list     List available test suites\n");
    printf("  -v, --verbose  Enable verbose output\n");
    printf("\n");
    printf("Test suites:\n");
    printf("  memory         Run memory operation tests\n");
    printf("  syscall        Run syscall handler tests\n");
    printf("  validation     Run validation tests\n");
    printf("  integration    Run integration tests\n");
    printf("  e2e            Run end-to-end tests\n");
    printf("  sandbox        Run sandbox rule-building tests\n");
    printf("  all            Run all tests (default)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s             Run all tests\n", progname);
    printf("  %s memory      Run only memory tests\n", progname);
    printf("  %s memory syscall  Run memory and syscall tests\n", progname);
    printf("  %s e2e         Run end-to-end tests only\n", progname);
    printf("\n");
}

/* List available test suites */
static void list_suites(void) {
    printf("\nAvailable test suites:\n");
    printf("  memory       - Memory operation tests\n");
    printf("  syscall      - Syscall handler tests\n");
    printf("  validation   - Validation and protocol tests\n");
    printf("  integration  - Integration tests\n");
    printf("  e2e          - End-to-end tests (requires server)\n");
    printf("  sandbox      - Sandbox rule-building tests\n");
    printf("  allowance-chain - Allowance chain tests\n");
    printf("  all          - All test suites (default)\n");
    printf("\n");
}

/* Main entry point */
int main(int argc, char *argv[]) {
    int verbose = 0;
    int run_memory = 0;
    int run_syscall = 0;
    int run_validation = 0;
    int run_integration = 0;
    int run_e2e = 0;
    int run_sandbox = 0;
    int run_allowance_chain = 0;
    int run_all = 1;

    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            list_suites();
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
            continue;
        }
        if (strcmp(argv[i], "memory") == 0) {
            run_memory = 1;
            run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "syscall") == 0) {
            run_syscall = 1;
            run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "validation") == 0) {
            run_validation = 1;
            run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "integration") == 0) {
            run_integration = 1;
            run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "e2e") == 0) {
            run_e2e = 1;
            run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "sandbox") == 0) {
            run_sandbox = 1;
            run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "allowance-chain") == 0) {
            run_allowance_chain = 1;
            run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "all") == 0) {
            run_all = 1;
            continue;
        }
        printf("Unknown option or test suite: %s\n", argv[i]);
        print_usage(argv[0]);
        return 1;
    }

    /* If no specific suites selected, run all except e2e by default */
    if (run_all) {
        run_memory = 1;
        run_syscall = 1;
        run_validation = 1;
        run_integration = 1;
        run_sandbox = 1;
        run_allowance_chain = 1;
        /* Don't run e2e by default as it requires server binary */
    }

    /* Print banner */
    print_banner();

    /* Print verbose info if requested */
    if (verbose) {
        printf("Verbose mode enabled\n");
        printf("Architecture: ");
#ifdef __x86_64__
        printf("x86_64\n");
#elif __i386__
        printf("i386\n");
#else
        printf("unknown\n");
#endif
        printf("\n");
    }

    /* Initialize random seed */
    srand((unsigned int)time(NULL));

    /* Test suite statistics */
    int total_run = 0;
    int total_passed = 0;
    int total_failed = 0;

    int run, passed, failed;

    /* Run memory tests */
    if (run_memory) {
        reset_memory_test_stats();
        run_memory_tests();
        get_memory_test_stats(&run, &passed, &failed);
        total_run += run;
        total_passed += passed;
        total_failed += failed;
    }

    /* Run syscall handler tests */
    if (run_syscall) {
        reset_syscall_handler_test_stats();
        run_syscall_handler_tests();
        get_syscall_handler_test_stats(&run, &passed, &failed);
        total_run += run;
        total_passed += passed;
        total_failed += failed;
    }

    /* Run validation tests */
    if (run_validation) {
        reset_validation_test_stats();
        run_validation_tests();
        get_validation_test_stats(&run, &passed, &failed);
        total_run += run;
        total_passed += passed;
        total_failed += failed;
    }

    /* Run integration tests */
    if (run_integration) {
        reset_integration_test_stats();
        run_integration_tests();
        get_integration_test_stats(&run, &passed, &failed);
        total_run += run;
        total_passed += passed;
        total_failed += failed;
    }

    /* Run end-to-end tests */
    if (run_e2e) {
        reset_e2e_test_stats();
        run_e2e_tests();
        get_e2e_test_stats(&run, &passed, &failed);
        total_run += run;
        total_passed += passed;
        total_failed += failed;
    }

    /* Run sandbox tests */
    if (run_sandbox) {
        reset_sandbox_test_stats();
        run_sandbox_tests();
        get_sandbox_test_stats(&run, &passed, &failed);
        total_run += run;
        total_passed += passed;
        total_failed += failed;
    }

    /* Run allowance chain tests */
    if (run_allowance_chain) {
        reset_allowance_chain_test_stats();
        run_allowance_chain_tests();
        get_allowance_chain_test_stats(&run, &passed, &failed);
        total_run += run;
        total_passed += passed;
        total_failed += failed;
    }

    /* Print summary */
    print_summary(total_run, total_passed, total_failed);

    /* Return appropriate exit code */
    return (total_failed > 0) ? 1 : 0;
}
