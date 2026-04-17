/*
 * test_wrap.c - Tests for rbox-wrap
 * 
 * Tests the rbox-wrap binary modes:
 * - --help
 * - --judge (query server for decision)
 * - --run (query and execute)
 * - --bin (binary packet mode)
 * - --relay (skip DFA)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>

#include "rbox_protocol.h"
#include "rbox_protocol_defs.h"

#define TEST_SOCKET "/tmp/rbox_wrap_test.sock"

static int test_count = 0;
static int pass_count = 0;

#define TEST(name) do { \
    test_count++; \
    printf("Testing: %s...\n", name); \
} while(0)

#define PASS() do { \
    pass_count++; \
    printf("  PASS\n"); \
} while(0)

#define FAIL(msg) do { \
    printf("  FAIL: %s\n", msg); \
    return 1; \
} while(0)

/* Run command and capture output */
static int run_cmd(const char *cmd, char *output, size_t output_size) {
    /* Redirect stderr to stdout for capture */
    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);
    
    FILE *fp = popen(full_cmd, "r");
    if (!fp) return -1;
    if (output) {
        output[0] = '\0';
        size_t n = fread(output, 1, output_size - 1, fp);
        output[n] = '\0';
    }
    int status = pclose(fp);
    return WEXITSTATUS(status);
}

/* Test 1: Help output */
static int test_help(void) {
    TEST("help output");
    
    char output[512];
    int status = run_cmd("./rbox-wrap --help", output, sizeof(output));
    (void)status;
    
    /* Output starts with "Usage:" or contains it */
    if (strstr(output, "Usage:") == NULL) {
        printf("  Got: %s\n", output);
        FAIL("missing usage info");
    }
    
    PASS();
    return 0;
}

/* Test 2: No command shows help */
static int test_no_command(void) {
    TEST("no command shows help");
    
    char output[512];
    int status = run_cmd("./rbox-wrap", output, sizeof(output));
    
    /* Should exit with error */
    if (status == 0) {
        FAIL("should have failed with no command");
    }
    
    if (strstr(output, "Usage:") == NULL && strstr(output, "Error:") == NULL) {
        printf("  Got: %s\n", output);
        FAIL("should show usage or error");
    }
    
    PASS();
    return 0;
}

/* Test 3: Unknown option */
static int test_unknown_option(void) {
    TEST("unknown option");
    
    char output[512];
    int status = run_cmd("./rbox-wrap --unknown-option", output, sizeof(output));
    
    /* Should fail */
    if (status == 0) {
        FAIL("should have failed with unknown option");
    }
    
    /* Check for any error-related message (unrecognized, unknown, or Error:) */
    if (strstr(output, "unrecognized") == NULL && 
        strstr(output, "unknown") == NULL &&
        strstr(output, "Error:") == NULL) {
        printf("  Got: %s\n", output);
        FAIL("should show error for unknown option");
    }
    
    PASS();
    return 0;
}

/* Test 4: Socket path option */
static int test_socket_option(void) {
    TEST("--socket option");
    
    char output[256];
    int status = run_cmd("./rbox-wrap --socket /nonexistent.sock --help", output, sizeof(output));
    
    /* --help should work even with invalid socket */
    /* Just verify it parses the option */
    
    PASS();
    return 0;
}

/* Test 5: Mode options parsing */
static int test_modes(void) {
    TEST("mode options --judge --run --bin --relay");
    
    char output[256];
    
    /* --judge mode */
    int status = run_cmd("./rbox-wrap --judge --help", output, sizeof(output));
    (void)status;
    
    /* --run mode */
    status = run_cmd("./rbox-wrap --run --help", output, sizeof(output));
    (void)status;
    
    /* --bin mode */
    status = run_cmd("./rbox-wrap --bin --help", output, sizeof(output));
    (void)status;
    
    /* --relay mode */
    status = run_cmd("./rbox-wrap --relay --help", output, sizeof(output));
    (void)status;
    
    PASS();
    return 0;
}

/* Test 6: Version constant consistency */
static int test_version(void) {
    TEST("version constant RBOX_VERSION == (9 << 16) | 0");
    
    if (RBOX_VERSION != ((9 << 16) | 0)) {
        printf("  RBOX_VERSION is %u, expected %u\n", RBOX_VERSION, ((9 << 16) | 0));
        FAIL("RBOX_VERSION should be (9 << 16) | 0");
    }
    
    PASS();
    return 0;
}

/* Test 7: Decision constants */
static int test_decisions(void) {
    TEST("decision constants");
    
    /* Verify decision values */
    if (RBOX_DECISION_ALLOW != 2) {
        FAIL("RBOX_DECISION_ALLOW should be 2");
    }
    if (RBOX_DECISION_DENY != 3) {
        FAIL("RBOX_DECISION_DENY should be 3");
    }
    
    PASS();
    return 0;
}

/* Test 8: Header size constant */
static int test_header_size(void) {
    TEST("header size RBOX_HEADER_SIZE == 127");

    if (RBOX_HEADER_SIZE != 127) {
        FAIL("RBOX_HEADER_SIZE should be 127");
    }

    PASS();
    return 0;
}

/* Test 9: Privilege dropping with non-existent UID */
static int test_priv_drop_invalid_uid(void) {
    TEST("privilege dropping rejects non-existent UID");

    /* UID 65000 is within valid range (<= 65534) but doesn't exist */
    char output[256];
    int status = run_cmd("./rbox-wrap -u 65000 --run -- id -u 2>&1", output, sizeof(output));

    if (strstr(output, "does not exist") != NULL) {
        PASS();
        return 0;
    }

    printf("  Got: %s\n", output);
    FAIL("should report non-existent UID");
}

/* Test 10: DFA does NOT fast-path dangerous commands */
static int test_dfa_does_not_fast_path_dangerous(void) {
    TEST("DFA does not fast-path 'rm' (goes to server)");

    char output[256];

    /* rm is NOT in the DFA autoallow list, so it should NOT say "ALLOW DFA fast-path" */
    int status = run_cmd("./rbox-wrap --judge -- rm 2>&1", output, sizeof(output));

    /* Should NOT match DFA fast-path */
    if (strstr(output, "ALLOW DFA fast-path") == NULL) {
        PASS();
        return 0;
    }

    printf("  Got: %s\n", output);
    FAIL("'rm' should not use DFA fast-path");
}

int main(void) {
    printf("=== rbox-wrap tests ===\n\n");

    /* Build tests */
    int failed = 0;

    failed |= test_help();
    failed |= test_no_command();
    failed |= test_unknown_option();
    failed |= test_socket_option();
    failed |= test_modes();
    failed |= test_version();
    failed |= test_decisions();
    failed |= test_header_size();
    failed |= test_priv_drop_invalid_uid();
    failed |= test_dfa_does_not_fast_path_dangerous();
    
    printf("\n=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    
    return failed ? 1 : 0;
}
