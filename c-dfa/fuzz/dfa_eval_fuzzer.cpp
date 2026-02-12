// LibFuzzer harness for c-dfa DFA evaluator
// Fuzzes dfa_evaluate() with random command strings

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "../include/dfa.h"
#include "../include/dfa_types.h"

// DFA file to load - relative to fuzzer binary
static const char* DFA_FILE = "../readonlybox.dfa";

// DFA state (initialized once)
static bool dfa_initialized = false;
static void* dfa_data = NULL;
static size_t dfa_size = 0;

// OOM counter to avoid infinite recursion on allocation failures
static int allocation_failure_counter = 0;

// Initialize DFA once
static void ensure_dfa_initialized(void) {
    if (dfa_initialized) return;

    // Load DFA from file
    dfa_data = load_dfa_from_file(DFA_FILE, &dfa_size);
    if (!dfa_data) {
        fprintf(stderr, "WARNING: Could not load DFA from %s\n", DFA_FILE);
        return;
    }

    if (!dfa_init(dfa_data, dfa_size)) {
        fprintf(stderr, "WARNING: DFA initialization failed\n");
        free(dfa_data);
        dfa_data = NULL;
        return;
    }

    dfa_initialized = true;
}

// Free DFA resources (called at exit)
static void cleanup_dfa(void) {
    if (dfa_data) {
        free(dfa_data);
        dfa_data = NULL;
    }
    dfa_initialized = false;
}

// LLVMFuzzerInitialize - called once at startup
extern "C" void LLVMFuzzerInitialize(void) {
    // Set up cleanup on exit
    atexit(cleanup_dfa);
}

// LLVMFuzzerTestOneInput - main fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Limit input size to prevent extreme cases (4KB is generous for command strings)
    const size_t MAX_INPUT_SIZE = 4096;
    if (size > MAX_INPUT_SIZE) {
        size = MAX_INPUT_SIZE;
    }

    // Ensure DFA is initialized
    if (!dfa_initialized) {
        ensure_dfa_initialized();
        if (!dfa_initialized) {
            // Can't fuzz without DFA - skip this input
            return 0;
        }
    }

    // Allocate buffer for null-terminated string
    char* str = (char*)malloc(size + 1);
    if (!str) {
        // Allocation failure - try to continue
        allocation_failure_counter++;
        if (allocation_failure_counter > 100) {
            // Too many failures, abort to avoid infinite loop
            abort();
        }
        return 0;
    }
    allocation_failure_counter = 0;

    // Copy input and null-terminate
    memcpy(str, data, size);
    str[size] = '\0';

    // Evaluate with DFA
    dfa_result_t result;
    bool ok = dfa_evaluate_with_limit(str, size, &result, 16);

    // Sanity checks - these should NEVER trigger if DFA is correct
    if (ok) {
        // Capture count should fit in array
        if (result.capture_count > 16) {
            fprintf(stderr, "ERROR: capture_count=%d exceeds MAX_CAPTURES=16\n",
                    result.capture_count);
            abort();
        }

        // Captures should be in bounds
        for (int i = 0; i < result.capture_count; i++) {
            if (result.captures[i].start > size || result.captures[i].end > size) {
                fprintf(stderr, "ERROR: capture %d out of bounds: start=%zu end=%zu size=%zu\n",
                        i, result.captures[i].start, result.captures[i].end, size);
                abort();
            }
            if (result.captures[i].start > result.captures[i].end) {
                fprintf(stderr, "ERROR: capture %d start > end: %zu > %zu\n",
                        i, result.captures[i].start, result.captures[i].end);
                abort();
            }
        }

        // Category should be valid
        if (result.category < DFA_CMD_UNKNOWN || result.category > DFA_CMD_ADMIN) {
            fprintf(stderr, "ERROR: invalid category: %d\n", result.category);
            abort();
        }
    }

    // Clean up
    free(str);
    return 0;
}
