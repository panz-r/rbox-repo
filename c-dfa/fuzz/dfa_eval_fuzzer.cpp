// LibFuzzer harness for c-dfa DFA evaluator
// Fuzzes BOTH the DFA binary AND input strings
// Input format: [dfa_size:4][dfa_data][num_strings:2][string1_len:2][string1]...

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>

#include "../include/dfa.h"
#include "../include/dfa_types.h"

// Maximum sizes
static const size_t MAX_DFA_SIZE = 1024 * 1024;  // 1 MB max DFA
static const size_t MAX_STRING_SIZE = 4096;       // 4 KB max per string
static const uint16_t MAX_STRINGS = 500;          // Max 500 strings per input

// Verbosity flag
static int g_verbose = 0;

// Read little-endian values
static inline uint32_t read_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | 
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint16_t read_u16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

// LLVMFuzzerInitialize
extern "C" void LLVMFuzzerInitialize(void) {
    const char* verbose = getenv("DFA_EVAL_FUZZER_VERBOSE");
    if (verbose && (*verbose == '1' || *verbose == 'y' || *verbose == 'Y')) {
        g_verbose = 1;
    }
    
    // Ignore SIGPIPE (can happen in forked subprocess)
    signal(SIGPIPE, SIG_IGN);
}

// Validate DFA sanity checks after evaluation
static bool validate_result(const dfa_result_t* result, size_t input_len) {
    // Capture count should fit in array
    if (result->capture_count > DFA_MAX_CAPTURES) {
        fprintf(stderr, "BUG: capture_count=%d exceeds MAX_CAPTURES=%d\n",
                result->capture_count, DFA_MAX_CAPTURES);
        return false;
    }

    // Captures should be in bounds
    for (int i = 0; i < result->capture_count; i++) {
        if (result->captures[i].start > input_len || 
            result->captures[i].end > input_len) {
            fprintf(stderr, "BUG: capture %d out of bounds: start=%zu end=%zu input_len=%zu\n",
                    i, result->captures[i].start, result->captures[i].end, input_len);
            return false;
        }
        if (result->captures[i].start > result->captures[i].end) {
            fprintf(stderr, "BUG: capture %d start > end: %zu > %zu\n",
                    i, result->captures[i].start, result->captures[i].end);
            return false;
        }
    }

    // Category should be valid (0-8: UNKNOWN, SAFE, CAUTION, MODIFYING, DANGEROUS, NETWORK, ADMIN, BUILD, CONTAINER)
    if (result->category > DFA_CMD_CONTAINER) {
        fprintf(stderr, "BUG: invalid category: %d\n", result->category);
        return false;
    }

    return true;
}

// Try to initialize and evaluate with a DFA blob
// Returns: 0 = OK, 1 = bug found, -1 = invalid input (skip)
static int test_dfa_with_strings(const uint8_t* dfa_data, size_t dfa_size,
                                  const uint8_t* strings_data, size_t strings_size) {
    // Try to initialize the DFA
    // dfa_init should handle malformed input gracefully
    if (!dfa_init(dfa_data, dfa_size)) {
        // Initialization failed - this is OK, invalid DFA
        if (g_verbose) {
            fprintf(stderr, "DEBUG: DFA init failed (invalid DFA)\n");
        }
        return -1;  // Skip, not a bug
    }

    // Parse string data
    size_t pos = 0;
    uint16_t num_strings = 0;
    
    if (strings_size >= 2) {
        num_strings = read_u16(strings_data);
        pos = 2;
        if (num_strings > MAX_STRINGS) {
            num_strings = MAX_STRINGS;
        }
    }

    int bugs_found = 0;

    // Evaluate each string
    for (uint16_t i = 0; i < num_strings && pos + 2 <= strings_size; i++) {
        uint16_t str_len = read_u16(strings_data + pos);
        pos += 2;
        
        // Clamp string length
        if (str_len > MAX_STRING_SIZE) {
            str_len = MAX_STRING_SIZE;
        }
        
        // Check if we have enough data
        if (pos + str_len > strings_size) {
            str_len = (uint16_t)(strings_size - pos);
        }
        
        const char* input = (const char*)(strings_data + pos);
        pos += str_len;
        
        // Evaluate the string against the DFA
        dfa_result_t result;
        memset(&result, 0, sizeof(result));
        
        bool ok = dfa_evaluate_with_limit(input, str_len, &result, DFA_MAX_CAPTURES);
        
        if (ok) {
            // Validate result sanity
            if (!validate_result(&result, str_len)) {
                fprintf(stderr, "  Input string %d: \"", i);
                fwrite(input, 1, str_len > 100 ? 100 : str_len, stderr);
                if (str_len > 100) fprintf(stderr, "...");
                fprintf(stderr, "\"\n");
                bugs_found++;
            }
        }
        // Don't call dfa_reset() - it clears current_dfa pointer
        // Each evaluation starts fresh from initial state anyway
    }
    
    return bugs_found > 0 ? 1 : 0;
}

// LLVMFuzzerTestOneInput - main fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need at least 6 bytes: [dfa_size:4][num_strings:2]
    if (size < 6) {
        return 0;
    }
    
    // Parse input format:
    // [dfa_size:4][dfa_data][num_strings:2][strings...]
    
    uint32_t dfa_size = read_u32(data);
    
    // Sanity check DFA size
    if (dfa_size > MAX_DFA_SIZE || dfa_size < 16) {
        return 0;  // Skip, invalid size
    }
    
    // Check if we have enough data for DFA
    if (4 + dfa_size + 2 > size) {
        // Not enough data - adjust dfa_size
        dfa_size = (uint32_t)(size - 6);
        if (dfa_size < 16) {
            return 0;  // Too small
        }
    }
    
    const uint8_t* dfa_data = data + 4;
    const uint8_t* strings_data = data + 4 + dfa_size;
    size_t strings_size = size - 4 - dfa_size;
    
    // Test the DFA with the strings
    int result = test_dfa_with_strings(dfa_data, dfa_size, strings_data, strings_size);
    
    if (result == 1) {
        // Bug found - abort to signal LibFuzzer
        fprintf(stderr, "BUG FOUND in DFA evaluation!\n");
        abort();
    }
    
    return 0;
}
