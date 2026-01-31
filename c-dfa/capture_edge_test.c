#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"

// Test case structure
struct test_case {
    const char* input;
    const char* description;
    int expected_captures;
};

int main() {
    // Load DFA
    FILE* f = fopen("/home/panz/osrc/lms-test/readonlybox/c-dfa/capture_edge.dfa", "rb");
    if (!f) { printf("Failed to open DFA\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    if (!dfa_init(data, size)) {
        printf("Failed to init DFA\n");
        return 1;
    }
    
    // Test cases
    struct test_case tests[] = {
        // Multiple captures - cp/mv patterns
        {"cp src dst", "cp with src and dst captures", 2},
        {"mv file1 file2", "mv with file1 and file2 captures", 2},
        
        // Capture at start and end - echo pattern
        {"echo hello world", "echo with msg capture", 1},
        
        // Empty capture - touch pattern
        {"touch file", "touch with file capture", 1},
        
        // Optional capture - ls pattern
        {"ls -la /tmp", "ls with flags and path captures", 2},
        
        // Simple single captures
        {"cat test.txt", "cat with file capture", 1},
        {"head -n 20", "head with num capture", 1},
        {"mkdir mydir", "mkdir with dir capture", 1},
    };
    
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;
    
    printf("========================================\n");
    printf("Capture Edge Case DFA Test\n");
    printf("========================================\n\n");
    
    for (int i = 0; i < num_tests; i++) {
        dfa_result_t result;
        const char* input = tests[i].input;
        size_t len = strlen(input);
        
        // Reset DFA state for each test
        dfa_reset();
        
        bool ok = dfa_evaluate(input, len, &result);
        
        printf("Test %d: %s\n", i + 1, tests[i].description);
        printf("  Input: '%s'\n", input);
        printf("  Matched: %s\n", result.matched ? "YES" : "NO");
        printf("  Category: %s\n", dfa_category_string(result.category));
        printf("  Capture count: %d\n", result.capture_count);
        
        if (result.matched) {
            if (result.capture_count == tests[i].expected_captures) {
                printf("  ✓ Expected captures: %d (PASS)\n", tests[i].expected_captures);
                passed++;
            } else {
                printf("  ✗ Expected captures: %d, Got: %d (FAIL)\n", 
                       tests[i].expected_captures, result.capture_count);
            }
            
            // Print capture details
            for (int j = 0; j < result.capture_count; j++) {
                size_t start, length;
                const char* name = dfa_get_capture_name(&result, j);
                
                if (dfa_get_capture_by_index(&result, j, &start, &length)) {
                    printf("  Capture %d (%s): start=%zu, length=%zu", 
                           j, name ? name : "unnamed", start, length);
                    
                    if (length > 0 && start + length <= len) {
                        printf(", content='%.*s'", (int)length, input + start);
                    }
                    printf("\n");
                }
            }
        } else {
            printf("  (No captures - pattern did not match)\n");
        }
        
        printf("\n");
    }
    
    printf("========================================\n");
    printf("Results: %d/%d tests passed\n", passed, num_tests);
    printf("========================================\n");
    
    free(data);
    return (passed == num_tests) ? 0 : 1;
}
