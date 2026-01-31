#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

#define DFA_STATE_ACCEPTING 0x0001

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dfa_file> [test_input]\n", argv[0]);
        return 1;
    }
    
    const char* dfa_file = argv[1];
    const char* test_input = argc > 2 ? argv[2] : "cp src dst";
    
    FILE* f = fopen(dfa_file, "rb");
    if (!f) {
        printf("Failed to open DFA file: %s\n", dfa_file);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* data = malloc(file_size);
    fread(data, 1, file_size, f);
    fclose(f);
    
    // Parse header manually
    uint32_t magic = *((uint32_t*)data);
    uint16_t version = *((uint16_t*)((char*)data + 4));
    uint16_t state_count = *((uint16_t*)((char*)data + 6));
    uint32_t initial_state = *((uint32_t*)((char*)data + 8));
    uint32_t accepting_mask = *((uint32_t*)((char*)data + 12));
    
    printf("DFA File: %s\n", dfa_file);
    printf("  Magic: 0x%08X (expected: 0x%08X)\n", magic, DFA_MAGIC);
    printf("  Version: %d\n", version);
    printf("  State count: %d\n", state_count);
    printf("  Initial state offset: %d\n", initial_state);
    printf("  Accepting mask: 0x%08X\n", accepting_mask);
    printf("  File size: %ld bytes\n", file_size);
    printf("\n");
    
    // Initialize DFA
    if (!dfa_init(data, file_size)) {
        printf("Failed to initialize DFA!\n");
        free(data);
        return 1;
    }
    
    printf("Test Input: '%s'\n", test_input);
    printf("Length: %zu\n\n", strlen(test_input));
    
    // Evaluate
    dfa_result_t result;
    bool ok = dfa_evaluate(test_input, strlen(test_input), &result);
    
    printf("Result:\n");
    printf("  Matched: %s\n", result.matched ? "YES" : "NO");
    printf("  Category: %d (%s)\n", result.category, dfa_category_string(result.category));
    printf("  Matched Length: %zu\n", result.matched_length);
    printf("  Capture Count: %d\n", result.capture_count);
    printf("  Final State: %d\n", result.final_state);
    
    if (result.capture_count > 0) {
        printf("\nCaptures:\n");
        for (int i = 0; i < result.capture_count; i++) {
            size_t start, length;
            const char* name = dfa_get_capture_name(&result, i);
            if (dfa_get_capture_by_index(&result, i, &start, &length)) {
                printf("  [%d] %s: start=%zu, length=%zu", i, name ? name : "unnamed", start, length);
                if (length > 0 && start + length <= strlen(test_input)) {
                    printf(", content='%.*s'", (int)length, test_input + start);
                }
                printf("\n");
            }
        }
    }
    
    free(data);
    return 0;
}
