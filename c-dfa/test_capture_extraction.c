#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"

int main() {
    // Load the capture test DFA
    FILE* f = fopen("capture_test.dfa", "rb");
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
    
    // Test: git log -n 10
    dfa_result_t result;
    bool ok = dfa_evaluate("git log -n 10", 0, &result);
    
    printf("Input: 'git log -n 10'\n");
    printf("Matched: %s\n", result.matched ? "true" : "false");
    printf("Matched length: %zu\n", result.matched_length);
    printf("Category: 0x%02x\n", result.category_mask);
    printf("Capture count: %d\n", result.capture_count);
    
    for (int i = 0; i < result.capture_count; i++) {
        size_t start, length;
        dfa_get_capture_by_index(&result, i, &start, &length);
        printf("Capture %d: start=%zu, length=%zu\n", i, start, length);
    }
    
    free(data);
    return 0;
}
