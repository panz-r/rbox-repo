#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"

void test_input(const char* input) {
    dfa_result_t result;
    bool ok = dfa_evaluate(input, 0, &result);
    
    printf("\nInput: '%s'\n", input);
    printf("Matched: %s\n", result.matched ? "true" : "false");
    printf("Matched length: %zu\n", result.matched_length);
    printf("Category: 0x%02x\n", result.category_mask);
    printf("Capture count: %d\n", result.capture_count);
    
    for (int i = 0; i < result.capture_count; i++) {
        size_t start, length;
        dfa_get_capture_by_index(&result, i, &start, &length);
        printf("Capture %d: start=%zu, length=%zu\n", i, start, length);
    }
}

int main() {
    FILE* f = fopen("readonlybox.dfa", "rb");
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
    
    printf("Testing readonlybox.dfa (size: %zu bytes)\n", size);
    
    // Test basic commands
    test_input("git log");
    test_input("ls -la");
    test_input("cat file.txt");
    
    free(data);
    return 0;
}
