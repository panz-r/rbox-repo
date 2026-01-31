#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

void test_input(const char* dfa_path, const char* input) {
    FILE* f = fopen(dfa_path, "rb");
    if (!f) { printf("Failed to open DFA\n"); return; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    if (!dfa_init(data, size)) {
        printf("Failed to init DFA\n");
        free(data);
        return;
    }
    
    dfa_result_t result;
    dfa_evaluate(input, 0, &result);
    
    printf("\nInput: '%s'\n", input);
    printf("  Matched: %s, Captures: %d\n", 
           result.matched ? "true" : "false", 
           result.capture_count);
    
    for (int i = 0; i < result.capture_count; i++) {
        size_t start, length;
        dfa_get_capture_by_index(&result, i, &start, &length);
        printf("  Capture %d: start=%zu, len=%zu", i, start, length);
        if (length > 0 && start + length <= strlen(input)) {
            printf("  ['%.*s']", (int)length, input + start);
        }
        printf("\n");
    }
    
    free(data);
}

int main() {
    const char* dfa = "capture_edge.dfa";
    
    printf("=== Capture Edge Case Tests ===\n");
    
    test_input(dfa, "cp src dst");
    test_input(dfa, "mv file1 file2");
    test_input(dfa, "echo hello world");
    test_input(dfa, "touch file");
    test_input(dfa, "ls -la /tmp");
    test_input(dfa, "cat test.txt");
    test_input(dfa, "head -n 20");
    
    return 0;
}
