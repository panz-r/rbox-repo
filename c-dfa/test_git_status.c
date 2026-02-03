#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

int main(int argc, char* argv[]) {
    const char* dfa_file = "/tmp/test_group.dfa";
    const char* test_input = "git status";
    
    // Load DFA file
    FILE* f = fopen(dfa_file, "rb");
    if (!f) {
        printf("Error: Cannot open DFA file: %s\n", dfa_file);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* data = malloc(size);
    if (!data) {
        printf("Error: Cannot allocate memory\n");
        fclose(f);
        return 1;
    }
    
    if (fread(data, 1, size, f) != (size_t)size) {
        printf("Error: Cannot read DFA file\n");
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);
    
    // Initialize DFA
    if (!dfa_init(data, size)) {
        printf("Error: Failed to initialize DFA\n");
        free(data);
        return 1;
    }
    
    // Evaluate 'git status'
    dfa_result_t result;
    bool matched = dfa_evaluate(test_input, strlen(test_input), &result);
    
    printf("Input: '%s'\n", test_input);
    printf("result.matched: %s\n", result.matched ? "true" : "false");
    printf("result.matched_length: %zu\n", result.matched_length);
    
    // Cleanup
    free(data);
    
    return 0;
}
