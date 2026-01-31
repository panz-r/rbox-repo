#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

int main() {
    const char* dfa_path = "capture_edge.dfa";
    const char* input = "cp src dst";
    
    FILE* f = fopen(dfa_path, "rb");
    if (!f) { printf("Failed to open DFA\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    printf("DFA size: %zu bytes\n", size);
    
    if (!dfa_init(data, size)) {
        printf("Failed to init DFA\n");
        free(data);
        return 1;
    }
    
    printf("DFA initialized, version: %d, states: %d\n", 
           dfa_get_version(), dfa_get_state_count());
    
    dfa_result_t result;
    bool ok = dfa_evaluate(input, strlen(input), &result);
    
    printf("\nInput: '%s'\n", input);
    printf("Evaluate returned: %s\n", ok ? "true" : "false");
    printf("  Matched: %s\n", result.matched ? "true" : "false");
    printf("  Matched Length: %zu\n", result.matched_length);
    printf("  Captures: %d\n", result.capture_count);
    
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
    return 0;
}
