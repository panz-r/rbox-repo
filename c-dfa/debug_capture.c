#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"

int main() {
    // Load DFA
    FILE* f = fopen("readonlybox.dfa", "rb");
    if (!f) {
        fprintf(stderr, "Failed to open DFA file\n");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    if (!dfa_init(data, size)) {
        fprintf(stderr, "Failed to init DFA\n");
        return 1;
    }
    
    printf("DFA loaded successfully\n");
    printf("Version: %d, States: %d\n", dfa_get_version(), dfa_get_state_count());
    
    // Test cat with capture
    const char* test = "cat test.txt";
    dfa_result_t result;
    
    printf("\nTesting: '%s'\n", test);
    dfa_evaluate(test, strlen(test), &result);
    
    printf("Result: matched=%d, len=%zu, category=%s, captures=%d\n",
           result.matched, result.matched_length,
           dfa_category_string(result.category),
           result.capture_count);
    
    for (int i = 0; i < result.capture_count; i++) {
        printf("  Capture %d: start=%zu, end=%zu\n", 
               i, result.captures[i].start, result.captures[i].end);
    }
    
    free(data);
    return 0;
}
