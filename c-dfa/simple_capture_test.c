#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

int main() {
    FILE* f = fopen("readonlybox.dfa", "rb");
    if (!f) { fprintf(stderr, "Failed to open DFA\n"); return 1; }
    
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
    
    printf("DFA loaded: %d states\n", dfa_get_state_count());
    
    // Test 1: Simple pattern without capture
    const char* test1 = "git status";
    dfa_result_t r1;
    dfa_evaluate(test1, strlen(test1), &r1);
    printf("Test 1 '%s': matched=%d, len=%zu, captures=%d\n", 
           test1, r1.matched, r1.matched_length, r1.capture_count);
    
    // Test 2: Pattern with capture
    const char* test2 = "cat test.txt";
    dfa_result_t r2;
    dfa_evaluate(test2, strlen(test2), &r2);
    printf("Test 2 '%s': matched=%d, len=%zu, captures=%d\n", 
           test2, r2.matched, r2.matched_length, r2.capture_count);
    
    // Test 3: Pattern with capture and limit
    dfa_result_t r3;
    dfa_evaluate_with_limit(test2, strlen(test2), &r3, 5);
    printf("Test 3 (limit=5) '%s': matched=%d, len=%zu, captures=%d\n", 
           test2, r3.matched, r3.matched_length, r3.capture_count);
    
    // Print capture details
    for (int i = 0; i < r2.capture_count; i++) {
        printf("  Capture %d: start=%zu, end=%zu\n", i, r2.captures[i].start, r2.captures[i].end);
    }
    
    free(data);
    return 0;
}
