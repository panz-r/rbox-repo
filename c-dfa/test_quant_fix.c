#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"

int main() {
    FILE* f = fopen("simple.dfa", "rb");
    if (!f) { printf("Failed to open DFA\n"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    if (!dfa_init(data, size)) { printf("Failed to init DFA\n"); return 1; }
    
    dfa_result_t result;
    char* tests[] = {"test a", "test hello", "test abc", "test xyz123", "test x"};
    int num_tests = 5;
    
    printf("Testing pattern: test <word>[a-z]+</word>\n\n");
    
    for (int i = 0; i < num_tests; i++) {
        dfa_evaluate(tests[i], 0, &result);
        printf("Input: '%s' -> Matched: %s (len=%zu)\n", 
               tests[i], 
               result.matched ? "YES" : "NO",
               result.matched_length);
    }
    
    free(data);
    return 0;
}
