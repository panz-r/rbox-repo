#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"

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
    
    printf("Testing pattern: test <word>[a-z]+</word>\n\n");
    
    char* tests[] = {
        "test a",      // single early letter
        "test x",      // single late letter
        "test m",      // single middle letter
        "test abc",    // multiple early
        "test xyz",    // multiple late
        "test hello",  // common word
        "test z",      // last letter
        "test ab",     // two letters
        "test xy"      // two late letters
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    
    for (int i = 0; i < num_tests; i++) {
        dfa_evaluate(tests[i], 0, &result);
        printf("Input: '%s' -> Matched: %s\n", tests[i], result.matched ? "YES" : "NO");
    }
    
    free(data);
    return 0;
}
