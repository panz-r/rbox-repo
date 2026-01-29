#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
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
    
    bool result = dfa_init(data, size);
    if (!result) {
        fprintf(stderr, "Failed to init DFA\n");
        free(data);
        return 1;
    }
    
    printf("Testing + quantifier on fragments:\n");
    printf("==================================\n\n");
    
    struct {
        const char* input;
        const char* pattern;
        int expected_match;
    } tests[] = {
        // Basic + quantifier tests (using fragments)
        {"ab", "a((TEST::B))+", 1},       // 1 'b' - should match
        {"abb", "a((TEST::B))+", 1},      // 2 'b's - should match  
        {"abbb", "a((TEST::B))+", 1},     // 3 'b's - should match
        {"abbbb", "a((TEST::B))+", 1},    // 4 'b's - should match
        {"ac", "a((TEST::B))+", 0},       // 'c' instead of 'b' - should NOT match
        {"abx", "a((TEST::B))+", 0},      // 'x' after 'b' - should NOT match
        
        // Test x((TEST::Y))+
        {"xy", "x((TEST::Y))+", 1},       // 1 'y' - should match
        {"xyy", "x((TEST::Y))+", 1},      // 2 'y's - should match
        {"xyyy", "x((TEST::Y))+", 1},     // 3 'y's - should match
        {"xyyyy", "x((TEST::Y))+", 1},    // 4 'y's - should match
        {"xz", "x((TEST::Y))+", 0},       // 'z' instead of 'y' - should NOT match
        
        // Test 1((TEST::TWO))+
        {"12", "1((TEST::TWO))+", 1},     // 1 '2' - should match
        {"122", "1((TEST::TWO))+", 1},    // 2 '2's - should match
        {"123", "1((TEST::TWO))+", 0},    // '3' after '2' - should NOT match
        {"12345", "1((TEST::TWO))+", 0},  // '3' after '2' - should NOT match
        
        // Edge cases
        {"a", "a((TEST::B))+", 0},        // No 'b' - should NOT match (needs at least 1)
        {"x", "x((TEST::Y))+", 0},        // No 'y' - should NOT match (needs at least 1)
        {"1", "1((TEST::TWO))+", 0},      // No '2' - should NOT match (needs at least 1)
    };
    
    int passed = 0;
    int failed = 0;
    
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        dfa_result_t result;
        bool matched = dfa_evaluate(tests[i].input, strlen(tests[i].input), &result);
        bool actual_match = (matched && result.matched);
        int correct = (actual_match == (tests[i].expected_match == 1));
        
        printf("Test %zu: input='%s' pattern='%s' expected=%s got=%s (len=%zu) - %s\n",
               i+1,
               tests[i].input,
               tests[i].pattern,
               tests[i].expected_match ? "match" : "no match",
               actual_match ? "match" : "no match",
               result.matched_length,
               correct ? "PASS" : "FAIL");
        
        if (correct) passed++;
        else failed++;
    }
    
    printf("\n==================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    
    free(data);
    return failed > 0 ? 1 : 0;
}
