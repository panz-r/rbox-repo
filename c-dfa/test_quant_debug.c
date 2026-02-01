#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <dfa_file> <test_string>\n", argv[0]);
        return 1;
    }
    
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        printf("Cannot open DFA file: %s\n", argv[1]);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    if (!dfa_init(data, size)) {
        printf("Failed to initialize DFA\n");
        return 1;
    }
    
    dfa_result_t result;
    const char* test = argv[2];
    bool matched = dfa_evaluate(test, 0, &result);
    
    printf("Testing: '%s'\n", test);
    printf("  matched: %s\n", matched ? "true" : "false");
    printf("  result.matched: %s\n", result.matched ? "true" : "false");
    printf("  result.matched_length: %zu\n", result.matched_length);
    printf("  result.category_mask: 0x%02x\n", result.category_mask);
    
    return 0;
}
