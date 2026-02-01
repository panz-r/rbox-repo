#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "dfa.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dfa_file> [test_string]\n", argv[0]);
        return 1;
    }

    const char* dfa_file = argv[1];
    const char* test_str = argc > 2 ? argv[2] : "abc";

    // Load DFA
    FILE* f = fopen(dfa_file, "rb");
    if (!f) {
        printf("Error: Cannot open %s\n", dfa_file);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    dfa_t dfa;
    if (!dfa_init(data, size, &dfa)) {
        printf("Error: Failed to initialize DFA\n");
        free(data);
        return 1;
    }

    printf("DFA loaded: %d states, %d symbols\n", 
           ((uint16_t*)data)[2], ((uint16_t*)data)[3]);

    // Test the string
    dfa_result_t result;
    bool matched = dfa_evaluate(test_str, 0, &result);

    printf("\nTesting: '%s'\n", test_str);
    printf("  matched: %s\n", result.matched ? "true" : "false");
    printf("  category_mask: 0x%02x\n", result.category_mask);
    printf("  matched_length: %zu\n", result.matched_length);

    // Also test other strings
    const char* tests[] = {"ab", "abb", "abc", "abcb", "abcbb", "x"};
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    printf("\n--- Multiple Tests ---\n");
    for (int i = 0; i < num_tests; i++) {
        dfa_evaluate(tests[i], 0, &result);
        printf("'%s': matched=%s, cat=0x%02x, len=%zu\n",
               tests[i],
               result.matched ? "true" : "false",
               result.category_mask,
               result.matched_length);
    }

    dfa_free(&dfa);
    free(data);
    return 0;
}
