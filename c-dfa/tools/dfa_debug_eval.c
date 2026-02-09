#include "../include/dfa.h"
#include <stdio.h>
#include <stdlib.h>

// Forward declaration of the loader
void* load_dfa_from_file(const char* filename, size_t* size);

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dfa_file> <input_string>\n", argv[0]);
        return 1;
    }
    size_t size;
    void* data = load_dfa_from_file(argv[1], &size);
    if (!data) {
        fprintf(stderr, "Failed to load DFA\n");
        return 1;
    }
    if (!dfa_init(data, size)) {
        fprintf(stderr, "Failed to init DFA\n");
        return 1;
    }
    dfa_result_t result;
    bool matched = dfa_evaluate(argv[2], 0, &result);
    printf("Input: '%s'\n", argv[2]);
    printf("Matched: %s\n", matched ? "YES" : "NO");
    printf("Matched Length: %zu\n", result.matched_length);
    printf("Category Mask: 0x%02x\n", result.category_mask);
    printf("Final State: %u\n", result.final_state);
    return 0;
}
