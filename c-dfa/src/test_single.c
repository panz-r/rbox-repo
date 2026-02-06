#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    const char* dfa_file = argc > 1 ? argv[1] : "readonlybox.dfa";
    const char* test_input = argc > 2 ? argv[2] : "ls";

    size_t size;
    void* data = load_dfa_from_file(dfa_file, &size);
    if (!data) {
        fprintf(stderr, "Cannot load DFA from %s\n", dfa_file);
        return 1;
    }

    if (!dfa_init(data, size)) {
        fprintf(stderr, "DFA init failed\n");
        free(data);
        return 1;
    }

    dfa_result_t result;
    bool matched = dfa_evaluate(test_input, 0, &result);

    printf("Input: '%s'\n", test_input);
    printf("Matched: %s\n", matched ? "true" : "false");
    printf("Category mask: 0x%02x\n", result.category_mask);
    printf("Final state: 0x%04x\n", result.final_state);
    printf("Matched length: %zu\n", result.matched_length);

    free(data);
    return 0;
}
