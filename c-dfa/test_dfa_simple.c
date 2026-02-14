#include <stdio.h>
#include <stdlib.h>
#include "include/dfa.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dfa_file> <test_string>\n", argv[0]);
        return 1;
    }

    size_t size;
    void* data = load_dfa_from_file(argv[1], &size);
    if (!data) {
        fprintf(stderr, "Failed to load DFA from %s\n", argv[1]);
        return 1;
    }

    if (!dfa_init(data, size)) {
        fprintf(stderr, "Failed to init DFA\n");
        free(data);
        return 1;
    }

    printf("DFA loaded: %u states, version %u\n", 
           dfa_get_state_count(), dfa_get_version());

    dfa_result_t result;
    if (dfa_evaluate(argv[2], 0, &result)) {
        printf("MATCH: category=%s (%02X), length=%zu\n",
               dfa_category_string(result.category),
               result.category_mask,
               result.matched_length);
    } else {
        printf("NO MATCH\n");
    }

    dfa_reset();
    free(data);
    return 0;
}
