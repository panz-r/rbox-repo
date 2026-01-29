#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE* f = fopen("readonlybox.dfa", "rb");
    if (!f) {
        fprintf(stderr, "Cannot open DFA file\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    bool result = dfa_init(data, size);
    printf("DFA init: %s\n", result ? "OK" : "FAILED");
    printf("DFA valid: %s\n", dfa_is_valid() ? "YES" : "NO");
    printf("DFA states: %d\n", dfa_get_state_count());

    const char* test_cases[] = {
        "cat",
        "cat *",
        "cat test.txt",
        "git status",
        "git push",
        "ls"
    };

    for (int i = 0; i < 6; i++) {
        dfa_result_t dfa_result;
        bool eval = dfa_evaluate(test_cases[i], 0, &dfa_result);
        printf("\nInput: '%s'\n", test_cases[i]);
        printf("  eval=%d, matched=%d, len=%zu, category=%d\n",
               eval, dfa_result.matched, dfa_result.matched_length, dfa_result.category);
    }

    return 0;
}
