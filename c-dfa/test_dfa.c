#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

int main() {
    // Load DFA
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

    if (!dfa_init(data, size)) {
        fprintf(stderr, "Failed to init DFA\n");
        free(data);
        return 1;
    }

    printf("DFA loaded: %u states\n", dfa_get_state_count());

    const char* tests[] = {
        "cat",
        "cat file.txt",
        "grep",
        "grep pattern *",
        "git",
        "git log",
        "git log --oneline",
        "rm -rf /",
        NULL
    };

    for (int i = 0; tests[i] != NULL; i++) {
        dfa_result_t result;
        dfa_evaluate(tests[i], strlen(tests[i]), &result);
        printf("'%s' -> matched=%d, category=%d (0x%02x), len=%zu\n",
               tests[i], result.matched, result.category, result.category_mask, result.matched_length);
    }

    dfa_reset();
    free(data);
    return 0;
}
