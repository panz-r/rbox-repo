#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "dfa.h"

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

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

    if (!dfa_init(data, size)) {
        fprintf(stderr, "Failed to load DFA\n");
        free(data);
        return 1;
    }

    printf("DFA loaded\n");

    const char* tests[] = {
        "c",
        "ca",
        "cat",
        "catt",
        "ch",
        "cha",
        "chm",
        "chmo",
        "chmod",
        "git",
        NULL
    };

    for (int i = 0; tests[i] != NULL; i++) {
        dfa_result_t result;
        bool eval_ok = dfa_evaluate(tests[i], 0, &result);
        printf("'%s' -> eval=%d, matched=%d, len=%zu, category=0x%02x\n",
               tests[i], eval_ok, result.matched, result.matched_length, result.category);
    }

    dfa_reset();
    return 0;
}
