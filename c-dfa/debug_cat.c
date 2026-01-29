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
    
    const char* tests[] = {
        "cat test.txt",
        "cat /path/to/file.txt",
        "cat *",
        "cat",
        "test.txt",
        NULL
    };
    
    for (int i = 0; tests[i]; i++) {
        dfa_result_t res;
        bool matched = dfa_evaluate(tests[i], strlen(tests[i]), &res);
        printf("Input: '%s' -> matched=%s, len=%zu, category=%d\n", 
               tests[i], matched && res.matched ? "yes" : "no", 
               res.matched_length, res.category);
    }
    
    free(data);
    return 0;
}
