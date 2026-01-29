#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE* f = fopen("readonlybox.dfa", "rb");
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    dfa_init(data, size);
    
    const char* tests[] = {
        "git status",
        "git",
        "git status ",
        "git status -s",
        NULL
    };
    
    for (int i = 0; tests[i]; i++) {
        dfa_result_t res;
        bool matched = dfa_evaluate(tests[i], strlen(tests[i]), &res);
        printf("'%s' -> matched=%s, len=%zu, cat=%d\n", 
               tests[i], matched && res.matched ? "yes" : "no", 
               res.matched_length, res.category);
    }
    
    free(data);
    return 0;
}
