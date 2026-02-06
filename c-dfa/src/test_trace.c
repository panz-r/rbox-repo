#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    dfa_result_t result;
    size_t size;
    void* data = load_dfa_from_file("../test_cat.dfa", &size);
    if (!data) { fprintf(stderr, "Cannot load DFA\n"); return 1; }
    if (!dfa_init(data, size)) { fprintf(stderr, "DFA init failed\n"); return 1; }
    
    const char* tests[] = {"git ", "git s", "git st", "git sta", "git stat", "git status"};
    
    for (int i = 0; i < 6; i++) {
        printf("Testing '%s': ", tests[i]);
        int len = strlen(tests[i]);
        bool matched = dfa_evaluate(tests[i], len, &result);
        if (matched) {
            printf("MATCHED cat=0x%02x\n", result.category_mask);
        } else {
            printf("NOT MATCHED\n");
        }
    }
    
    free(data);
    return 0;
}
