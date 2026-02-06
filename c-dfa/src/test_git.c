#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    dfa_result_t result;
    size_t size;
    void* data = load_dfa_from_file("../test_cat.dfa", &size);
    if (!data) { fprintf(stderr, "Cannot load DFA\n"); return 1; }
    if (!dfa_init(data, size)) { fprintf(stderr, "DFA init failed\n"); return 1; }
    
    const char* tests[] = {"git status", "git log", "git push", "git fetch", "git commit"};
    uint8_t expected[] = {0x02, 0x02, 0x04, 0x04, 0x08};
    
    for (int i = 0; i < 5; i++) {
        printf("Testing '%s': ", tests[i]);
        if (dfa_evaluate(tests[i], 0, &result) && result.matched) {
            printf("MATCHED cat=0x%02x (expected 0x%02x) %s\n", 
                   result.category_mask, expected[i],
                   result.category_mask == expected[i] ? "OK" : "WRONG");
        } else {
            printf("NOT MATCHED (expected 0x%02x)\n", expected[i]);
        }
    }
    
    free(data);
    return 0;
}
