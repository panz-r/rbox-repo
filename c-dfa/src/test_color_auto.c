#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    dfa_result_t result;
    size_t size;
    void* data = load_dfa_from_file("../readonlybox.dfa", &size);
    if (!data) { fprintf(stderr, "Cannot load DFA\n"); return 1; }
    if (!dfa_init(data, size)) { fprintf(stderr, "DFA init failed\n"); return 1; }
    
    printf("Testing 'ls --color-auto':\n");
    if (dfa_evaluate("ls --color-auto", 0, &result) && result.matched) {
        printf("  MATCHED - category_mask=0x%02x\n", result.category_mask);
    } else {
        printf("  NOT MATCHED\n");
    }
    
    printf("Testing 'ls -la':\n");
    if (dfa_evaluate("ls -la", 0, &result) && result.matched) {
        printf("  MATCHED - category_mask=0x%02x\n", result.category_mask);
    } else {
        printf("  NOT MATCHED\n");
    }
    
    free(data);
    return 0;
}
