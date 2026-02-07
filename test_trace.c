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
    
    const char* input = "git";
    printf("Testing '%s':\n", input);
    
    int len = strlen(input);
    bool matched = dfa_evaluate(input, len, &result);
    printf("  Result: matched=%s, category_mask=0x%02x\n", 
           matched ? "true" : "false", result.category_mask);
    
    free(data);
    return 0;
}
