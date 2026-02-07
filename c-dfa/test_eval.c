#include <stdio.h>
#include <stdlib.h>
#include "include/dfa_types.h"
#include "src/dfa_loader.c"
#include "src/dfa_eval.c"

int main() {
    size_t size;
    void* data = load_dfa_from_file("build_test/test.dfa", &size);
    if (!data) {
        fprintf(stderr, "Failed to load DFA\n");
        return 1;
    }
    
    if (!dfa_init(data, size)) {
        fprintf(stderr, "Failed to init DFA\n");
        return 1;
    }
    
    const char* tests[] = {"a", "b", "aa", "ab", "ba", "aaa", NULL};
    for (int i = 0; tests[i]; i++) {
        dfa_result_t result;
        dfa_evaluate(tests[i], 0, &result);
        printf("'%s': matched=%s, len=%zu, cat=0x%02x\n", 
               tests[i], 
               result.matched ? "YES" : "NO",
               result.matched_length,
               result.category_mask);
    }
    
    free(data);
    return 0;
}
