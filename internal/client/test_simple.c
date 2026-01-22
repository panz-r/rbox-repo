#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dfa.h"

extern const unsigned char readonlybox_dfa_data[];
extern const size_t readonlybox_dfa_size;

int main() {
    dfa_init();
    
    const char* tests[] = {"git log", "git status", "ls", "pwd", "wc -l"};
    for (int i = 0; i < 5; i++) {
        dfa_result_t result;
        dfa_evaluate(tests[i], 0, &result);
        printf("'%s': matched=%d, category=%d\n", tests[i], result.matched, result.category);
    }
    return 0;
}
