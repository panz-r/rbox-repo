#include <stdio.h>
#include <string.h>
#include "dfa.h"

int main(void) {
    printf("DFA Debug Tests\n");
    printf("===============\n\n");

    if (!dfa_init()) {
        printf("DFA init failed!\n");
        return 1;
    }

    printf("DFA initialized successfully\n");

    // Trace through some commands
    const char* tests[] = {
        "git log",
        "git status",
        "ls",
        "pwd",
        "git blame *",
        "git checkout",
        "rm file.txt",
    };

    for (int i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
        dfa_result_t result;
        dfa_evaluate(tests[i], strlen(tests[i]), &result);
        printf("'%s' -> matched=%d, category=%d\n",
               tests[i], result.matched, result.category);
    }

    return 0;
}
