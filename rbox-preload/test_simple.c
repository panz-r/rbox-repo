#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dfa.h"

extern const unsigned char readonlybox_dfa_data[];
extern const size_t readonlybox_dfa_size;

int main() {
    dfa_init(readonlybox_dfa_data, readonlybox_dfa_size);

    const char* tests[] = {
        "git log --oneline",
        "which socat",
        "which bwrap",
        "git remote get-url origin",
        "git worktree list",
        "ls -la",
        "pwd"
    };

    for (int i = 0; i < 7; i++) {
        dfa_result_t result;
        dfa_evaluate(tests[i], 0, &result);
        printf("'%s': matched=%d, category=%d\n", tests[i], result.matched, result.category);
    }
    return 0;
}
