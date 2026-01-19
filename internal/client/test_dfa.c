#include <stdio.h>
#include "dfa.h"

int main(void) {
    printf("Testing DFA-based command validation\n");
    printf("=====================================\n\n");

    struct {
        const char* cmd;
        int expected_allow;
    } tests[] = {
        {"cat", 1},
        {"cat file.txt", 1},
        {"grep pattern file", 1},
        {"ls", 1},
        {"head -n 10 file", 1},
        {"tail -f log", 1},
        {"wc -l file", 1},
        {"git log", 1},
        {"git show", 1},
        {"git diff", 1},
        {"find . -name *.txt", 1},
        {"rm", 0},
        {"rm -rf", 0},
        {"mv", 0},
        {"cp", 0},
        {"curl", 0},
        {"wget", 0},
        {"ssh", 0},
        {"sudo", 0},
        {"chmod", 0},
        {"chown", 0},
        {"unknown_command", 0},
    };

    int passed = 0;
    int failed = 0;

    for (int i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
        int result = dfa_should_allow(tests[i].cmd);
        const char* status = (result == tests[i].expected_allow) ? "PASS" : "FAIL";
        if (result == tests[i].expected_allow) passed++; else failed++;
        printf("[%s] '%s' -> %s (expected: %s)\n",
               status, tests[i].cmd,
               result ? "ALLOW" : "SEND TO SERVER",
               tests[i].expected_allow ? "ALLOW" : "SEND TO SERVER");
    }

    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
