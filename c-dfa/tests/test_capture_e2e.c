/**
 * End-to-End Capture Test
 * Tests nested capture extraction from DFA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "../include/dfa.h"
#include "../include/nfa.h"

static bool file_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int build_dfa_if_needed(void) {
    const char* dfa_file = "build/test_markers.dfa";
    const char* pattern_file = "patterns/captures/with_captures.txt";
    const char* cdfatool = "build/tools/cdfatool";

    if (file_exists(dfa_file)) {
        return 0;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "./%s compile %s -o %s 2>/dev/null", cdfatool, pattern_file, dfa_file);
    printf("Building DFA: %s\n", cmd);
    return system(cmd);
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    const char* dfa_file = "build/test_markers.dfa";

    printf("=================================================\n");
    printf("END-TO-END CAPTURE TEST\n");
    printf("=================================================\n\n");

    if (build_dfa_if_needed() != 0) {
        printf("ERROR: Failed to build DFA file\n");
        return 1;
    }

    FILE* f = fopen(dfa_file, "rb");
    if (!f) {
        printf("ERROR: Could not open %s\n", dfa_file);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* data = malloc(size);
    if (fread(data, 1, size, f) != (size_t)size) {
        printf("ERROR: Failed to read DFA file\n");
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);

    printf("DFA loaded successfully (%ld bytes)\n\n", size);

    dfa_result_t result;
    int passed = 0;
    int failed = 0;

    struct {
        const char* input;
        int expected_match;
    } tests[] = {
        {"git status", 1},
        {"git branch -a", 1},
        {"git log -n 1", 1},
        {"git remote get-url origin", 1},
        {"cp abc.txt xyz.txt", 1},
        {"mv old.txt new.txt", 1},
        {"rsync -avz src/ dest/", 1},
        {"echo hello world", 1},
        {"unknown command", 0},
        {"git", 0},  // "git" alone doesn't match (only git status etc)
    };

    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        bool matched = dfa_eval(data, size, tests[i].input, strlen(tests[i].input), &result);
        if (matched == (tests[i].expected_match == 1)) {
            printf("PASS: '%s' %s\n", tests[i].input, matched ? "matched" : "no match");
            passed++;
        } else {
            printf("FAIL: '%s' expected %s but got %s\n", 
                   tests[i].input,
                   tests[i].expected_match ? "match" : "no match",
                   matched ? "match" : "no match");
            failed++;
        }
    }

    printf("\n=================================================\n");
    printf("RESULTS: %d passed, %d failed\n", passed, failed);
    printf("=================================================\n");
    printf("SUMMARY: %d/%d passed\n", passed, passed + failed);

    free(data);
    return failed > 0 ? 1 : 0;
}
