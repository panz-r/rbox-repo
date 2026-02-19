/**
 * End-to-End Capture Test
 * Tests nested capture extraction from DFA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../include/dfa_types.h"
#include "../include/dfa.h"
#include "../include/nfa.h"

static bool dfa_loaded = false;

void test_match(const char* input, const char* expected_pattern, int expected_captures) {
    if (!dfa_loaded) {
        printf("SKIP: DFA not loaded\n");
        return;
    }

    dfa_result_t result;
    if (!dfa_evaluate(input, strlen(input), &result)) {
        printf("FAIL: '%s' - No match (expected '%s')\n", input, expected_pattern);
        return;
    }

    printf("TEST: '%s'\n", input);
    printf("  Match: len=%zu, cat=0x%02X\n", result.matched_length, result.category_mask);

    int actual_captures = result.capture_count;
    if (actual_captures != expected_captures) {
        printf("  FAIL: Expected %d captures, got %d\n", expected_captures, actual_captures);
    } else {
        printf("  PASS: %d captures\n", actual_captures);
    }

    for (int i = 0; i < actual_captures && i < 16; i++) {
        printf("    [%d] '%s' = '%.*s' (pos %d-%d)\n",
               i, result.captures[i].name,
               result.captures[i].end - result.captures[i].start,
               input + result.captures[i].start,
               result.captures[i].start,
               result.captures[i].end);
    }
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    const char* dfa_file = "test_markers.dfa";
    if (argc > 1) dfa_file = argv[1];

    printf("=================================================\n");
    printf("END-TO-END CAPTURE TEST\n");
    printf("=================================================\n\n");

    FILE* f = fopen(dfa_file, "rb");
    if (!f) {
        printf("ERROR: Could not open %s\n", dfa_file);
        printf("Run: ./tools/nfa_builder test/nested_captures.txt test_markers.nfa\n");
        printf("     ./tools/nfa2dfa_advanced test_markers.nfa test_markers.dfa\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* data = malloc(size);
    if (fread(data, 1, size, f) != (size_t)size) {
        printf("ERROR: Failed to read DFA file\n");
        free(data);
        return 1;
    }
    fclose(f);

    if (!dfa_init(data, size)) {
        printf("ERROR: Failed to initialize DFA\n");
        free(data);
        return 1;
    }

    dfa_loaded = true;
    printf("DFA loaded successfully (%ld bytes)\n\n", size);

    test_match("git log", "cmd+op", 2);
    printf("\n");
    test_match("git status", "cmd+op", 2);
    printf("\n");
    test_match("git", "git", 1);
    printf("\n");
    test_match("log", "log", 1);

    printf("\n=================================================\n");
    printf("END-TO-END CAPTURE TEST COMPLETE\n");
    printf("=================================================\n");

    return 0;
}
