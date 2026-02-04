#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

int main() {
    const char* dfa_file = "/home/panz/osrc/lms-test/readonlybox/c-dfa/build/readonlybox.dfa";
    
    FILE* f = fopen(dfa_file, "rb");
    if (!f) {
        printf("Error: Cannot open DFA file: %s\n", dfa_file);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* data = malloc(size);
    if (!data) {
        printf("Error: Cannot allocate memory\n");
        fclose(f);
        return 1;
    }
    
    if (fread(data, 1, size, f) != (size_t)size) {
        printf("Error: Cannot read DFA file\n");
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);
    
    if (!dfa_init(data, size)) {
        printf("Error: Failed to initialize DFA\n");
        free(data);
        return 1;
    }
    
    const char* tests[] = {
        "git status",
        "ls -la",
        "cat file.txt",
        "echo hello world",
        "git  status",
        "ls   -la",
        NULL
    };
    
    printf("Testing space patterns:\n");
    printf("========================\n\n");
    
    for (int i = 0; tests[i] != NULL; i++) {
        dfa_result_t result;
        bool matched = dfa_evaluate(tests[i], strlen(tests[i]), &result);
        printf("Input: '%s' (len=%zu)\n", tests[i], strlen(tests[i]));
        printf("  matched: %s\n", matched ? "true" : "false");
        printf("  matched_length: %zu\n", result.matched_length);
        printf("\n");
    }
    
    free(data);
    return 0;
}
