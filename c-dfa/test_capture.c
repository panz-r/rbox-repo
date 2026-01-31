#include <stdio.h>
#include <stdlib.h>
#include "dfa.h"

int main() {
    FILE* f = fopen("/home/panz/osrc/lms-test/readonlybox/c-dfa/simple_capture.dfa", "rb");
    if (!f) { printf("Failed to open DFA\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    if (!dfa_init(data, size)) {
        printf("Failed to init DFA\n");
        return 1;
    }
    
    // Test "git log -n 10" - should capture "10"
    dfa_result_t result;
    bool ok = dfa_evaluate("git log -n 10", 0, &result);
    
    printf("Input: 'git log -n 10'\n");
    printf("Matched: %s\n", result.matched ? "true" : "false");
    printf("Capture count: %d\n", result.capture_count);
    
    for (int i = 0; i < result.capture_count; i++) {
        size_t start, length;
        dfa_get_capture_by_index(&result, i, &start, &length);
        printf("Capture %d: start=%zu, len=%zu\n", i, start, length);
        if (length > 0 && start + length <= 13) {
            printf("  Content: '%.*s'\n", (int)length, "git log -n 10" + start);
        }
    }
    
    free(data);
    return 0;
}
