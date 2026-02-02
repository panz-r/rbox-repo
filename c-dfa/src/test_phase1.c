#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"

int main() {
    dfa_result_t result;

    printf("Testing x((y))+ DFA\n");
    printf("====================\n\n");

    // Load DFA
    size_t size;
    void* data = load_dfa_from_file("build/phase1.dfa", &size);
    if (!data) {
        printf("Failed to load DFA\n");
        return 1;
    }

    if (!dfa_init(data, size)) {
        printf("Failed to init DFA\n");
        free(data);
        return 1;
    }

    // Test cases
    const char* tests[] = {
        "x",     // should NOT match (needs at least one y)
        "xy",    // should match (len=2)
        "xyy",   // should match (len=3)
        "xyyy",  // should match (len=4)
        "xz",    // should NOT match
        "xyz",   // should NOT match
        "yx",    // should NOT match
        NULL
    };

    for (int i = 0; tests[i] != NULL; i++) {
        memset(&result, 0, sizeof(result));
        bool matched = dfa_evaluate(tests[i], strlen(tests[i]), &result);

        printf("'%s': matched=%s, len=%zu, category=0x%02X",
               tests[i],
               matched ? "YES" : "NO",
               result.matched_length,
               result.category_mask);

        if (matched && result.category_mask & 0x01) {
            printf(" [SAFE]");
        }
        printf("\n");
    }

    dfa_reset();
    free(data);
    return 0;
}
