#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"
#include "dfa_types.h"

int main() {
    // Load DFA
    FILE* f = fopen("minimal.dfa", "rb");
    if (!f) {
        fprintf(stderr, "Cannot open minimal.dfa\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    if (!dfa_init(data, size)) {
        fprintf(stderr, "DFA init failed\n");
        return 1;
    }

    printf("Testing minimal DFA:\n");

    dfa_result_t result;

    // Test 1: 'cat' should match
    bool t1 = dfa_evaluate("cat", 0, &result);
    printf("  'cat': matched=%s, category=0x%02x\n", result.matched ? "YES" : "NO", result.category_mask);

    // Test 2: 'dog' should match
    bool t2 = dfa_evaluate("dog", 0, &result);
    printf("  'dog': matched=%s, category=0x%02x\n", result.matched ? "YES" : "NO", result.category_mask);

    // Test 3: 'a' should NOT match (needs at least one 'b')
    bool t3 = dfa_evaluate("a", 0, &result);
    printf("  'a': matched=%s (expected NO)\n", result.matched ? "YES" : "NO");

    // Test 4: 'ab' should match
    bool t4 = dfa_evaluate("ab", 0, &result);
    printf("  'ab': matched=%s, len=%zu (expected YES, len=2)\n", result.matched ? "YES" : "NO", result.matched_length);

    // Test 5: 'abb' should match
    bool t5 = dfa_evaluate("abb", 0, &result);
    printf("  'abb': matched=%s, len=%zu (expected YES, len=3)\n", result.matched ? "YES" : "NO", result.matched_length);

    // Test 6: 'abx' should NOT match (x is not b)
    bool t6 = dfa_evaluate("abx", 0, &result);
    printf("  'abx': matched=%s, len=%zu, category=0x%02x (expected NO)\n",
           result.matched ? "YES" : "NO", result.matched_length, result.category_mask);

    // Summary
    int passed = 0;
    if (!t3) passed++;
    if (t4 && result.matched_length == 2) passed++;
    if (t5 && result.matched_length == 3) passed++;
    if (!t6) passed++;
    printf("\nPassed: %d/4\n", passed);

    return (passed == 4) ? 0 : 1;
}
