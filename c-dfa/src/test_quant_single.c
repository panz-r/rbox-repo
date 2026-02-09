#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t size;
    void* data = load_dfa_from_file("c-dfa/readonlybox.dfa", &size);
    if (!data) return 1;
    if (!dfa_init(data, size)) return 1;
    dfa_result_t result;
    bool matched = dfa_evaluate("abb", 0, &result);
    printf("Result: %s, mask=0x%02x\n", matched ? "true" : "false", result.category_mask);
    return 0;
}