#include <stdio.h>
#include <stdlib.h>
#include "dfa.h"
int main() {
    FILE* f = fopen("test.dfa", "rb");
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    dfa_init(data, size);
    dfa_result_t r;
    dfa_evaluate("git log -n 3", 0, &r);
    printf("git log -n 3 matched: %s (should be NO)\n", r.matched ? "YES" : "NO");
    dfa_evaluate("git log -n 1", 0, &r);
    printf("git log -n 1 matched: %s (should be YES)\n", r.matched ? "YES" : "NO");
    free(data);
    return 0;
}
