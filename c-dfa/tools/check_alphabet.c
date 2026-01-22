#include <stdio.h>
#include <stdint.h>

int main() {
    // Load the NFA alphabet
    FILE* f = fopen("../readonlybox.nfa", "r");
    if (!f) { fprintf(stderr, "Cannot open NFA file\n"); return 1; }
    
    char line[256];
    int alphabet_size = 0;
    int symbol_ids[64];
    int start_chars[64];
    int end_chars[64];
    
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "  Symbol %d: %d-%d", &alphabet_size, &start_chars[alphabet_size], &end_chars[alphabet_size]) == 3) {
            symbol_ids[alphabet_size] = alphabet_size;
            printf("Symbol %d: id=%d, range=%d-%d\n", alphabet_size, symbol_ids[alphabet_size], start_chars[alphabet_size], end_chars[alphabet_size]);
            alphabet_size++;
        }
        if (alphabet_size >= 64) break;
    }
    fclose(f);
    
    printf("\nAlphabet entries:\n");
    for (int i = 0; i < 10; i++) {
        printf("  i=%d: symbol_id=%d\n", i, symbol_ids[i]);
    }
    
    return 0;
}
