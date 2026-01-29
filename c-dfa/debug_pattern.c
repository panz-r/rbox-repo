#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_LINE_LENGTH 2048

int find_symbol_id(unsigned char c, int alphabet[][3], int alphabet_size) {
    for (int i = 0; i < alphabet_size; i++) {
        if (c >= alphabet[i][0] && c <= alphabet[i][1]) {
            return alphabet[i][2];
        }
    }
    return -1;
}

int main() {
    // Load alphabet
    int alphabet[32][3];
    int alphabet_size = 0;
    
    FILE* f = fopen("tools/alphabet.map", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f) && alphabet_size < 32) {
            if (line[0] == '#') continue;
            int sid, start, end;
            if (sscanf(line, "%d %d %d", &sid, &start, &end) >= 3) {
                alphabet[alphabet_size][0] = start;
                alphabet[alphabet_size][1] = end;
                alphabet[alphabet_size][2] = sid;
                alphabet_size++;
            }
        }
        fclose(f);
    }
    
    printf("Alphabet size: %d\n", alphabet_size);
    
    // Check pattern "git status"
    const char* pattern = "[safe:git:read] git status";
    
    printf("\nPattern: '%s'\n", pattern);
    
    // Parse pattern
    const char* p = pattern;
    while (*p && *p != ']') p++;  // Skip category
    if (*p == ']') p++;
    
    while (*p == ' ' || *p == '\t') p++;  // Skip whitespace
    
    printf("Pattern part: '%s'\n", p);
    
    // Check each character
    printf("\nCharacter analysis:\n");
    for (int i = 0; p[i]; i++) {
        char c = p[i];
        int sid = find_symbol_id(c, alphabet, alphabet_size);
        printf("  '%c' (%d) -> symbol %d\n", c >= 32 ? c : '?', (int)(unsigned char)c, sid);
    }
    
    return 0;
}
