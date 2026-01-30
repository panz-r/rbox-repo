#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    const char* pattern = "cat \\x3cfilename";
    printf("Pattern: '%s'\n", pattern);
    
    for (int i = 0; pattern[i]; i++) {
        printf("  [%d] '%c' (0x%02X)\n", i, pattern[i], (unsigned char)pattern[i]);
    }
    
    // Check for \x3c
    for (int i = 0; pattern[i]; i++) {
        if (pattern[i] == '\\' && pattern[i+1] == 'x') {
            printf("Found \\x at position %d\n", i);
            if (pattern[i+2] && pattern[i+3]) {
                char hex[3] = {pattern[i+2], pattern[i+3], 0};
                int val = (int)strtol(hex, NULL, 16);
                printf("  Hex: '%s' = %d (0x%02X = '%c')\n", hex, val, val, val);
            }
        }
    }
    
    return 0;
}
