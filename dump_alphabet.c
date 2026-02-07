#include <stdio.h>
#include <stdint.h>

extern const unsigned char readonlybox_dfa_data[];

int main() {
    printf("First 64 bytes of alphabet_map (starting at byte 32):\n");
    for (int i = 0; i < 64; i++) {
        uint8_t val = readonlybox_dfa_data[32 + i];
        if (i % 16 == 0) printf("  [%d] ", i);
        printf("%02x ", val);
        if (i % 16 == 15) printf("\n");
    }
    
    printf("\nSpecific character mappings:\n");
    int chars[] = {0x67, 0x69, 0x74, 0x47, 0x49, 0x54, 0x20, 0x2d};
    for (int i = 0; i < 8; i++) {
        int c = chars[i];
        printf("  0x%02x ('%c') -> %d\n", c, c >= 32 && c < 127 ? c : '?', readonlybox_dfa_data[32 + c]);
    }
    
    return 0;
}
