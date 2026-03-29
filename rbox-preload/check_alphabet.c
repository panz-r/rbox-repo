#include <stdio.h>
#include <stdint.h>

extern const unsigned char readonlybox_dfa_data[];

int main() {
    // Alphabet map is at offset 32
    printf("Alphabet map at offset 32:\n");
    printf("  'g' (0x67) -> %d\n", readonlybox_dfa_data[32 + 0x67]);
    printf("  'i' (0x69) -> %d\n", readonlybox_dfa_data[32 + 0x69]);
    printf("  't' (0x74) -> %d\n", readonlybox_dfa_data[32 + 0x74]);
    printf("  ' ' (0x20) -> %d\n", readonlybox_dfa_data[32 + 0x20]);
    printf("  'G' (0x47) -> %d\n", readonlybox_dfa_data[32 + 0x47]);
    printf("  'I' (0x49) -> %d\n", readonlybox_dfa_data[32 + 0x49]);
    printf("  'T' (0x54) -> %d\n", readonlybox_dfa_data[32 + 0x54]);
    printf("  '-' (0x2d) -> %d\n", readonlybox_dfa_data[32 + 0x2d]);
    
    // Header
    uint32_t init_state = *(uint32_t*)&readonlybox_dfa_data[8];
    uint16_t alphabet_size = *(uint16_t*)&readonlybox_dfa_data[16];
    printf("\nHeader:\n");
    printf("  initial_state: %d\n", init_state);
    printf("  alphabet_size: %d\n", alphabet_size);
    
    return 0;
}
