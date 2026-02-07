#include <stdio.h>
#include <stdint.h>

extern const unsigned char readonlybox_dfa_data[];

int main() {
    printf("Direct byte access:\n");
    printf("  byte[16] = 0x%02x\n", readonlybox_dfa_data[16]);
    printf("  byte[17] = 0x%02x\n", readonlybox_dfa_data[17]);
    printf("  Combined (little-endian) = 0x%04x\n", 
           (unsigned char)readonlybox_dfa_data[16] | 
           ((unsigned char)readonlybox_dfa_data[17] << 8));
    
    uint16_t via_pointer = *(uint16_t*)&readonlybox_dfa_data[16];
    printf("  Via pointer = %d\n", via_pointer);
    
    // Check what's actually at those bytes
    printf("\nFirst 20 bytes of data:\n  ");
    for (int i = 0; i < 20; i++) {
        printf("%02x ", (unsigned char)readonlybox_dfa_data[i]);
    }
    printf("\n");
    
    return 0;
}
