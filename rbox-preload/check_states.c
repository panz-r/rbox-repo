#include <stdio.h>
#include <stdint.h>

extern const unsigned char readonlybox_dfa_data[];

int main() {
    // Header fields
    uint32_t initial_state = *(uint32_t*)&readonlybox_dfa_data[8];
    uint16_t state_count = *(uint16_t*)&readonlybox_dfa_data[6];
    
    printf("Initial state offset: %d (0x%x)\n", initial_state, initial_state);
    printf("State count: %d\n", state_count);
    
    // Check what's at initial_state offset
    printf("\nAt initial_state offset (%d):\n", initial_state);
    uint32_t trans_offset = *(uint32_t*)&readonlybox_dfa_data[initial_state];
    uint16_t trans_count = *(uint16_t*)&readonlybox_dfa_data[initial_state + 4];
    
    printf("  transitions_offset: %d\n", trans_offset);
    printf("  transition_count: %d\n", trans_count);
    
    // Print first few transitions
    printf("\nFirst transitions:\n");
    for (int i = 0; i < trans_count && i < 5; i++) {
        uint8_t ch = readonlybox_dfa_data[initial_state + 6 + i * 5];
        uint32_t next = *(uint32_t*)&readonlybox_dfa_data[initial_state + 6 + i * 5 + 1];
        printf("  trans[%d]: char=%d, next_offset=%d\n", i, ch, next);
    }
    
    return 0;
}
