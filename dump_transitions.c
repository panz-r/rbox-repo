#include <stdio.h>
#include <stdint.h>

extern const unsigned char readonlybox_dfa_data[];

int main() {
    uint32_t initial_state = *(uint32_t*)&readonlybox_dfa_data[8];
    uint16_t state_count = *(uint16_t*)&readonlybox_dfa_data[6];
    
    printf("State 0 at offset %d:\n", initial_state);
    uint32_t trans_offset = *(uint32_t*)&readonlybox_dfa_data[initial_state];
    uint16_t trans_count = *(uint16_t*)&readonlybox_dfa_data[initial_state + 4];
    
    printf("  transitions_offset: %d\n", trans_offset);
    printf("  transition_count: %d\n", trans_count);
    
    // Print all transitions for state 0
    printf("\nState 0 transitions:\n");
    for (int i = 0; i < trans_count; i++) {
        uint8_t ch = readonlybox_dfa_data[initial_state + 6 + i * 5];
        uint32_t next = *(uint32_t*)&readonlybox_dfa_data[initial_state + 6 + i * 5 + 1];
        printf("  [%d] char=%d (0x%02x) -> offset %d\n", i, ch, ch, next);
    }
    
    // Also check what's at the initial_state offset more carefully
    printf("\nBytes at initial_state offset (%d):\n  ", initial_state);
    for (int i = 0; i < 20; i++) {
        printf("%02x ", readonlybox_dfa_data[initial_state + i]);
    }
    printf("\n");
    
    return 0;
}
