#include <stdio.h>
#include <stdint.h>

extern const unsigned char readonlybox_dfa_data[];
extern const size_t readonlybox_dfa_size;

int main() {
    printf("DFA size: %zu\n", readonlybox_dfa_size);
    
    // Read header
    uint32_t init_state = *(uint32_t*)&readonlybox_dfa_data[8];
    uint16_t state_count = *(uint16_t*)&readonlybox_dfa_data[6];
    size_t trans_start = init_state + state_count * 8;
    
    printf("Initial state: %d\n", init_state);
    printf("State count: %d\n", state_count);
    printf("Transitions start: %zu\n", trans_start);
    
    // First two transitions
    uint8_t char0 = readonlybox_dfa_data[trans_start + 0];
    uint32_t next0 = *(uint32_t*)&readonlybox_dfa_data[trans_start + 1];
    uint8_t char1 = readonlybox_dfa_data[trans_start + 5];
    uint32_t next1 = *(uint32_t*)&readonlybox_dfa_data[trans_start + 6];
    
    printf("Trans[0]: char=%d, next=%d\n", char0, next0);
    printf("Trans[1]: char=%d, next=%d\n", char1, next1);
    
    return 0;
}
