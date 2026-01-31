#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "include/dfa_types.h"

int main() {
    FILE* f = fopen("simple.dfa", "rb");
    if (!f) { printf("Cannot open file\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    dfa_t* dfa = (dfa_t*)data;
    
    printf("DFA Header:\n");
    printf("  Magic: 0x%08X (expected 0x%08X)\n", dfa->magic, DFA_MAGIC);
    printf("  Version: %d\n", dfa->version);
    printf("  State count: %d\n", dfa->state_count);
    printf("  Initial state offset: %u\n", dfa->initial_state);
    printf("  Accepting mask: 0x%08X\n", dfa->accepting_mask);
    printf("  sizeof(dfa_t) = %zu\n", sizeof(dfa_t));
    printf("  sizeof(dfa_state_t) = %zu\n", sizeof(dfa_state_t));
    printf("\n");
    
    for (int i = 0; i < dfa->state_count; i++) {
        dfa_state_t* state = &dfa->states[i];
        printf("State %d (offset=%zu):\n", i, (size_t)((uint8_t*)state - data));
        printf("  transitions_offset: %u\n", state->transitions_offset);
        printf("  transition_count: %u\n", state->transition_count);
        printf("  flags: 0x%04X", state->flags);
        if (state->flags & DFA_STATE_ACCEPTING) printf(" ACCEPTING");
        if (state->flags & DFA_STATE_CAPTURE_START) printf(" CAPTURE_START");
        if (state->flags & DFA_STATE_CAPTURE_END) printf(" CAPTURE_END");
        printf("\n");
        printf("  capture_start_id: %d\n", state->capture_start_id);
        printf("  capture_end_id: %d\n", state->capture_end_id);
        
        if (state->transitions_offset > 0 && state->transition_count > 0) {
            printf("  Transitions:\n");
            for (int t = 0; t < state->transition_count && t < 30; t++) {
                // Each transition is 5 bytes packed
                uint8_t* trans_ptr = data + state->transitions_offset + t * 5;
                char c = trans_ptr[0];
                uint32_t next_offset = *(uint32_t*)(trans_ptr + 1);
                
                // Find state index from offset
                int next_state = -1;
                for (int s = 0; s < dfa->state_count; s++) {
                    if ((uint32_t)((uint8_t*)&dfa->states[s] - data) == next_offset) {
                        next_state = s;
                        break;
                    }
                }
                
                if (c >= 32 && c < 127) {
                    printf("    [%d]: '%c' (0x%02X) -> state %d (offset %u)\n", 
                           t, c, (unsigned char)c, next_state, next_offset);
                } else if (c == 0) {
                    printf("    [%d]: ANY (0x00) -> state %d\n", t, next_state);
                } else if (c == 5) {
                    printf("    [%d]: EOS (0x05) -> state %d\n", t, next_state);
                } else {
                    printf("    [%d]: 0x%02X -> state %d\n", t, (unsigned char)c, next_state);
                }
            }
        }
        printf("\n");
    }
    
    free(data);
    return 0;
}
