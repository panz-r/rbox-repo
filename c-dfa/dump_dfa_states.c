#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

#define STATE_INDEX_TO_OFFSET(idx) (sizeof(dfa_t) + ((size_t)(idx) * sizeof(dfa_state_t)))

int main() {
    FILE* f = fopen("readonlybox.dfa", "rb");
    if (!f) return 1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    dfa_t* dfa = (dfa_t*)data;
    printf("DFA: %d states, initial_state=%u, sizeof(dfa_t)=%zu, sizeof(state)=%zu\n", 
           dfa->state_count, dfa->initial_state, sizeof(dfa_t), sizeof(dfa_state_t));
    
    // Check state INDEX 90 (which is at offset 20 + 90*12 = 1100)
    int state90_idx = 90;
    size_t state90_offset = STATE_INDEX_TO_OFFSET(state90_idx);
    printf("\nState INDEX %d at offset %zu:\n", state90_idx, state90_offset);
    dfa_state_t* s90 = (dfa_state_t*)((char*)data + state90_offset);
    printf("  flags=0x%04X, trans_count=%d, trans_offset=%u\n", s90->flags, s90->transition_count, s90->transitions_offset);
    
    if (s90->transition_count > 0) {
        dfa_transition_t* t90 = (dfa_transition_t*)((char*)data + s90->transitions_offset);
        for (int i = 0; i < s90->transition_count; i++) {
            printf("  trans[%d]: char=%d (0x%02X", i, t90[i].character, (unsigned char)t90[i].character);
            if (t90[i].character >= 32 && t90[i].character < 127) printf(" '%c'", t90[i].character);
            printf("), next_state_offset=%u", t90[i].next_state_offset);
            
            // Compute where this leads
            size_t next_offset = STATE_INDEX_TO_OFFSET(t90[i].next_state_offset);
            if (next_offset < (size_t)size) {
                dfa_state_t* s_next = (dfa_state_t*)((char*)data + next_offset);
                printf(" -> state %u (offset %zu, %d trans)", t90[i].next_state_offset, next_offset, s_next->transition_count);
            } else {
                printf(" -> INVALID OFFSET");
            }
            printf("\n");
        }
    }
    
    // Check state INDEX 62 (from space transition)
    int state62_idx = 62;
    size_t state62_offset = STATE_INDEX_TO_OFFSET(state62_idx);
    printf("\nState INDEX %d at offset %zu (after space):\n", state62_idx, state62_offset);
    dfa_state_t* s62 = (dfa_state_t*)((char*)data + state62_offset);
    printf("  flags=0x%04X, trans_count=%d, trans_offset=%u\n", s62->flags, s62->transition_count, s62->transitions_offset);
    
    if (s62->transition_count > 0 && s62->transition_count < 50) {
        dfa_transition_t* t62 = (dfa_transition_t*)((char*)data + s62->transitions_offset);
        for (int i = 0; i < s62->transition_count; i++) {
            printf("  trans[%d]: char=%d (0x%02X", i, t62[i].character, (unsigned char)t62[i].character);
            if (t62[i].character >= 32 && t62[i].character < 127) printf(" '%c'", t62[i].character);
            printf("), next_state_offset=%u\n", t62[i].next_state_offset);
        }
    }
    
    free(data);
    return 0;
}
