#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

#define STATE_INDEX_TO_OFFSET(idx) (sizeof(dfa_t) + ((size_t)(idx) * sizeof(dfa_state_t)))

void dump_state(void* data, int state_idx) {
    dfa_t* dfa = (dfa_t*)data;
    size_t offset = STATE_INDEX_TO_OFFSET(state_idx);
    
    if (offset >= (size_t)sizeof(dfa_t) + dfa->state_count * sizeof(dfa_state_t)) {
        printf("  State %d: INVALID OFFSET %zu\n", state_idx, offset);
        return;
    }
    
    dfa_state_t* state = (dfa_state_t*)((char*)data + offset);
    printf("  State %d (offset %zu): flags=0x%04X, trans_count=%d\n", 
           state_idx, offset, state->flags, state->transition_count);
    
    if (state->transition_count > 0 && state->transition_count < 100) {
        dfa_transition_t* trans = (dfa_transition_t*)((char*)data + state->transitions_offset);
        for (int i = 0; i < state->transition_count; i++) {
            printf("    [%d] char=%d (0x%02X", i, trans[i].character, (unsigned char)trans[i].character);
            if (trans[i].character >= 32 && trans[i].character < 127) printf(" '%c'", trans[i].character);
            printf(") -> state %u\n", trans[i].next_state_offset);
        }
    }
}

int main() {
    FILE* f = fopen("readonlybox.dfa", "rb");
    if (!f) return 1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    // Trace the path for "cat test.txt"
    printf("Tracing path for 'cat test.txt':\n");
    
    int state = 0; // Initial state index
    const char* input = "cat test.txt";
    
    dump_state(data, state);
    
    for (int pos = 0; input[pos]; pos++) {
        unsigned char c = input[pos];
        printf("  At pos %d, char '%c' (%d):\n", pos, c, c);
        
        dfa_t* dfa = (dfa_t*)data;
        size_t offset = STATE_INDEX_TO_OFFSET(state);
        dfa_state_t* cur = (dfa_state_t*)((char*)data + offset);
        
        int found = 0;
        if (cur->transition_count > 0) {
            dfa_transition_t* trans = (dfa_transition_t*)((char*)data + cur->transitions_offset);
            for (int i = 0; i < cur->transition_count; i++) {
                if (trans[i].character == 0 || trans[i].character == c) {
                    printf("    Found transition on %d, going to state %u\n", 
                           trans[i].character, trans[i].next_state_offset);
                    state = trans[i].next_state_offset;
                    dump_state(data, state);
                    found = 1;
                    break;
                }
            }
        }
        
        if (!found) {
            printf("    NO TRANSITION FOUND!\n");
            break;
        }
    }
    
    free(data);
    return 0;
}
