#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "include/dfa.h"
#include "include/dfa_types.h"

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
    printf("DFA header:\n");
    printf("  magic: 0x%08X\n", dfa->magic);
    printf("  version: %d\n", dfa->version);
    printf("  state_count: %d\n", dfa->state_count);
    printf("  initial_state: %u (offset)\n", dfa->initial_state);
    printf("  sizeof(dfa_t): %zu\n", sizeof(dfa_t));
    printf("  sizeof(dfa_state_t): %zu\n", sizeof(dfa_state_t));
    
    // Check first few states
    printf("\nFirst few states:\n");
    for (int i = 0; i < 5; i++) {
        dfa_state_t* state = (dfa_state_t*)((char*)data + dfa->initial_state + i * sizeof(dfa_state_t));
        printf("  state[%d] at offset %zu: flags=0x%04X, trans_count=%d, trans_offset=%u\n",
               i, (size_t)state - (size_t)data, state->flags, state->transition_count, state->transitions_offset);
    }
    
    // Check state 3 (which has CAPTURE_START)
    printf("\nState at offset 764 (index ~31):\n");
    dfa_state_t* state764 = (dfa_state_t*)((char*)data + 764);
    printf("  flags=0x%04X, trans_count=%d, trans_offset=%u\n",
           state764->flags, state764->transition_count, state764->transitions_offset);
    
    // Check transitions from state 764
    dfa_transition_t* trans = (dfa_transition_t*)((char*)data + state764->transitions_offset);
    printf("  Transitions:\n");
    for (int i = 0; i < state764->transition_count; i++) {
        printf("    [%d] char=%d (0x%02X), next_offset=%u\n", 
               i, trans[i].character, (unsigned char)trans[i].character, trans[i].next_state_offset);
    }
    
    // Now check: if next_offset is 90, what state is at offset 90?
    printf("\nChecking offset 90:\n");
    dfa_state_t* state90 = (dfa_state_t*)((char*)data + 90);
    printf("  At offset 90: flags=0x%04X, trans_count=%d\n", state90->flags, state90->transition_count);
    
    // Check what index state 90 would be
    int idx90 = (90 - sizeof(dfa_t)) / sizeof(dfa_state_t);
    printf("  Index if offset 90 is a state index: %d\n", idx90);
    
    free(data);
    return 0;
}
