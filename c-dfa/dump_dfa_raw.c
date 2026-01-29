#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "include/dfa_types.h"

int main() {
    FILE *f = fopen("readonlybox.dfa", "rb");
    if (!f) { perror("fopen"); return 1; }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    dfa_t *dfa = (dfa_t*)data;
    
    printf("Header:\n");
    printf("  magic: 0x%08X\n", dfa->magic);
    printf("  version: %d\n", dfa->version);
    printf("  state_count: %d\n", dfa->state_count);
    printf("  initial_state: %u\n", dfa->initial_state);
    printf("  sizeof(dfa_t): %zu\n", sizeof(dfa_t));
    printf("  sizeof(dfa_state_t): %zu\n", sizeof(dfa_state_t));
    printf("  states array start: %zu\n", sizeof(dfa_t));
    
    dfa_state_t *states = (dfa_state_t*)((char*)dfa + sizeof(dfa_t));
    
    printf("\nFirst 10 states:\n");
    for (int i = 0; i < 10 && i < dfa->state_count; i++) {
        printf("  [%d] trans_offset=%u, trans_count=%u, flags=0x%04X\n",
               i, states[i].transitions_offset, states[i].transition_count, states[i].flags);
    }
    
    printf("\nTransition table start (from state 0): %u\n", states[0].transitions_offset);
    
    // Check what's at offset 7
    printf("\nMemory at offset 7: ");
    uint8_t *p = (uint8_t*)data;
    for (int i = 0; i < 10; i++) {
        printf("%02X ", p[7 + i]);
    }
    printf("\n");
    
    return 0;
}
