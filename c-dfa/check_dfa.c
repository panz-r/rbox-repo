#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "include/dfa_types.h"

int main(int argc, char* argv[]) {
    const char* filename = argc > 1 ? argv[1] : "test_captures.dfa";
    
    FILE *f = fopen(filename, "rb");
    if (!f) { perror("fopen"); return 1; }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    dfa_t *dfa = (dfa_t*)data;
    
    printf("File: %s\n", filename);
    printf("Magic: 0x%08X (expected 0x%08X)\n", dfa->magic, DFA_MAGIC);
    printf("Version: %d\n", dfa->version);
    printf("State count: %d\n", dfa->state_count);
    printf("Initial state offset: %u (0x%X)\n", dfa->initial_state, dfa->initial_state);
    printf("Accepting mask: 0x%08X\n", dfa->accepting_mask);
    printf("sizeof(dfa_t) = %zu\n", sizeof(dfa_t));
    printf("sizeof(dfa_state_t) = %zu\n", sizeof(dfa_state_t));
    printf("Total file size: %ld\n", size);
    printf("Identifier length: %d\n", dfa->identifier_length);

    // For Version 4, states start after the identifier
    size_t header_size = sizeof(dfa_t);
    if (dfa->version >= 4) {
        header_size += dfa->identifier_length;
    }
    dfa_state_t *states = (dfa_state_t*)((char*)dfa + header_size);
    for (int i = 0; i < dfa->state_count && i < 10; i++) {
        printf("\nState %d:\n", i);
        printf("  transitions_offset: %u (0x%X)\n", states[i].transitions_offset, states[i].transitions_offset);
        printf("  transition_count: %u\n", states[i].transition_count);
        printf("  flags: 0x%04X\n", states[i].flags);
    }
    
    return 0;
}
