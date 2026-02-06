#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "include/dfa_types.h"

int main() {
    FILE* f = fopen("test_cat.dfa", "rb");
    if (!f) { fprintf(stderr, "Cannot open file\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    dfa_t* dfa = (dfa_t*)data;
    
    printf("DFA Header Analysis:\n");
    printf("  magic: 0x%08X (expected 0xDFA1DFA1)\n", dfa->magic);
    printf("  version: %d\n", dfa->version);
    printf("  state_count: %d\n", dfa->state_count);
    printf("  initial_state: %u (0x%X)\n", dfa->initial_state, dfa->initial_state);
    printf("  identifier_length: %d\n", dfa->identifier_length);
    
    // Calculate expected sizes
    size_t id_len = dfa->identifier_length;
    size_t header_size_v4 = 19 + id_len;
    size_t sizeof_dfa_t = sizeof(dfa_t);
    
    printf("\nSize Analysis:\n");
    printf("  sizeof(dfa_t): %zu\n", sizeof_dfa_t);
    printf("  sizeof(dfa_state_t): %zu\n", sizeof(dfa_state_t));
    printf("  sizeof(dfa_transition_t): %zu\n", sizeof(dfa_transition_t));
    printf("  Expected header_size (v4 formula): %zu\n", header_size_v4);
    printf("  Expected states_size: %zu\n", dfa->state_count * sizeof(dfa_state_t));
    
    // Check where initial_state actually points
    printf("\nInitial State Analysis:\n");
    printf("  initial_state = %u (decimal)\n", dfa->initial_state);
    
    if (dfa->initial_state < size) {
        printf("  Bytes at initial_state offset:\n");
        uint8_t* p = (uint8_t*)data + dfa->initial_state;
        for (int i = 0; i < 20 && (dfa->initial_state + i) < size; i++) {
            printf("    offset +%d: 0x%02X '%c'\n", i, p[i], (p[i] >= 32 && p[i] < 127) ? p[i] : '?');
        }
    }
    
    // Read first few states
    printf("\nFirst States Analysis:\n");
    for (int i = 0; i < 5 && i < dfa->state_count; i++) {
        size_t state_offset = 19 + id_len + i * sizeof(dfa_state_t);
        dfa_state_t* state = (dfa_state_t*)((char*)data + state_offset);
        printf("  state[%d] at offset %zu:\n", i, state_offset);
        printf("    transitions_offset: %u (0x%X)\n", state->transitions_offset, state->transitions_offset);
        printf("    transition_count: %d\n", state->transition_count);
        printf("    flags: 0x%04X\n", state->flags);
        
        // Check if transitions_offset is valid
        if (state->transitions_offset < size) {
            printf("    (valid offset, %zu bytes from end)\n", size - state->transitions_offset);
        } else {
            printf("    (INVALID offset - exceeds file size %ld!)\n", size);
        }
    }
    
    free(data);
    return 0;
}
