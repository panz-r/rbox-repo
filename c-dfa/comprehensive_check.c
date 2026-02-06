#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "include/dfa_types.h"

int main() {
    const char* filename = "test_cat.dfa";
    FILE* f = fopen(filename, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", filename); return 1; }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    printf("=== COMPREHENSIVE DFA FILE ANALYSIS ===\n\n");
    
    // Parse header
    uint32_t magic = *(uint32_t*)(data);
    uint16_t version = *(uint16_t*)(data + 4);
    uint16_t state_count = *(uint16_t*)(data + 6);
    uint32_t initial_state = *(uint32_t*)(data + 8);
    uint8_t id_len = data[18];
    
    printf("HEADER:\n");
    printf("  magic: 0x%08X %s\n", magic, magic == DFA_MAGIC ? "(OK)" : "(BAD)");
    printf("  version: %d\n", version);
    printf("  state_count: %d\n", state_count);
    printf("  initial_state: %u (0x%X)\n", initial_state, initial_state);
    printf("  identifier_length: %d\n", id_len);
    
    // Calculate expected positions
    size_t header_size = 19 + id_len;
    size_t states_size = state_count * sizeof(dfa_state_t);
    size_t states_start = header_size;
    size_t transitions_start = header_size + states_size;
    
    printf("\nEXPECTED CALCULATIONS:\n");
    printf("  sizeof(dfa_t): %zu\n", sizeof(dfa_t));
    printf("  sizeof(dfa_state_t): %zu\n", sizeof(dfa_state_t));
    printf("  sizeof(dfa_transition_t): %zu\n", sizeof(dfa_transition_t));
    printf("  header_size (19 + id_len): %zu\n", header_size);
    printf("  states_start: %zu\n", states_start);
    printf("  transitions_start: %zu\n", transitions_start);
    printf("  file_size: %ld\n", size);
    
    // Check if file is large enough
    printf("\nFILE SIZE VALIDATION:\n");
    size_t min_required = header_size + states_size;
    printf("  Minimum required: %zu bytes\n", min_required);
    printf("  File size: %ld bytes\n", size);
    printf("  Status: %s\n", size >= min_required ? "OK" : "TOO SMALL!");
    
    // Verify states_start
    printf("\nSTATES ARRAY VALIDATION:\n");
    printf("  States expected at offset: %zu\n", states_start);
    printf("  States end at offset: %zu\n", states_start + states_size);
    
    // Check initial_state field
    printf("\nINITIAL_STATE FIELD:\n");
    printf("  Stored initial_state: %u\n", initial_state);
    printf("  Expected (should equal header_size): %zu\n", header_size);
    printf("  Status: %s\n", initial_state == header_size ? "CORRECT" : "MISMATCH!");
    
    // Check first few states
    printf("\nFIRST 5 STATES:\n");
    for (int i = 0; i < 5 && i < state_count; i++) {
        size_t state_offset = states_start + i * sizeof(dfa_state_t);
        uint32_t trans_offset = *(uint32_t*)(data + state_offset);
        uint16_t trans_count = *(uint16_t*)(data + state_offset + 4);
        
        printf("  state[%d] at %zu: trans_offset=%u, trans_count=%d\n",
               i, state_offset, trans_offset, trans_count);
        
        // Verify trans_offset is valid
        if (trans_offset >= size) {
            printf("    ERROR: trans_offset %u exceeds file size %ld!\n", trans_offset, size);
        } else if (trans_offset < transitions_start) {
            printf("    WARNING: trans_offset %u is before transition table (expected >= %zu)\n",
                   trans_offset, transitions_start);
        }
    }
    
    // Check last few states
    printf("\nLAST 3 STATES:\n");
    for (int i = state_count - 3; i < state_count; i++) {
        if (i < 0) continue;
        size_t state_offset = states_start + i * sizeof(dfa_state_t);
        if (state_offset >= size) {
            printf("  state[%d] at %zu: PAST EOF!\n", i, state_offset);
            continue;
        }
        uint32_t trans_offset = *(uint32_t*)(data + state_offset);
        uint16_t trans_count = *(uint16_t*)(data + state_offset + 4);
        
        printf("  state[%d] at %zu: trans_offset=%u, trans_count=%d\n",
               i, state_offset, trans_offset, trans_count);
        
        if (trans_offset >= size) {
            printf("    ERROR: trans_offset %u exceeds file size %ld!\n", trans_offset, size);
        }
    }
    
    // Count invalid offsets
    int invalid_count = 0;
    for (int i = 0; i < state_count; i++) {
        size_t state_offset = states_start + i * sizeof(dfa_state_t);
        if (state_offset + 4 > size) { invalid_count++; continue; }
        uint32_t trans_offset = *(uint32_t*)(data + state_offset);
        if (trans_offset >= size || trans_offset < transitions_start) {
            invalid_count++;
        }
    }
    
    printf("\nSUMMARY:\n");
    printf("  Total states: %d\n", state_count);
    printf("  States with invalid trans_offset: %d\n", invalid_count);
    printf("  Overall status: %s\n", invalid_count == 0 ? "FILE APPEARS VALID" : "FILE HAS CORRUPTION!");
    
    free(data);
    return invalid_count > 0 ? 1 : 0;
}
