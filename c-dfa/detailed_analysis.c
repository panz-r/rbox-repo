#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "include/dfa_types.h"

int main() {
    FILE* f = fopen("test_cat.dfa", "rb");
    if (!f) return 1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    printf("FILE SIZE: %ld bytes\n\n", size);
    
    // Parse header
    uint32_t magic = *(uint32_t*)(data + 0);
    uint16_t version = *(uint16_t*)(data + 4);
    uint16_t state_count = *(uint16_t*)(data + 6);
    uint32_t initial_state = *(uint32_t*)(data + 8);
    uint32_t accepting_mask = *(uint32_t*)(data + 12);
    uint16_t flags = *(uint16_t*)(data + 16);
    uint8_t id_len = data[18];
    
    printf("HEADER ANALYSIS:\n");
    printf("  magic: 0x%08X\n", magic);
    printf("  version: %d\n", version);
    printf("  state_count: %d\n", state_count);
    printf("  initial_state: %u (0x%X)\n", initial_state, initial_state);
    printf("  accepting_mask: 0x%08X\n", accepting_mask);
    printf("  flags: 0x%04X\n", flags);
    printf("  identifier_length: %d\n", id_len);
    
    // Calculate expected positions
    size_t sizeof_dfa_t = sizeof(dfa_t);  // 20 with padding
    size_t expected_header_v4 = 19 + id_len;  // Should be 25
    size_t states_start_v4 = expected_header_v4;  // Should be 25
    
    printf("\nSIZE CALCULATIONS:\n");
    printf("  sizeof(dfa_t): %zu\n", sizeof_dfa_t);
    printf("  sizeof(dfa_state_t): %zu\n", sizeof(dfa_state_t));
    printf("  Expected header_size (19 + id_len): %zu\n", expected_header_v4);
    printf("  Expected states array start: %zu\n", states_start_v4);
    printf("  Expected states array end: %zu\n", states_start_v4 + state_count * sizeof(dfa_state_t));
    
    printf("\nIDENTIFIER (offset 19, len %d):\n", id_len);
    for (int i = 0; i < id_len && 19 + i < size; i++) {
        printf("  [%d] 0x%02X '%c'\n", 19 + i, data[19 + i], 
               (data[19 + i] >= 32 && data[19 + i] < 127) ? data[19 + i] : '?');
    }
    
    printf("\nSTATE ARRAY CORRUPTION CHECK:\n");
    printf("  If states start at offset %zu (sizeof(dfa_t)):\n", sizeof_dfa_t);
    printf("    Byte at offset %zu: 0x%02X\n", sizeof_dfa_t, data[sizeof_dfa_t]);
    printf("    This SHOULD be first state.transitions_offset[0]\n");
    printf("  If states start at offset %zu (19+id_len):\n", expected_header_v4);
    printf("    Byte at offset %zu: 0x%02X\n", expected_header_v4, data[expected_header_v4]);
    printf("    This SHOULD be first state.transitions_offset[0]\n");
    
    // Read first state at CORRECT position (19 + id_len = 25)
    printf("\nFIRST STATE (at offset %zu = 19 + id_len):\n", expected_header_v4);
    uint32_t trans_offset = *(uint32_t*)(data + expected_header_v4);
    uint16_t trans_count = *(uint16_t*)(data + expected_header_v4 + 4);
    printf("  transitions_offset: %u (0x%X)\n", trans_offset, trans_offset);
    printf("  transition_count: %u\n", trans_count);
    printf("  flags: 0x%04X\n", *(uint16_t*)(data + expected_header_v4 + 6));
    
    // Now check what the state array looks like at WRONG position (sizeof(dfa_t) = 20)
    printf("\nWRONG STATE POSITION (at offset %zu = sizeof(dfa_t)):\n", sizeof_dfa_t);
    printf("  Byte 0: 0x%02X '%c' (should be part of identifier, not state data!)\n",
           data[sizeof_dfa_t], 
           (data[sizeof_dfa_t] >= 32 && data[sizeof_dfa_t] < 127) ? data[sizeof_dfa_t] : '?');
    
    // Check actual bytes around transition offset
    printf("\nTRANSITION TABLE CHECK:\n");
    printf("  File size: %ld\n", size);
    printf("  State array should end at: %zu\n", states_start_v4 + state_count * sizeof(dfa_state_t));
    printf("  Transition table should start at: %zu\n", 
           states_start_v4 + state_count * sizeof(dfa_state_t));
    
    if (trans_offset < size) {
        printf("  Stored transitions_offset %u is WITHIN file bounds\n", trans_offset);
        printf("  At offset %u:\n", trans_offset);
        for (int i = 0; i < 10 && trans_offset + i < size; i++) {
            printf("    +%d: 0x%02X\n", i, data[trans_offset + i]);
        }
    } else {
        printf("  ERROR: Stored transitions_offset %u EXCEEDS file size %ld!\n", trans_offset, size);
    }
    
    // The real question: what is the CORRECT first state transitions_offset?
    printf("\nRECONSTRUCTING CORRECT STATE[0]:\n");
    printf("  State[0] is at offset %zu\n", states_start_v4);
    printf("  State[0].transitions_offset bytes: ");
    for (int i = 0; i < 4; i++) {
        printf("0x%02X ", data[states_start_v4 + i]);
    }
    printf("\n");
    
    // Calculate what it SHOULD be
    size_t correct_trans_offset = states_start_v4 + state_count * sizeof(dfa_state_t);
    printf("  CORRECT transitions_offset should be: %zu (0x%zX)\n", 
           correct_trans_offset, correct_trans_offset);
    
    free(data);
    return 0;
}
