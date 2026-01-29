#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE* f = fopen("readonlybox.dfa", "rb");
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* data = malloc(file_size);
    fread(data, 1, file_size, f);
    fclose(f);
    
    dfa_init(data, file_size);
    
    // Read header
    uint32_t magic = *((uint32_t*)data);
    uint16_t version = *((uint16_t*)((char*)data + 4));
    uint16_t state_count = *((uint16_t*)((char*)data + 6));
    uint32_t initial_state = *((uint32_t*)((char*)data + 8));
    
    printf("Header: magic=0x%08X, version=%d, states=%d, initial=%u\n", 
           magic, version, state_count, initial_state);
    
    // Check state 476
    uint32_t state_476_offset = 20 + 476 * 12;  // header + state_index * state_size
    printf("\nState 476 at offset %u:\n", state_476_offset);
    
    if (state_476_offset >= file_size) {
        printf("  ERROR: out of bounds!\n");
        return 1;
    }
    
    uint32_t trans_offset = *((uint32_t*)((char*)data + state_476_offset));
    uint16_t trans_count = *((uint16_t*)((char*)data + state_476_offset + 4));
    uint16_t flags = *((uint16_t*)((char*)data + state_476_offset + 6));
    uint32_t eos_target = *((uint32_t*)((char*)data + state_476_offset + 8));
    
    printf("  trans_offset=%u, trans_count=%d, flags=0x%04X, eos_target=%u\n",
           trans_offset, trans_count, flags, eos_target);
    
    printf("  Transitions:\n");
    for (int t = 0; t < trans_count; t++) {
        size_t off = trans_offset + t * 5;
        unsigned char c = *((unsigned char*)((char*)data + off));
        uint32_t next = *((uint32_t*)((char*)data + off + 1));
        printf("    char=%d ('%c') -> %u\n", c, c >= 32 && c < 127 ? c : '?', next);
    }
    
    // Check if 's' is in the pattern "git status"
    // The state after "git " should transition on 's'
    printf("\nLooking for 's' (115): ");
    bool found = false;
    for (int t = 0; t < trans_count; t++) {
        size_t off = trans_offset + t * 5;
        unsigned char c = *((unsigned char*)((char*)data + off));
        if (c == 115) {
            printf("FOUND at transition %d\n", t);
            found = true;
            break;
        }
    }
    if (!found) printf("NOT FOUND\n");
    
    // Check other git patterns
    printf("\nPatterns starting with 'git ':\n");
    system("grep\\[safe:git -E '^' patterns_safe_commands.txt | head -20");
    
    free(data);
    return 0;
}
