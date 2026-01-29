#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DFA_STATE_ACCEPTING 0x0001

int main() {
    FILE* f = fopen("readonlybox.dfa", "rb");
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* data = malloc(file_size);
    fread(data, 1, file_size, f);
    fclose(f);
    
    dfa_init(data, file_size);
    
    // Check state 3224
    uint32_t state_offset = 3224;
    printf("State at offset %u:\n", state_offset);
    
    if (state_offset >= file_size) {
        printf("  ERROR: out of bounds!\n");
        return 1;
    }
    
    uint16_t flags = *((uint16_t*)((char*)data + state_offset + 6));
    printf("  flags=0x%04X\n", flags);
    printf("  accepting=%s\n", (flags & DFA_STATE_ACCEPTING) ? "YES" : "NO");
    
    // Check what state this is
    uint32_t trans_offset = *((uint32_t*)((char*)data + state_offset));
    uint16_t trans_count = *((uint16_t*)((char*)data + state_offset + 4));
    printf("  trans_offset=%u, trans_count=%d\n", trans_offset, trans_count);
    
    // Check accepting_mask from header
    uint32_t accepting_mask = *((uint32_t*)((char*)data + 12));
    printf("\nDFA accepting_mask: 0x%08X\n", accepting_mask);
    
    free(data);
    return 0;
}
