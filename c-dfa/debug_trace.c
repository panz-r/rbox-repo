#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE* f = fopen("safe_final.dfa", "rb");
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* data = malloc(file_size);
    fread(data, 1, file_size, f);
    fclose(f);
    
    dfa_init(data, file_size);
    
    const char* input = "git";
    uint32_t state_offset = 20;
    
    printf("Initial state offset: %u\n", state_offset);
    
    for (int pos = 0; input[pos] != '\0'; pos++) {
        unsigned char c = input[pos];
        
        // Bounds check
        if (state_offset >= file_size || state_offset < 20) {
            printf("ERROR: state_offset %u out of bounds [%d, %ld)\n", state_offset, 20, file_size);
            break;
        }
        
        uint32_t trans_offset = *((uint32_t*)((char*)data + state_offset));
        uint16_t trans_count = *((uint16_t*)((char*)data + state_offset + 4));
        uint16_t flags = *((uint16_t*)((char*)data + state_offset + 6));
        
        printf("Pos %d: '%c'(%d) -> state=%u, trans_off=%u, count=%d, flags=0x%04X\n", 
               pos, c >= 32 ? c : '?', c, state_offset, trans_offset, trans_count, flags);
        
        // Find transition
        bool found = false;
        for (int t = 0; t < trans_count; t++) {
            size_t off = trans_offset + t * 5;
            if (off >= file_size) continue;
            unsigned char tc = *((unsigned char*)((char*)data + off));
            if (tc == c) {
                state_offset = *((uint32_t*)((char*)data + off + 1));
                printf("  -> Found! Next state at %u\n", state_offset);
                found = true;
                break;
            }
        }
        
        if (!found) {
            printf("  -> NO TRANSITION for '%c'(%d)\n", c >= 32 ? c : '?', c);
            break;
        }
    }
    
    // Check final state flags
    uint16_t final_flags = *((uint16_t*)((char*)data + state_offset + 6));
    uint8_t accepting_mask = (final_flags >> 8) & 0xFF;
    printf("\nFinal state: offset=%u, flags=0x%04X, accepting_mask=0x%02X\n", 
           state_offset, final_flags, accepting_mask);
    
    free(data);
    return 0;
}
