#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint16_t flags;
    uint8_t trans_count;
    uint8_t trans_offset;  // Actually 24-bit, need to handle carefully
} dfa_state_header_t;
#pragma pack(pop)

int main() {
    FILE* f = fopen("simple.dfa", "rb");
    if (!f) { printf("Cannot open file\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    // Header: magic(4) + version(2) + state_count(2) + initial_offset(4)
    uint32_t magic = *(uint32_t*)data;
    uint16_t version = *(uint16_t*)(data + 4);
    uint16_t state_count = *(uint16_t*)(data + 6);
    uint32_t initial_offset = *(uint32_t*)(data + 8);
    
    printf("DFA Header:\n");
    printf("  Magic: 0x%08x\n", magic);
    printf("  Version: %d\n", version);
    printf("  State count: %d\n", state_count);
    printf("  Initial state offset: %d\n", initial_offset);
    printf("\n");
    
    // State table starts at offset 20
    uint32_t* state_offsets = (uint32_t*)(data + 20);
    
    for (int i = 0; i < state_count; i++) {
        uint32_t offset = state_offsets[i];
        if (offset == 0xFFFFFFFF) {
            printf("State %d: INVALID (offset=0xFFFFFFFF)\n", i);
            continue;
        }
        
        uint16_t flags = *(uint16_t*)(data + offset);
        uint8_t trans_count = *(uint8_t*)(data + offset + 2);
        uint8_t trans_offset_low = *(uint8_t*)(data + offset + 3);
        uint32_t trans_offset = trans_offset_low | ((*(uint32_t*)(data + offset + 4)) << 8);
        
        printf("State %d (offset=%u):\n", i, offset);
        printf("  flags=0x%04x, trans_count=%d, trans_offset=%u\n", flags, trans_count, trans_offset);
        
        // Print transitions
        for (int t = 0; t < trans_count && t < 10; t++) {
            uint32_t t_offset = trans_offset + t * 8;
            if (t_offset + 8 > size) break;
            
            uint8_t char_low = data[t_offset];
            uint8_t char_high = data[t_offset + 1];
            uint16_t c = char_low | (char_high << 8);
            int32_t next_offset = *(int32_t*)(data + t_offset + 4);
            
            if (c < 128 && c >= 32) {
                printf("    [%d]: char='%c' (%d) -> offset %d\n", t, (char)c, c, next_offset);
            } else {
                printf("    [%d]: char=%d -> offset %d\n", t, c, next_offset);
            }
        }
        printf("\n");
    }
    
    free(data);
    return 0;
}
