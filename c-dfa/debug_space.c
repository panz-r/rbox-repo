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
    
    // Check all transitions from state 296 (after "git ")
    uint32_t state_296_offset = 20 + 296 * 12;
    printf("State 296 at offset %u:\n", state_296_offset);
    
    uint32_t trans_offset = *((uint32_t*)((char*)data + state_296_offset));
    uint16_t trans_count = *((uint16_t*)((char*)data + state_296_offset + 4));
    
    printf("  trans_offset=%u, trans_count=%d\n", trans_offset, trans_count);
    printf("  Looking for ' ' (32):\n");
    
    for (int t = 0; t < trans_count; t++) {
        size_t off = trans_offset + t * 5;
        unsigned char c = *((unsigned char*)((char*)data + off));
        uint32_t next = *((uint32_t*)((char*)data + off + 1));
        if (c == 32) {
            printf("    Found ' ' -> state %u (byte offset %u)\n", next, next);
            printf("    State index would be: %u\n", (next - 20) / 12);
        }
    }
    
    // Also check what transitions exist
    printf("\n  All transitions from state 296:\n");
    for (int t = 0; t < trans_count && t < 10; t++) {
        size_t off = trans_offset + t * 5;
        unsigned char c = *((unsigned char*)((char*)data + off));
        uint32_t next = *((uint32_t*)((char*)data + off + 1));
        printf("    char=%d ('%c') -> %u\n", c, c >= 32 && c < 127 ? c : '?', next);
    }
    
    free(data);
    return 0;
}
