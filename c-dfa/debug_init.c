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
    
    // Check initial state
    uint32_t magic = *((uint32_t*)data);
    uint16_t version = *((uint16_t*)((char*)data + 4));
    uint16_t state_count = *((uint16_t*)((char*)data + 6));
    uint32_t initial_state = *((uint32_t*)((char*)data + 8));
    
    printf("DFA Header:\n");
    printf("  Magic: 0x%08X\n", magic);
    printf("  Version: %d\n", version);
    printf("  State count: %d\n", state_count);
    printf("  Initial state offset: %u\n", initial_state);
    
    // Check initial state transitions
    uint32_t trans_offset = *((uint32_t*)((char*)data + initial_state));
    uint16_t trans_count = *((uint16_t*)((char*)data + initial_state + 4));
    
    printf("\nInitial state (offset %u):\n", initial_state);
    printf("  trans_offset=%u, trans_count=%d\n", trans_offset, trans_count);
    printf("  Transitions:\n");
    for (int t = 0; t < trans_count && t < 20; t++) {
        unsigned char c = *((unsigned char*)((char*)data + trans_offset + t*5));
        uint32_t next = *((uint32_t*)((char*)data + trans_offset + t*5 + 1));
        printf("    char=%d ('%c') -> %u\n", c, c >= 32 && c < 127 ? c : '?', next);
    }
    
    // Test "which socat"
    dfa_result_t result;
    bool matched = dfa_evaluate("which socat", 0, &result);
    printf("\n'which socat': matched=%s, len=%zu, category=%d\n",
           matched && result.matched ? "yes" : "no",
           result.matched_length, result.category);
    
    free(data);
    return 0;
}
