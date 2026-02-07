#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
    FILE* f = fopen("/home/panz/osrc/lms-test/readonlybox/c-dfa/mini.dfa", "rb");
    if (!f) { fprintf(stderr, "Cannot open DFA\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    // Header
    uint32_t magic = *(uint32_t*)&data[0];
    uint16_t version = *(uint16_t*)&data[4];
    uint16_t state_count = *(uint16_t*)&data[6];
    uint32_t init_state = *(uint32_t*)&data[8];
    uint16_t alphabet_size = *(uint16_t*)&data[16];
    
    printf("Header:\n");
    printf("  magic: 0x%08x\n", magic);
    printf("  version: %d\n", version);
    printf("  state_count: %d\n", state_count);
    printf("  init_state: %d\n", init_state);
    printf("  alphabet_size: %d\n", alphabet_size);
    
    // Transitions start
    size_t trans_start = init_state + state_count * 8;
    printf("\nTransitions start at: %zu\n", trans_start);
    
    // First state transitions
    uint32_t trans_offset = *(uint32_t*)&data[init_state];
    uint16_t trans_count = *(uint16_t*)&data[init_state + 4];
    printf("State 0: trans_offset=%d, trans_count=%d\n", trans_offset, trans_count);
    
    // Read transitions
    for (int i = 0; i < trans_count; i++) {
        uint8_t ch = data[trans_start + trans_offset + i * 5];
        uint32_t next = *(uint32_t*)&data[trans_start + trans_offset + i * 5 + 1];
        printf("  Trans[%d]: char=%d, next=%d\n", i, ch, next);
    }
    
    // Alphabet map
    printf("\nAlphabet map (first 16):\n");
    for (int i = 0; i < 16; i++) {
        printf("  [%d] = %d\n", i, data[32 + i]);
    }
    
    free(data);
    return 0;
}
