#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
    FILE* f = fopen("c-dfa/test.dfa", "rb");
    if (!f) { fprintf(stderr, "Cannot open DFA file\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    // Read header
    uint32_t magic = *(uint32_t*)&data[0];
    uint16_t version = *(uint16_t*)&data[4];
    uint16_t state_count = *(uint16_t*)&data[6];
    uint32_t initial_state = *(uint32_t*)&data[8];
    uint32_t accepting_mask = *(uint32_t*)&data[12];
    uint16_t alphabet_size = *(uint16_t*)&data[16];
    uint16_t reserved = *(uint16_t*)&data[18];
    
    printf("Header:\n");
    printf("  magic: 0x%08x\n", magic);
    printf("  version: %d\n", version);
    printf("  state_count: %d\n", state_count);
    printf("  initial_state: %d (0x%x)\n", initial_state, initial_state);
    printf("  accepting_mask: 0x%08x\n", accepting_mask);
    printf("  alphabet_size: %d\n", alphabet_size);
    
    // Calculate offsets
    size_t header_size = 20; // dfa_header_t
    size_t alphabet_map_size = 256;
    size_t states_offset = header_size + alphabet_map_size;
    size_t state_size = 8; // dfa_state_t
    size_t transitions_start = states_offset + state_count * state_size;
    
    printf("\nLayout:\n");
    printf("  header_size: %zu\n", header_size);
    printf("  alphabet_map at: %zu\n", header_size);
    printf("  states at: %zu\n", states_offset);
    printf("  transitions_start: %zu\n", transitions_start);
    printf("  initial_state offset in data: %d\n", initial_state);
    
    // Read state 0
    printf("\nState 0 at offset %d:\n", initial_state);
    uint32_t state0_offset = *(uint32_t*)&data[initial_state];
    uint16_t state0_count = *(uint16_t*)&data[initial_state + 4];
    uint16_t state0_flags = *(uint16_t*)&data[initial_state + 6];
    
    printf("  transitions_offset (relative): %d\n", state0_offset);
    printf("  transition_count: %d\n", state0_count);
    printf("  flags: 0x%04x\n", state0_flags);
    
    // Read transitions at transitions_start + state0_offset
    size_t trans_addr = transitions_start + state0_offset;
    printf("\nReading transitions at %zu (transitions_start + state0.transitions_offset):\n", trans_addr);
    for (int i = 0; i < state0_count && i < 5; i++) {
        uint8_t ch = data[trans_addr + i * 5];
        uint32_t next = *(uint32_t*)&data[trans_addr + i * 5 + 1];
        printf("  trans[%d]: char=%d (0x%02x), next_offset=%d\n", i, ch, ch, next);
    }
    
    free(data);
    return 0;
}
