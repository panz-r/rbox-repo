#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// DFA structures with proper packing
#pragma pack(push, 1)
typedef struct {
    uint32_t transitions_offset;
    uint16_t transition_count;
    uint16_t flags;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
    int8_t eos_target;
} dfa_state_t;

typedef struct {
    char character;
    uint32_t next_state_offset;
} dfa_transition_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t state_count;
    uint32_t initial_state;
    uint32_t accepting_mask;
    uint16_t flags;
    uint16_t reserved;
} dfa_header_t;
#pragma pack(pop)

#define DFA_GET_CATEGORY_MASK(flags) ((flags) >> 8)

void print_state_details(const char* dfa_data, int state_idx) {
    const dfa_header_t* header = (const dfa_header_t*)dfa_data;
    size_t raw_base = (size_t)dfa_data;
    
    size_t state_offset = sizeof(dfa_header_t) + state_idx * sizeof(dfa_state_t);
    const dfa_state_t* state = (const dfa_state_t*)(raw_base + state_offset);
    
    printf("State %d at offset 0x%04zX:\n", state_idx, state_offset);
    printf("  transitions_offset: 0x%08X\n", state->transitions_offset);
    printf("  transition_count: %d\n", state->transition_count);
    printf("  flags: 0x%04X (category_mask=0x%02X)\n", 
           state->flags, DFA_GET_CATEGORY_MASK(state->flags));
    printf("  capture_start_id: %d\n", state->capture_start_id);
    printf("  capture_end_id: %d\n", state->capture_end_id);
    printf("  eos_target: %d\n", state->eos_target);
    
    if (state->transition_count > 0 && state->transitions_offset > 0) {
        printf("  Transitions:\n");
        const dfa_transition_t* trans = (const dfa_transition_t*)(raw_base + state->transitions_offset);
        for (int i = 0; i < state->transition_count && i < 20; i++) {
            unsigned char c = (unsigned char)trans[i].character;
            printf("    [%d] char=0x%02X ('%c') -> offset=0x%08X\n", 
                   i, c, (c >= 32 && c < 127) ? c : '.', trans[i].next_state_offset);
        }
        if (state->transition_count > 20) {
            printf("    ... (%d more transitions)\n", state->transition_count - 20);
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dfa_file> [state_index]\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *dfa_data = malloc(size);
    fread(dfa_data, 1, size, f);
    fclose(f);
    
    const dfa_header_t* header = (const dfa_header_t*)dfa_data;
    printf("DFA Header:\n");
    printf("  magic: 0x%08X\n", header->magic);
    printf("  version: %d\n", header->version);
    printf("  state_count: %d\n", header->state_count);
    printf("  initial_state offset: %d\n", header->initial_state);
    printf("  header size: %zu bytes\n", sizeof(dfa_header_t));
    printf("  state size: %zu bytes\n", sizeof(dfa_state_t));
    printf("\n");
    
    int state_idx = 0;
    if (argc > 2) {
        state_idx = atoi(argv[2]);
        print_state_details(dfa_data, state_idx);
    } else {
        // Print first 10 states
        for (int i = 0; i < 10 && i < header->state_count; i++) {
            print_state_details(dfa_data, i);
        }
    }
    
    free(dfa_data);
    return 0;
}
