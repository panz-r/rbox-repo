#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

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
    uint32_t magic;
    uint16_t version;
    uint16_t state_count;
    uint32_t initial_state;
    uint32_t accepting_mask;
    uint16_t flags;
    uint16_t reserved;
} dfa_header_t;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dfa_file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    dfa_header_t header;
    fread(&header, sizeof(header), 1, f);
    
    printf("Magic: 0x%08X\n", header.magic);
    printf("Version: %d\n", header.version);
    printf("State count: %d\n", header.state_count);
    printf("Initial state offset: %d\n", header.initial_state);
    printf("\n");
    
    printf("States with non-zero category_mask (flags >> 8):\n");
    printf("State | Offset   | flags  | cat_mask | trans_offset | trans_count\n");
    printf("------|----------|--------|----------|--------------|------------\n");
    
    for (int i = 0; i < header.state_count; i++) {
        dfa_state_t state;
        fread(&state, sizeof(state), 1, f);
        
        uint8_t category_mask = (state.flags >> 8) & 0xFF;
        if (category_mask != 0) {
            printf("%5d | %08X | 0x%04X | 0x%02X     | %08X     | %d\n",
                   i, 
                   (int)(sizeof(header) + i * sizeof(state)),
                   state.flags,
                   category_mask,
                   state.transitions_offset,
                   state.transition_count);
        }
    }
    
    fclose(f);
    return 0;
}
