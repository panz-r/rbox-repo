#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
    FILE* f = fopen("/home/panz/osrc/lms-test/readonlybox/c-dfa/readonlybox.dfa", "rb");
    if (!f) return 1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    // Read header
    uint32_t magic = *(uint32_t*)&data[0];
    uint16_t state_count = *(uint16_t*)&data[6];
    uint32_t initial_state = *(uint32_t*)&data[8];
    
    printf("Magic: 0x%08x\n", magic);
    printf("State count: %d\n", state_count);
    printf("Initial state: %d\n", initial_state);
    
    // Transitions start at initial_state + state_count * sizeof(dfa_state_t)
    size_t states_start = initial_state;
    size_t trans_start = states_start + state_count * 8;
    
    printf("States start: %zu\n", states_start);
    printf("Transitions start: %zu\n", trans_start);
    
    // Read state 0
    uint32_t trans_offset = *(uint32_t*)&data[states_start];
    uint16_t trans_count = *(uint16_t*)&data[states_start + 4];
    
    printf("State 0: trans_offset=%d, trans_count=%d\n", trans_offset, trans_count);
    
    // Read transitions
    size_t first_trans = trans_start + trans_offset;
    printf("\nFirst transition at %zu:\n", first_trans);
    for (int i = 0; i < trans_count && i < 3; i++) {
        size_t pos = first_trans + i * 5;
        uint8_t ch = data[pos];
        uint32_t next = *(uint32_t*)&data[pos + 1];
        printf("  [%d] byte[%zu]=%d (0x%02x), next=0x%08x (%d)\n", i, pos, ch, ch, next, next);
    }
    
    free(data);
    return 0;
}
