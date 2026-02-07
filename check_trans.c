#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
    FILE* f = fopen("/home/panz/osrc/lms-test/readonlybox/c-dfa/readonlybox.dfa", "rb");
    if (!f) { fprintf(stderr, "Cannot open DFA\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    // Header at offset 0
    uint32_t initial_state = *(uint32_t*)&data[8];
    printf("Initial state offset: %d (0x%x)\n", initial_state, initial_state);
    
    // State 0 at offset 276 (0x114)
    uint32_t trans_offset = *(uint32_t*)&data[276];
    uint16_t trans_count = *(uint16_t*)&data[280];
    printf("State 0: trans_offset=%d, trans_count=%d\n", trans_offset, trans_count);
    
    // Calculate transitions start position
    // states at 276, 197 states * 8 bytes = 1576 bytes
    // transitions start at 276 + 1576 = 1852
    size_t transitions_start = 276 + 197 * 8;
    printf("Transitions start at: %zu\n", transitions_start);
    
    // First transition at transitions_start + trans_offset
    uint8_t char0 = data[transitions_start + trans_offset];
    uint32_t next0 = *(uint32_t*)&data[transitions_start + trans_offset + 1];
    printf("Trans[0]: char=%d (0x%02x), next=%d\n", char0, char0, next0);
    
    uint8_t char1 = data[transitions_start + trans_offset + 5];
    uint32_t next1 = *(uint32_t*)&data[transitions_start + trans_offset + 6];
    printf("Trans[1]: char=%d (0x%02x), next=%d\n", char1, char1, next1);
    
    free(data);
    return 0;
}
