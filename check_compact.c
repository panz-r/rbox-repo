#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
    FILE* f = fopen("/home/panz/osrc/lms-test/readonlybox/c-dfa/test.dfa", "rb");
    if (!f) return 1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    // Read header
    uint32_t initial_state = *(uint32_t*)&data[8];
    uint16_t state_count = *(uint16_t*)&data[6];
    
    printf("Initial state: %d\n", initial_state);
    printf("State count: %d\n", state_count);
    
    // Transitions start at initial_state + state_count * sizeof(dfa_state_t)
    // But we need to check what sizeof(dfa_state_t) actually is in the binary
    printf("\nReading states:\n");
    for (int i = 0; i < 3; i++) {
        uint32_t trans_offset = *(uint32_t*)&data[initial_state + i * 8];
        uint16_t trans_count = *(uint16_t*)&data[initial_state + i * 8 + 4];
        printf("  State %d: trans_offset=%d, trans_count=%d\n", i, trans_offset, trans_count);
    }
    
    // Transitions start
    size_t states_size = state_count * 8;  // dfa_state_t is 8 bytes (4 + 2 + 2 with padding)
    size_t trans_start = initial_state + states_size;
    printf("\nStates total size: %zu\n", states_size);
    printf("Transitions start at: %zu\n", trans_start);
    
    // First transition at trans_start + trans_offset
    uint8_t char0 = data[trans_start + 0];
    uint32_t next0 = *(uint32_t*)&data[trans_start + 1];
    printf("\nTrans[0]: char=%d, next=0x%08x (%d)\n", char0, next0, next0);
    
    uint8_t char1 = data[trans_start + 5];
    uint32_t next1 = *(uint32_t*)&data[trans_start + 6];
    printf("Trans[1]: char=%d, next=0x%08x (%d)\n", char1, next1, next1);
    
    free(data);
    return 0;
}
