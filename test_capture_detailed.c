#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"
#include "dfa_types.h"

int main() {
    FILE* f = fopen("capture_test.dfa", "rb");
    if (!f) { printf("Failed to open DFA\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    if (!dfa_init(data, size)) {
        printf("Failed to init DFA\n");
        return 1;
    }
    
    printf("DFA loaded successfully\n");
    printf("Version: %d\n", dfa_get_version());
    printf("State count: %d\n", dfa_get_state_count());
    
    // Dump first few states
    const dfa_t* dfa = dfa_get_current();
    printf("\nInitial state offset: %u\n", dfa->initial_state);
    printf("Accepting mask: 0x%08x\n\n", dfa->accepting_mask);
    
    // Check first 10 states
    for (int i = 0; i < 10 && i < dfa_get_state_count(); i++) {
        dfa_state_t* state = (dfa_state_t*)((char*)dfa + sizeof(dfa_t) + i * sizeof(dfa_state_t));
        printf("State %d: flags=0x%04x, trans=%u, cap_start=%d, cap_end=%d\n",
               i, state->flags, state->transition_count, 
               state->capture_start_id, state->capture_end_id);
    }
    
    free(data);
    return 0;
}
