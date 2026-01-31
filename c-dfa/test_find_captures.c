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
    
    const dfa_t* dfa = dfa_get_current();
    int state_count = dfa_get_state_count();
    int capture_states = 0;
    int accepting_states = 0;
    
    printf("Checking %d states for capture markers...\n\n", state_count);
    
    for (int i = 0; i < state_count; i++) {
        dfa_state_t* state = (dfa_state_t*)((char*)dfa + sizeof(dfa_t) + i * sizeof(dfa_state_t));
        
        bool has_capture = (state->capture_start_id >= 0 || state->capture_end_id >= 0);
        bool is_accepting = (state->flags & DFA_STATE_ACCEPTING);
        uint8_t category = DFA_GET_CATEGORY_MASK(state->flags);
        
        if (has_capture) {
            printf("State %d: cap_start=%d, cap_end=%d, flags=0x%04x, cat=0x%02x\n",
                   i, state->capture_start_id, state->capture_end_id, state->flags, category);
            capture_states++;
        }
        
        if (is_accepting || category != 0) {
            accepting_states++;
        }
    }
    
    printf("\nTotal states with capture markers: %d\n", capture_states);
    printf("Total accepting states: %d\n", accepting_states);
    
    free(data);
    return 0;
}
