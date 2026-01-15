#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simple DFA visualizer for debugging
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dfa_file>\n", argv[0]);
        return 1;
    }

    const char* dfa_file = argv[1];

    // Load DFA
    size_t dfa_size;
    void* dfa_data = load_dfa_from_file(dfa_file, &dfa_size);
    if (dfa_data == NULL) {
        printf("Failed to load DFA from %s\n", dfa_file);
        return 1;
    }

    // Initialize DFA
    if (!dfa_init(dfa_data, dfa_size)) {
        printf("Failed to initialize DFA\n");
        free(dfa_data);
        return 1;
    }

    const dfa_t* dfa = dfa_get_current();
    if (dfa == NULL) {
        printf("No DFA loaded\n");
        free(dfa_data);
        return 1;
    }

    printf("DFA Information:\n");
    printf("Magic: 0x%08X\n", dfa->magic);
    printf("Version: %u\n", dfa->version);
    printf("State Count: %u\n", dfa->state_count);
    printf("Initial State Offset: %u\n", dfa->initial_state);
    printf("Size: %zu bytes\n", dfa_size);

    // Basic state information
    if (dfa->state_count > 0) {
        const dfa_state_t* initial_state = (const dfa_state_t*)((const char*)dfa + dfa->initial_state);
        printf("\nInitial State:\n");
        printf("  Flags: 0x%04X (%s)\n", initial_state->flags,
               initial_state->flags & DFA_STATE_ACCEPTING ? "ACCEPTING" : "NON-ACCEPTING");
        printf("  Transition Count: %u\n", initial_state->transition_count);

        if (initial_state->transition_count > 0) {
            printf("  Transitions:\n");
            const dfa_transition_t* trans = (const dfa_transition_t*)(
                (const char*)dfa + initial_state->transitions_offset);

            for (uint16_t i = 0; i < initial_state->transition_count && i < 10; i++) {
                printf("    %c -> offset %u\n",
                       trans[i].character == DFA_CHAR_ANY ? '*' : trans[i].character,
                       trans[i].next_state_offset);
            }
            if (initial_state->transition_count > 10) {
                printf("    ... (%u more transitions)\n", initial_state->transition_count - 10);
            }
        }
    }

    // Cleanup
    dfa_reset();
    free(dfa_data);

    return 0;
}