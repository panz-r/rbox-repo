#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dfa.h"
#include "dfa_types.h"

#define DFA_STATE_SIZE sizeof(dfa_state_t)
#define STATE_INDEX_TO_OFFSET(idx) (sizeof(dfa_t) + ((size_t)(idx) * DFA_STATE_SIZE))

int main(int argc, char* argv[]) {
    const char* test_input = "ab";

    FILE* f = fopen("readonlybox.dfa", "rb");
    if (!f) {
        fprintf(stderr, "Cannot open DFA file\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    if (!dfa_init(data, size)) {
        fprintf(stderr, "DFA init failed\n");
        free(data);
        return 1;
    }

    const dfa_t* dfa = (const dfa_t*)data;
    size_t raw_base = (size_t)dfa;
    size_t initial_state_offset = dfa->initial_state;

    printf("\nManual evaluation of '%s':\n", test_input);
    printf("  Initial state offset: %zu\n", initial_state_offset);

    const dfa_state_t* current_state = (const dfa_state_t*)((const char*)dfa + initial_state_offset);

    for (size_t pos = 0; test_input[pos] != '\0'; pos++) {
        unsigned char c = (unsigned char)test_input[pos];
        size_t current_offset = (size_t)current_state - raw_base;

        printf("  pos=%zu, char='%c'(%d), state_offset=%zu, trans_count=%d, eos_target=%u\n",
               pos, c, c, current_offset, current_state->transition_count, current_state->eos_target);

        // Find transition
        bool found = false;
        if (current_state->transition_count > 0) {
            size_t trans_offset = current_state->transitions_offset;
            const dfa_transition_t* trans = (const dfa_transition_t*)((const char*)raw_base + trans_offset);
            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                printf("    trans[%d]: char=%d, next_state=%u\n", i, trans[i].character, trans[i].next_state_offset);
                if (trans[i].character == c) {
                    size_t next_offset = STATE_INDEX_TO_OFFSET(trans[i].next_state_offset);
                    current_state = (const dfa_state_t*)((const char*)dfa + next_offset);
                    printf("    -> Taking transition to state %u (offset=%zu)\n", trans[i].next_state_offset, next_offset);
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            printf("    NO TRANSITION FOUND!\n");
            break;
        }
    }

    size_t final_offset = (size_t)current_state - raw_base;
    printf("  Final state: offset=%zu, flags=0x%04x, eos_target=%u\n",
           final_offset, current_state->flags, current_state->eos_target);

    if (current_state->eos_target != 0) {
        size_t eos_offset = STATE_INDEX_TO_OFFSET(current_state->eos_target);
        const dfa_state_t* eos_state = (const dfa_state_t*)((const char*)dfa + eos_offset);
        printf("  EOS target state %u: offset=%zu, flags=0x%04x\n",
               current_state->eos_target, eos_offset, eos_state->flags);
    }

    free(data);
    return 0;
}
