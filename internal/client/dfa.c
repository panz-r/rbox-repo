#include "dfa.h"
#include <stdio.h>
#include <string.h>

static const dfa_header_t* g_dfa_header = NULL;
static const dfa_state_t* g_dfa_states = NULL;
static size_t g_transitions_start = 0;

bool dfa_init(void) {
    if (readonlybox_dfa_size < sizeof(dfa_header_t)) {
        return false;
    }
    g_dfa_header = (const dfa_header_t*)readonlybox_dfa_data;
    if (g_dfa_header->magic != DFA_MAGIC) {
        return false;
    }
    if (g_dfa_header->version != DFA_VERSION) {
        return false;
    }
    if (g_dfa_header->state_count == 0) {
        return false;
    }
    if (g_dfa_header->initial_state == 0 || 
        g_dfa_header->initial_state >= readonlybox_dfa_size) {
        return false;
    }
    g_dfa_states = (const dfa_state_t*)(
        (const char*)readonlybox_dfa_data + g_dfa_header->initial_state);
    
    size_t header_size = sizeof(uint32_t) * 3 + sizeof(uint16_t) * 2;
    size_t state_header_size = sizeof(uint32_t) + sizeof(uint16_t) * 2;
    g_transitions_start = header_size + g_dfa_header->state_count * state_header_size;
    
    return true;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
    fprintf(stderr, "dfa_evaluate: input=%s length=%zu\n", input, length);
    if (g_dfa_header == NULL || input == NULL || result == NULL) {
        fprintf(stderr, "dfa_evaluate: NULL check failed\n");
        return false;
    }

    memset(result, 0, sizeof(dfa_result_t));

    if (length == 0) {
        length = strlen(input);
    }
    if (length == 0) {
        return true;
    }

    const dfa_state_t* current_state = g_dfa_states;
    fprintf(stderr, "dfa_evaluate: starting state=%p\n", (void*)current_state);

    for (size_t pos = 0; pos < length; pos++) {
        unsigned char c = (unsigned char)input[pos];
        fprintf(stderr, "dfa_evaluate: pos=%zu char='%c' (0x%02X)\n", pos, c >= 32 ? c : '?', c);
        fprintf(stderr, "dfa_evaluate: state offset=%u count=%u flags=0x%04X\n",
               current_state->transitions_offset,
               current_state->transition_count,
               current_state->flags);
        bool transition_found = false;

        if (current_state->transition_count > 0) {
            const dfa_transition_t* trans = (const dfa_transition_t*)(
                (const char*)g_dfa_header + g_transitions_start + current_state->transitions_offset);
            fprintf(stderr, "dfa_evaluate: trans table at offset %lu (transitions_start=%zu + trans_offset=%u)\n",
                   (unsigned long)(g_transitions_start + current_state->transitions_offset),
                   g_transitions_start, current_state->transitions_offset);

            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                fprintf(stderr, "dfa_evaluate: trans[%u] char=0x%02X offset=%u\n",
                       i, (unsigned char)trans[i].character, trans[i].next_state_offset);
                if (trans[i].character == DFA_CHAR_ANY || trans[i].character == c) {
                    if (trans[i].next_state_offset == 0) {
                        return true;
                    }
                    current_state = (const dfa_state_t*)(
                        (const char*)g_dfa_header + trans[i].next_state_offset);
                    fprintf(stderr, "dfa_evaluate: next state at offset %u\n",
                           trans[i].next_state_offset);
                    transition_found = true;
                    break;
                }
            }
        }

        if (!transition_found) {
            fprintf(stderr, "dfa_evaluate: no transition found for '%c', checking if final state is accepting\n", c >= 32 ? c : '?');
            break;
        }

        if (current_state->flags & 0x0001) {
            result->matched = true;
            result->matched_length = pos + 1;
            result->category = DFA_CMD_READONLY_SAFE;
            return true;
        }
    }

    if (current_state->flags & 0x0001) {
        result->matched = true;
        result->category = DFA_CMD_READONLY_SAFE;
    }

    return true;
}

int dfa_should_allow(const char* cmd) {
    if (cmd == NULL || cmd[0] == '\0') {
        fprintf(stderr, "dfa_should_allow: NULL or empty cmd\n");
        return 0;
    }
    if (g_dfa_header == NULL) {
        fprintf(stderr, "dfa_should_allow: calling dfa_init\n");
        if (!dfa_init()) {
            fprintf(stderr, "dfa_should_allow: dfa_init failed\n");
            return 0;
        }
    }
    fprintf(stderr, "dfa_should_allow: evaluating '%s'\n", cmd);
    dfa_result_t result;
    if (dfa_evaluate(cmd, 0, &result)) {
        fprintf(stderr, "dfa_should_allow: result matched=%d category=%d\n", result.matched, result.category);
        return result.category == DFA_CMD_READONLY_SAFE && result.matched;
    }
    return 0;
}
