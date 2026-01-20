#include "dfa.h"
#include <string.h>

static const dfa_header_t* g_dfa_header = NULL;
static const dfa_state_t* g_dfa_states = NULL;
static size_t g_transitions_start = 0;
static const uint8_t* g_alphabet_map = NULL;

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
    
    // Version 2: Header + 256-byte alphabet map + states + transitions
    // The alphabet_map is always 256 bytes even though only alphabet_size symbols are used
    size_t header_size = sizeof(dfa_header_t) + 256;
    
    if (g_dfa_header->initial_state == 0 || 
        g_dfa_header->initial_state >= readonlybox_dfa_size) {
        return false;
    }
    
    g_dfa_states = (const dfa_state_t*)(
        (const char*)readonlybox_dfa_data + g_dfa_header->initial_state);
    
    // Alphabet map is right after the header (256 bytes)
    g_alphabet_map = (const uint8_t*)(readonlybox_dfa_data + sizeof(dfa_header_t));
    
    size_t state_header_size = sizeof(uint32_t) + sizeof(uint16_t) * 2;
    g_transitions_start = header_size + g_dfa_header->state_count * state_header_size;
    
    return true;
}

static int char_to_symbol(unsigned char c) {
    if (g_alphabet_map != NULL && c < 256) {
        return g_alphabet_map[c];
    }
    return -1;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
    if (g_dfa_header == NULL || input == NULL || result == NULL) {
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

    for (size_t pos = 0; pos < length; pos++) {
        unsigned char c = (unsigned char)input[pos];
        bool transition_found = false;
        
        int symbol = char_to_symbol(c);

        if (current_state->transition_count > 0) {
            const dfa_transition_t* trans = (const dfa_transition_t*)(
                (const char*)g_dfa_header + g_transitions_start + current_state->transitions_offset);

            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                if (symbol >= 0 && trans[i].character == symbol) {
                    if (trans[i].next_state_offset == 0) {
                        if (current_state->flags & DFA_STATE_ACCEPTING) {
                            result->matched = true;
                            result->matched_length = pos + 1;
                            result->category = DFA_CMD_READONLY_SAFE;
                        }
                        return true;
                    }
                    current_state = (const dfa_state_t*)(
                        (const char*)g_dfa_header + trans[i].next_state_offset);
                    transition_found = true;
                    break;
                }
            }
        }

        if (!transition_found) {
            break;
        }

        if (current_state->flags & DFA_STATE_ACCEPTING) {
            result->matched = true;
            result->matched_length = pos + 1;
            result->category = DFA_CMD_READONLY_SAFE;
            return true;
        }
    }

    if (current_state->flags & DFA_STATE_ACCEPTING) {
        result->matched = true;
        result->category = DFA_CMD_READONLY_SAFE;
    }

    return true;
}

int dfa_should_allow(const char* cmd) {
    if (cmd == NULL || cmd[0] == '\0') {
        return 0;
    }
    if (g_dfa_header == NULL) {
        if (!dfa_init()) {
            return 0;
        }
    }
    dfa_result_t result;
    if (dfa_evaluate(cmd, 0, &result)) {
        return result.category == DFA_CMD_READONLY_SAFE && result.matched;
    }
    return 0;
}
