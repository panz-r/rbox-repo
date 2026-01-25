#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <string.h>

static const dfa_t* current_dfa = NULL;

bool dfa_init(const void* dfa_data, size_t size) {
    if (dfa_data == NULL || size < sizeof(dfa_t)) {
        return false;
    }

    const dfa_t* dfa = (const dfa_t*)dfa_data;

    if (dfa->magic != DFA_MAGIC) {
        return false;
    }

    if (dfa->version != 3) {
        fprintf(stderr, "Error: Only DFA version 3 is supported (got version %d)\n", dfa->version);
        return false;
    }

    if (dfa->state_count == 0 || dfa->state_count > DFA_MAX_STATES) {
        return false;
    }

    if (dfa->initial_state == 0 || dfa->initial_state >= size) {
        return false;
    }

    current_dfa = dfa;
    return true;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
    if (current_dfa == NULL || input == NULL || result == NULL) {
        return false;
    }

    result->category = DFA_CMD_UNKNOWN;
    result->final_state = 0;
    result->matched = false;
    result->matched_length = 0;

    if (length == 0) {
        length = strlen(input);
    }

    if (length == 0) {
        return true;
    }

    size_t states_size = current_dfa->state_count * sizeof(dfa_state_t);
    size_t dfa_header_size = sizeof(dfa_t);
    size_t dfa_total_size = dfa_header_size + states_size;
    size_t raw_base = (size_t)current_dfa;
    size_t transitions_base = raw_base + dfa_total_size;

    size_t initial_state_offset = current_dfa->initial_state;
    if (initial_state_offset == 0 || initial_state_offset >= dfa_total_size) {
        return false;
    }

    const dfa_state_t* current_state = (const dfa_state_t*)((const char*)current_dfa + initial_state_offset);

    size_t pos = 0;
    for (pos = 0; pos < length && pos < 1000; pos++) {
        size_t current_offset = (size_t)current_state - raw_base;
        unsigned char c = (unsigned char)input[pos];
        
        if (current_offset >= 100000) {
            result->matched_length = pos;
            return true;
        }

        bool transition_found = false;

        if (current_state->transition_count > 0) {
            size_t trans_offset = current_state->transitions_offset;
            if (trans_offset >= 100000) {
                result->matched_length = pos;
                return true;
            }

            size_t trans_addr = transitions_base + trans_offset;
            const dfa_transition_t* trans = (const dfa_transition_t*)trans_addr;

            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                unsigned char trans_char = (unsigned char)trans[i].character;
                uint32_t next_trans_offset = trans[i].next_state_offset;

                if (trans_char == DFA_CHAR_ANY || trans_char == c) {
                    if (next_trans_offset == 0) {
                        result->final_state = current_state->flags;
                        result->matched_length = pos;
                        return true;
                    }

                    const dfa_state_t* next_state = (const dfa_state_t*)((const char*)raw_base + next_trans_offset);

                    current_state = next_state;
                    transition_found = true;
                    break;
                }
            }
        }

        if (!transition_found) {
            result->final_state = current_state->flags;
            result->matched_length = pos;
            return true;
        }

        if (current_state->flags & DFA_STATE_ACCEPTING) {
            result->matched = true;
            result->final_state = current_state->flags;
            result->matched_length = pos + 1;
            result->category = DFA_CMD_READONLY_SAFE;
        }
    }

    // Check for EOS transition at end of input
    if (current_state->transition_count > 0) {
        size_t trans_offset = current_state->transitions_offset;
        size_t trans_addr = transitions_base + trans_offset;
        const dfa_transition_t* trans = (const dfa_transition_t*)trans_addr;

        for (uint16_t i = 0; i < current_state->transition_count; i++) {
            if (trans[i].character == DFA_CHAR_EOS && trans[i].next_state_offset != 0) {
                const dfa_state_t* eos_state = (const dfa_state_t*)((const char*)raw_base + trans[i].next_state_offset);
                if (eos_state->flags & DFA_STATE_ACCEPTING) {
                    result->matched = true;
                    result->matched_length = pos;
                    result->final_state = trans[i].next_state_offset;
                    result->category = DFA_CMD_READONLY_SAFE;
                    return true;
                }
            }
        }
    }

    result->matched_length = pos;
    return true;
}

const char* dfa_category_string(dfa_command_category_t category) {
    switch (category) {
        case DFA_CMD_UNKNOWN: return "Unknown";
        case DFA_CMD_READONLY_SAFE: return "Read-only (Safe)";
        case DFA_CMD_READONLY_CAUTION: return "Read-only (Caution)";
        case DFA_CMD_MODIFYING: return "Modifying";
        case DFA_CMD_DANGEROUS: return "Dangerous";
        case DFA_CMD_NETWORK: return "Network";
        case DFA_CMD_ADMIN: return "Admin";
        default: return "Invalid";
    }
}

bool dfa_is_valid(void) {
    return current_dfa != NULL;
}

uint16_t dfa_get_version(void) {
    if (current_dfa == NULL) {
        return 0;
    }
    return current_dfa->version;
}

uint16_t dfa_get_state_count(void) {
    if (current_dfa == NULL) {
        return 0;
    }
    return current_dfa->state_count;
}

bool dfa_reset(void) {
    current_dfa = NULL;
    return true;
}
