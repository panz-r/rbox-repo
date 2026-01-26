#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <string.h>

static const dfa_t* current_dfa = NULL;

// Capture tracking during evaluation
typedef struct {
    size_t start_pos;    // Start position of capture
    bool active;         // Is capture currently active?
    int capture_id;      // Capture ID for lookup
} eval_capture_t;

bool dfa_init(const void* dfa_data, size_t size) {
    if (dfa_data == NULL || size < sizeof(dfa_t)) {
        return false;
    }

    const dfa_t* dfa = (const dfa_t*)dfa_data;

    if (dfa->magic != DFA_MAGIC) {
        return false;
    }

    if (dfa->version != 3 && dfa->version != 4) {
        fprintf(stderr, "Error: Only DFA version 3 or 4 is supported (got version %d)\n", dfa->version);
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

    // Initialize result
    result->category = DFA_CMD_UNKNOWN;
    result->category_mask = 0;
    result->final_state = 0;
    result->matched = false;
    result->matched_length = 0;
    result->capture_count = 0;
    for (int i = 0; i < DFA_MAX_CAPTURES; i++) {
        result->captures[i].start = 0;
        result->captures[i].end = 0;
        result->captures[i].name[0] = '\0';
        result->captures[i].active = false;
        result->captures[i].completed = false;
    }

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

    // Initialize capture tracking
    eval_capture_t active_captures[DFA_MAX_CAPTURES];
    for (int i = 0; i < DFA_MAX_CAPTURES; i++) {
        active_captures[i].start_pos = 0;
        active_captures[i].active = false;
        active_captures[i].capture_id = -1;
    }

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

                // Check for CAPTURE_START (0xF0)
                if (trans_char == DFA_CHAR_CAPTURE_START) {
                    // Next character is the capture ID
                    continue; // Skip to next transition which should have the ID
                }

                // Check for capture ID byte
                bool is_capture_id = false;
                int cap_id = -1;
                for (int ci = 0; ci < DFA_MAX_CAPTURES; ci++) {
                    if (active_captures[ci].capture_id == trans_char && active_captures[ci].active) {
                        is_capture_id = true;
                        break;
                    }
                }
                if (!is_capture_id && trans_char >= 0 && trans_char < DFA_MAX_CAPTURES) {
                    // This might be a capture ID we're starting
                    cap_id = trans_char;
                }

                if (trans_char == DFA_CHAR_ANY || trans_char == c) {
                    const dfa_state_t* next_state = (const dfa_state_t*)((const char*)raw_base + next_trans_offset);

                    current_state = next_state;
                    transition_found = true;
                    break;
                }
            }
        }

        if (!transition_found) {
            result->final_state = current_state->flags;
            result->category_mask = DFA_GET_CATEGORY_MASK(current_state->flags);
            result->matched_length = pos;
            return true;
        }

        // Check for accepting state
        if (current_state->flags & DFA_STATE_ACCEPTING) {
            result->matched = true;
            result->final_state = current_state->flags;
            result->matched_length = pos + 1;
            result->category_mask = DFA_GET_CATEGORY_MASK(current_state->flags);
            
            // Derive legacy category enum from mask for backward compatibility
            if (result->category_mask & 0x01) result->category = DFA_CMD_READONLY_SAFE;
            else if (result->category_mask & 0x02) result->category = DFA_CMD_READONLY_CAUTION;
            else if (result->category_mask & 0x04) result->category = DFA_CMD_MODIFYING;
            else if (result->category_mask & 0x08) result->category = DFA_CMD_DANGEROUS;
            else if (result->category_mask & 0x10) result->category = DFA_CMD_NETWORK;
            else if (result->category_mask & 0x20) result->category = DFA_CMD_ADMIN;
        }
    }

    // Process captures at end of input
    for (int i = 0; i < DFA_MAX_CAPTURES; i++) {
        if (active_captures[i].active) {
            result->captures[result->capture_count].start = active_captures[i].start_pos;
            result->captures[result->capture_count].end = pos;
            result->captures[result->capture_count].active = true;
            result->captures[result->capture_count].completed = true;
            result->capture_count++;
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
                    result->category_mask = DFA_GET_CATEGORY_MASK(eos_state->flags);

                    // Derive legacy category enum from mask for backward compatibility
                    if (result->category_mask & 0x01) result->category = DFA_CMD_READONLY_SAFE;
                    else if (result->category_mask & 0x02) result->category = DFA_CMD_READONLY_CAUTION;
                    else if (result->category_mask & 0x04) result->category = DFA_CMD_MODIFYING;
                    else if (result->category_mask & 0x08) result->category = DFA_CMD_DANGEROUS;
                    else if (result->category_mask & 0x10) result->category = DFA_CMD_NETWORK;
                    else if (result->category_mask & 0x20) result->category = DFA_CMD_ADMIN;
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

const dfa_t* dfa_get_current(void) {
    return current_dfa;
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

int dfa_get_capture(const dfa_result_t* result, int index, const char** out_start, size_t* out_length) {
    if (result == NULL || index < 0 || index >= result->capture_count) {
        return -1;
    }

    const dfa_capture_t* cap = &result->captures[index];
    if (!cap->completed || cap->start >= cap->end) {
        return -1;
    }

    // We need the original input to extract the capture
    // This is a limitation - the input is not stored in result
    // For now, return the indices
    if (out_start != NULL) {
        *out_start = NULL; // Would need input to provide this
    }
    if (out_length != NULL) {
        *out_length = cap->end - cap->start;
    }

    return (int)(cap->end - cap->start);
}

const char* dfa_get_capture_name(const dfa_result_t* result, int index) {
    if (result == NULL || index < 0 || index >= result->capture_count) {
        return NULL;
    }
    return result->captures[index].name[0] != '\0' ? result->captures[index].name : NULL;
}

bool dfa_reset(void) {
    current_dfa = NULL;
    return true;
}
