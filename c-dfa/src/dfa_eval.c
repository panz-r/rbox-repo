#include "dfa.h"
#include "dfa_types.h"
#include <string.h>

// Current DFA instance
static const dfa_t* current_dfa = NULL;

// Alphabet mapping for character-to-symbol conversion
static char alphabet_map[256] = {0}; // Maps character to symbol ID
static bool alphabet_initialized = false;

bool dfa_init(const void* dfa_data, size_t size) {
    if (dfa_data == NULL || size < sizeof(dfa_t)) {
        return false;
    }

    const dfa_t* dfa = (const dfa_t*)dfa_data;

    // Validate magic number
    if (dfa->magic != DFA_MAGIC) {
        return false;
    }

    // Validate version (support both v1 and v2)
    if (dfa->version != 1 && dfa->version != 2) {
        return false;
    }

    // Validate state count
    if (dfa->state_count == 0 || dfa->state_count > DFA_MAX_STATES) {
        return false;
    }

    // Validate initial state offset
    if (dfa->initial_state == 0 || dfa->initial_state >= size) {
        return false;
    }

    current_dfa = dfa;
    
    // Initialize alphabet mapping for version 2
    if (dfa->version == 2) {
        const char* alphabet_map_ptr = (const char*)dfa + sizeof(dfa_t);
        for (int i = 0; i < 256; i++) {
            alphabet_map[i] = alphabet_map_ptr[i];
        }
        alphabet_initialized = true;
    } else {
        // Version 1: identity mapping (character = symbol)
        for (int i = 0; i < 256; i++) {
            alphabet_map[i] = i;
        }
        alphabet_initialized = true;
    }
    
    return true;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
    if (current_dfa == NULL || input == NULL || result == NULL) {
        return false;
    }

    // Initialize result
    result->category = DFA_CMD_UNKNOWN;
    result->final_state = 0;
    result->matched = false;
    result->matched_length = 0;

    // Use length if provided, otherwise calculate
    if (length == 0) {
        length = strlen(input);
    }

    if (length == 0) {
        return true; // Empty input
    }

    // Start at initial state
    const dfa_state_t* current_state = (const dfa_state_t*)((const char*)current_dfa + current_dfa->initial_state);
    size_t pos = 0;

    for (pos = 0; pos < length; pos++) {
        char c = input[pos];
        char symbol_id = alphabet_initialized ? alphabet_map[(unsigned char)c] : c;
        bool transition_found = false;

        // Get transition table for current state
        if (current_state->transition_count > 0) {
            const dfa_transition_t* trans = (const dfa_transition_t*)(
                (const char*)current_dfa + current_state->transitions_offset);

            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                if (trans[i].character == DFA_CHAR_ANY || trans[i].character == symbol_id) {
                    // Found a transition
                    if (trans[i].next_state_offset == 0) {
                        // No transition (dead end)
                        result->final_state = current_state->flags;
                        result->matched_length = pos;
                        return true;
                    }

                    // Move to next state
                    current_state = (const dfa_state_t*)(
                        (const char*)current_dfa + trans[i].next_state_offset);
                    transition_found = true;
                    break;
                } else if (trans[i].character == DFA_CHAR_WHITESPACE) {
                    // Whitespace wildcard - matches any whitespace character
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                        if (trans[i].next_state_offset == 0) {
                            // No transition (dead end)
                            result->final_state = current_state->flags;
                            result->matched_length = pos;
                            return true;
                        }

                        // Move to next state
                        current_state = (const dfa_state_t*)(
                            (const char*)current_dfa + trans[i].next_state_offset);
                        transition_found = true;
                        break;
                    }
                } else if (trans[i].character == DFA_CHAR_VERBATIM_SPACE) {
                    // Verbatim space - matches exactly one space character
                    if (c == ' ') {
                        if (trans[i].next_state_offset == 0) {
                            // No transition (dead end)
                            result->final_state = current_state->flags;
                            result->matched_length = pos;
                            return true;
                        }

                        // Move to next state
                        current_state = (const dfa_state_t*)(
                            (const char*)current_dfa + trans[i].next_state_offset);
                        transition_found = true;
                        break;
                    }
                } else if (trans[i].character == DFA_CHAR_NORMALIZING_SPACE) {
                    // Normalizing space - matches one or more space/tab characters
                    if (c == ' ' || c == '\t') {
                        if (trans[i].next_state_offset == 0) {
                            // No transition (dead end)
                            result->final_state = current_state->flags;
                            result->matched_length = pos;
                            return true;
                        }

                        // Move to next state
                        current_state = (const dfa_state_t*)(
                            (const char*)current_dfa + trans[i].next_state_offset);
                        transition_found = true;
                        break;
                    }
                }
            }
        }

        if (!transition_found) {
            // No transition found for this character
            result->final_state = current_state->flags;
            result->matched_length = pos;
            return true;
        }

        // Check if we reached an accepting state
        if (current_state->flags & DFA_STATE_ACCEPTING) {
            result->matched = true;
            result->final_state = current_state->flags;
            result->matched_length = pos + 1;

            // Determine command category based on which accepting state we're in
            // This would be enhanced with more sophisticated category detection
            result->category = DFA_CMD_READONLY_SAFE;

            return true;
        }
    }

    // Reached end of input
    result->final_state = current_state->flags;
    result->matched_length = pos;

    if (current_state->flags & DFA_STATE_ACCEPTING) {
        result->matched = true;
        result->category = DFA_CMD_READONLY_SAFE;
    }

    return true;
}

const dfa_t* dfa_get_current(void) {
    return current_dfa;
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