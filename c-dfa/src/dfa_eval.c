#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <string.h>

// Debug output control - set to 1 to enable debug prints
#ifndef PRINT_DEBUG
#define PRINT_DEBUG 0
#endif

static const dfa_t* current_dfa = NULL;

// Size of dfa_state_t structure - used to compute state offsets from indices
#define DFA_STATE_SIZE (sizeof(dfa_state_t))

// Compute absolute offset from state index
// next_state_offset now stores state index, we compute: sizeof(dfa_t) + state_index * sizeof(dfa_state_t)
#define STATE_INDEX_TO_OFFSET(idx) (sizeof(dfa_t) + ((size_t)(idx) * DFA_STATE_SIZE))

// Capture tracking during evaluation
typedef struct {
    size_t start_pos;    // Start position of capture
    bool active;         // Is capture currently active?
    int capture_id;      // Capture ID for lookup
} eval_capture_t;

bool dfa_init(const void* dfa_data, size_t size) {
    if (dfa_data == NULL || size < sizeof(dfa_t)) {
#if PRINT_DEBUG
        fprintf(stderr, "DEBUG: dfa_init failed - null data or size too small\n");
#endif
        return false;
    }

    const dfa_t* dfa = (const dfa_t*)dfa_data;

    if (dfa->magic != DFA_MAGIC) {
#if PRINT_DEBUG
        fprintf(stderr, "DEBUG: dfa_init failed - invalid magic\n");
#endif
        return false;
    }

    if (dfa->version != 3 && dfa->version != 4) {
        fprintf(stderr, "Error: Only DFA version 3 or 4 is supported (got version %d)\n", dfa->version);
        return false;
    }

    if (dfa->state_count == 0 || dfa->state_count > DFA_MAX_STATES) {
#if PRINT_DEBUG
        fprintf(stderr, "DEBUG: dfa_init failed - state_count=%d (max=%d)\n", dfa->state_count, DFA_MAX_STATES);
#endif
        return false;
    }

    if (dfa->initial_state == 0 || dfa->initial_state >= size) {
#if PRINT_DEBUG
        fprintf(stderr, "DEBUG: dfa_init failed - initial_state=%d, size=%zu\n", dfa->initial_state, size);
#endif
        return false;
    }

    current_dfa = dfa;
#if PRINT_DEBUG
    fprintf(stderr, "DEBUG: dfa_init succeeded - states=%d, initial=%d, size=%zu\n",
            dfa->state_count, dfa->initial_state, size);
#endif
    return true;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
#if PRINT_DEBUG
    fprintf(stderr, "DEBUG: dfa_evaluate called with input='%s'\n", input);
#endif
    if (current_dfa == NULL || input == NULL || result == NULL) {
#if PRINT_DEBUG
        fprintf(stderr, "DEBUG: early return - null pointer\n");
#endif
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
#if PRINT_DEBUG
    fprintf(stderr, "DEBUG: Starting evaluation, initial_state at offset %zu\n", initial_state_offset);
#endif
    for (pos = 0; pos < length && pos < 1000; pos++) {
        unsigned char c = (unsigned char)input[pos];
        size_t current_offset = (size_t)current_state - raw_base;

#if PRINT_DEBUG
        fprintf(stderr, "DEBUG: pos=%zu, char='%c'(%d), state_offset=%zu, trans_count=%d, flags=0x%x\n",
                pos, c, c, current_offset, current_state->transition_count, current_state->flags);
#endif
        
        // Debug: show transitions from this state
        if (current_state->transition_count > 0) {
            size_t trans_offset = current_state->transitions_offset;
            const dfa_transition_t* trans = (const dfa_transition_t*)((const char*)raw_base + trans_offset);
            for (uint16_t i = 0; i < current_state->transition_count && i < 5; i++) {
                unsigned char trans_char = (unsigned char)trans[i].character;
#if PRINT_DEBUG
                fprintf(stderr, "    DEBUG: trans[%d]: char=%d, next_offset=%u\n",
                        i, trans_char, trans[i].next_state_offset);
#endif
            }
        }

        if (current_offset >= 1000000) {
            result->matched_length = pos;
            return true;
        }

        bool transition_found = false;
#if PRINT_DEBUG
        fprintf(stderr, "DEBUG: Looking for transition on char=%d ('%c') from state_offset=%zu\n", c, c, current_offset);
#endif

        if (current_state->transition_count > 0) {
            size_t trans_offset = current_state->transitions_offset;
            if (trans_offset >= 100000) {
                result->matched_length = pos;
                return true;
            }

            // transitions_offset is an absolute offset from start of DFA structure
            const dfa_transition_t* trans = (const dfa_transition_t*)((const char*)raw_base + trans_offset);

            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                unsigned char trans_char = (unsigned char)trans[i].character;
                uint32_t next_trans_offset = trans[i].next_state_offset;

                // Check for CAPTURE_START (0xF0)
                if (trans_char == DFA_CHAR_CAPTURE_START) {
                    // Next character is the capture ID
                    continue; // Skip to next transition which should have the ID
                }

                // Check for CAPTURE_END (0xF1)
                if (trans_char == DFA_CHAR_CAPTURE_END) {
                    // Next character is the capture ID
                    continue; // Skip to next transition which should have the ID
                }

                // Check for capture ID markers (0xF2 = CAPTURE_ID_BASE + capture_id)
                if (trans_char >= DFA_CHAR_CAPTURE_ID_BASE && trans_char < DFA_CHAR_CAPTURE_ID_BASE + DFA_MAX_CAPTURES) {
                    // This is a capture ID transition
                    int cap_id = trans_char - DFA_CHAR_CAPTURE_ID_BASE;

                    // Find an inactive capture slot and activate it
                    for (int ci = 0; ci < DFA_MAX_CAPTURES; ci++) {
                        if (!active_captures[ci].active) {
                            active_captures[ci].capture_id = cap_id;
                            active_captures[ci].start_pos = pos;
                            active_captures[ci].active = true;
                            break;
                        }
                    }

                    // Move to next state (capture markers don't consume input)
                    // next_trans_offset is now a state index, compute actual offset
                    size_t next_offset = STATE_INDEX_TO_OFFSET(next_trans_offset);
                    const dfa_state_t* next_state = (const dfa_state_t*)((const char*)raw_base + next_offset);
                    current_state = next_state;
                    transition_found = true;
                    break;
                }

                if (trans_char == DFA_CHAR_ANY || trans_char == c) {
                    // next_trans_offset is now a state index, compute actual offset
                    size_t next_offset = STATE_INDEX_TO_OFFSET(next_trans_offset);
                    const dfa_state_t* next_state = (const dfa_state_t*)((const char*)raw_base + next_offset);

                    current_state = next_state;
                    transition_found = true;
                    break;
                }
            }
        }

        if (!transition_found) {
            // No transition found - pattern doesn't match
            // Don't return a match just because we're in some state
            result->final_state = current_state->flags;
            result->category_mask = DFA_GET_CATEGORY_MASK(current_state->flags);
            result->matched_length = pos;
            result->matched = false;
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

    // Check for EOS target at end of input
    // The eos_target field points to an accepting state if one exists
    // Only check EOS target if we've consumed all input (pos >= length)
    if (pos >= length && current_state->eos_target != 0) {
        fprintf(stderr, "DEBUG: EOS check: pos=%zu, length=%zu, eos_target=%u\n", pos, length, current_state->eos_target);
        size_t eos_offset = STATE_INDEX_TO_OFFSET(current_state->eos_target);
        const dfa_state_t* eos_accepting_state = (const dfa_state_t*)((const char*)raw_base + eos_offset);
        fprintf(stderr, "DEBUG: EOS state flags=0x%04x, accepting=%s\n", 
                eos_accepting_state->flags, (eos_accepting_state->flags & DFA_STATE_ACCEPTING) ? "yes" : "no");
        if (eos_accepting_state->flags & DFA_STATE_ACCEPTING) {
            result->matched = true;
            result->matched_length = pos;
            result->final_state = eos_accepting_state->flags;
            result->category_mask = DFA_GET_CATEGORY_MASK(eos_accepting_state->flags);

            // Derive legacy category enum from mask for backward compatibility
            if (result->category_mask & 0x01) result->category = DFA_CMD_READONLY_SAFE;
            else if (result->category_mask & 0x02) result->category = DFA_CMD_READONLY_CAUTION;
            else if (result->category_mask & 0x04) result->category = DFA_CMD_MODIFYING;
            else if (result->category_mask & 0x08) result->category = DFA_CMD_DANGEROUS;
            else if (result->category_mask & 0x10) result->category = DFA_CMD_NETWORK;
            else if (result->category_mask & 0x20) result->category = DFA_CMD_ADMIN;
            fprintf(stderr, "DEBUG: Match via EOS! matched=%d, len=%zu\n", result->matched, result->matched_length);
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
