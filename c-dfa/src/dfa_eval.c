#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const dfa_t* current_dfa = NULL;

#define DFA_STATE_SIZE (sizeof(dfa_state_t))
#define STATE_INDEX_TO_OFFSET(idx) (sizeof(dfa_t) + ((size_t)(idx) * DFA_STATE_SIZE))

typedef struct {
    size_t start_pos;
    bool active;
    int capture_id;
    uint8_t category;  // Category mask when capture started
} eval_capture_t;

typedef struct {
    int capture_id;
    size_t start_pos;
} defer_entry_t;

#define MAX_DEFER_STACK 16
static defer_entry_t defer_stack[MAX_DEFER_STACK];
static int defer_stack_depth = 0;

static void defer_push(int capture_id, size_t start_pos) {
    if (defer_stack_depth < MAX_DEFER_STACK) {
        defer_stack[defer_stack_depth].capture_id = capture_id;
        defer_stack[defer_stack_depth].start_pos = start_pos;
        defer_stack_depth++;
    }
}

static int defer_get_depth(void) {
    return defer_stack_depth;
}

static bool process_capture_markers(const dfa_state_t** state_ptr, size_t raw_base,
                                    eval_capture_t* active_captures, size_t pos, dfa_result_t* result) {
    const dfa_state_t* current_state = *state_ptr;
    bool changed = false;
    
    if (current_state->flags & DFA_STATE_CAPTURE_START) {
        int cap_id = current_state->capture_start_id;
        if (cap_id >= 0) {
            for (int ci = 0; ci < DFA_MAX_CAPTURES; ci++) {
                if (!active_captures[ci].active) {
                    active_captures[ci].capture_id = cap_id;
                    active_captures[ci].start_pos = pos;
                    active_captures[ci].active = true;
                    break;
                }
            }
            changed = true;
        }
    }
    
    if (current_state->flags & DFA_STATE_CAPTURE_END) {
        int cap_id = current_state->capture_end_id;
        if (cap_id >= 0) {
            for (int ci = 0; ci < DFA_MAX_CAPTURES; ci++) {
                if (active_captures[ci].active && active_captures[ci].capture_id == cap_id) {
                    if (result->capture_count < DFA_MAX_CAPTURES) {
                        dfa_capture_t* cap = &result->captures[result->capture_count];
                        cap->start = active_captures[ci].start_pos;
                        cap->end = pos;
                        cap->active = false;
                        cap->completed = true;
                        snprintf(cap->name, sizeof(cap->name), "capture_%d", cap_id);
                        result->capture_count++;
                    }
                    active_captures[ci].active = false;
                    active_captures[ci].capture_id = -1;
                    break;
                }
            }
            changed = true;
        }
    }
    
    if (current_state->flags & DFA_STATE_CAPTURE_DEFER) {
        int cap_id = current_state->capture_defer_id;
        if (cap_id >= 0) {
            for (int ci = 0; ci < DFA_MAX_CAPTURES; ci++) {
                if (active_captures[ci].active && active_captures[ci].capture_id == cap_id) {
                    defer_push(cap_id, active_captures[ci].start_pos);
                    break;
                }
            }
            changed = true;
        }
    }
    
    return changed;
}

static void process_deferred_captures(const dfa_state_t* current_state, 
                                       size_t next_state_offset, size_t raw_base,
                                       size_t pos, dfa_result_t* result) {
    int defer_depth = defer_get_depth();
    if (defer_depth == 0) {
        return;
    }
    
    const dfa_state_t* next_state = (const dfa_state_t*)((const char*)raw_base + next_state_offset);
    
    for (int d = 0; d < defer_depth; d++) {
        int cap_id = defer_stack[d].capture_id;
        size_t start_pos = defer_stack[d].start_pos;
        
        if (next_state->flags & DFA_STATE_CAPTURE_DEFER) {
            if (next_state->capture_defer_id == cap_id) {
                continue;
            }
        }
        
        if (result->capture_count < DFA_MAX_CAPTURES) {
            dfa_capture_t* cap = &result->captures[result->capture_count];
            cap->start = start_pos;
            cap->end = pos;
            cap->active = false;
            cap->completed = true;
            snprintf(cap->name, sizeof(cap->name), "capture_%d", cap_id);
            result->capture_count++;
        }
        
        for (int shift = d; shift < defer_depth - 1; shift++) {
            defer_stack[shift] = defer_stack[shift + 1];
        }
        defer_stack_depth--;
        defer_depth--;
        d--;
    }
}

bool dfa_init(const void* dfa_data, size_t size) {
    if (dfa_data == NULL || size < sizeof(dfa_t)) {
        return false;
    }

    const dfa_t* dfa = (const dfa_t*)dfa_data;

    if (dfa->magic != DFA_MAGIC) {
        return false;
    }

    if (dfa->version != 3 && dfa->version != 4) {
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

bool dfa_is_valid(void) {
    return current_dfa != NULL;
}

uint16_t dfa_get_version(void) {
    return current_dfa ? current_dfa->version : 0;
}

uint16_t dfa_get_state_count(void) {
    return current_dfa ? current_dfa->state_count : 0;
}

bool dfa_reset(void) {
    current_dfa = NULL;
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

int dfa_get_capture_count(const dfa_result_t* result) {
    return result ? result->capture_count : 0;
}

bool dfa_get_capture_by_index(const dfa_result_t* result, int index, size_t* out_start, size_t* out_length) {
    if (result == NULL || index < 0 || index >= result->capture_count) {
        return false;
    }
    if (out_start) *out_start = result->captures[index].start;
    if (out_length) *out_length = result->captures[index].end - result->captures[index].start;
    return true;
}

const char* dfa_get_capture_name(const dfa_result_t* result, int index) {
    if (result == NULL || index < 0 || index >= result->capture_count) {
        return NULL;
    }
    return result->captures[index].name;
}

int dfa_get_capture(const dfa_result_t* result, int index, const char** out_start, size_t* out_length) {
    if (result == NULL || index < 0 || index >= result->capture_count) {
        return -1;
    }
    if (out_start) *out_start = "";
    if (out_length) *out_length = 0;
    return result->captures[index].capture_id;
}

bool dfa_evaluate_with_limit(const char* input, size_t length, dfa_result_t* result, int max_captures) {
    if (current_dfa == NULL || input == NULL || result == NULL) {
        return false;
    }

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

    // Reset defer stack for this evaluation
    defer_stack_depth = 0;

    size_t states_size = current_dfa->state_count * sizeof(dfa_state_t);
    size_t dfa_header_size = sizeof(dfa_t);
    size_t dfa_total_size = dfa_header_size + states_size;
    size_t raw_base = (size_t)current_dfa;

    size_t initial_state_offset = current_dfa->initial_state;
    if (initial_state_offset == 0 || initial_state_offset >= dfa_total_size) {
        return false;
    }

    const dfa_state_t* current_state = (const dfa_state_t*)((const char*)current_dfa + initial_state_offset);

    eval_capture_t active_captures[DFA_MAX_CAPTURES];
    for (int i = 0; i < DFA_MAX_CAPTURES; i++) {
        active_captures[i].start_pos = 0;
        active_captures[i].active = false;
        active_captures[i].capture_id = -1;
    }

    size_t pos = 0;

    process_capture_markers(&current_state, raw_base, active_captures, pos, result);

    // Track the best candidate match seen so far (for handling patterns that can end early)
    uint8_t best_category_mask = 0;
    const dfa_state_t* best_state = NULL;
    size_t best_length = 0;

    for (pos = 0; pos < length && pos < 1000; pos++) {
        unsigned char c = (unsigned char)input[pos];
        size_t current_offset = (size_t)current_state - raw_base;

        process_capture_markers(&current_state, raw_base, active_captures, pos, result);
        current_offset = (size_t)current_state - raw_base;

        if (current_offset >= 1000000) {
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

            const dfa_transition_t* trans = (const dfa_transition_t*)((const char*)raw_base + trans_offset);

            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                unsigned char trans_char = (unsigned char)trans[i].character;
                uint32_t next_trans_offset = trans[i].next_state_offset;

                if (trans_char == DFA_CHAR_ANY || trans_char == c) {
                    size_t next_offset = next_trans_offset;

                    process_deferred_captures(current_state, next_offset, raw_base, pos, result);

                    const dfa_state_t* next_state = (const dfa_state_t*)((const char*)raw_base + next_offset);
                    current_state = next_state;
                    transition_found = true;
                    break;
                }
            }
        }

        if (!transition_found) {
            // Dead end - check if current state can accept here
            uint8_t category_mask = DFA_GET_CATEGORY_MASK(current_state->flags);
            if (category_mask != 0) {
                // Only accept if this state can actually terminate (no outgoing transitions)
                // The category_mask tells us if this state is accepting
                // We do NOT check eos_target here because:
                // 1. category_mask already indicates if we're in an accepting state
                // 2. Following eos_target was causing bugs (it pointed to wrong state)
                bool has_outgoing = (current_state->transition_count > 0);
                if (!has_outgoing && category_mask != 0) {
                    result->matched = true;
                    result->final_state = current_state->flags;
                    result->matched_length = pos;
                    result->category_mask = category_mask;

                    if (category_mask & 0x01) result->category = DFA_CMD_READONLY_SAFE;
                    else if (category_mask & 0x02) result->category = DFA_CMD_READONLY_CAUTION;
                    else if (category_mask & 0x04) result->category = DFA_CMD_MODIFYING;
                    else if (category_mask & 0x08) result->category = DFA_CMD_DANGEROUS;
                    else if (category_mask & 0x10) result->category = DFA_CMD_NETWORK;
                    else if (category_mask & 0x20) result->category = DFA_CMD_ADMIN;
                }
            }
            result->final_state = current_state->flags;
            result->category_mask = DFA_GET_CATEGORY_MASK(current_state->flags);
            result->matched_length = pos;
            return true;
        }

        // Track candidate match states (but don't finalize yet)
        // CRITICAL: Only consider DEAD-END states as valid accepting states
        // A state can accept ONLY if it has no outgoing transitions
        // States with EOS targets but outgoing transitions are NOT accepting
        // This prevents partial matches for patterns like a((b))+ where 'ab' would
        // incorrectly match before the required 'b' is consumed
        uint8_t category_mask = DFA_GET_CATEGORY_MASK(current_state->flags);
        if (category_mask != 0 && current_state->transition_count == 0) {
            // Only dead-end states (no transitions) can accept
            best_category_mask = category_mask;
            best_state = current_state;
            best_length = pos + 1;
        }
    }

    // End of input - check if final state can accept
    // THEORY: A DFA state is accepting if it contains ANY NFA accepting state
    // (i.e., category_mask != 0). The EOS transition is already followed during
    // epsilon_closure, so the accepting state is included in the DFA state.
    // We do NOT require the state to have no outgoing transitions.
    uint8_t current_category_mask = DFA_GET_CATEGORY_MASK(current_state->flags);

    // A state is accepting if category_mask != 0 (contains at least one accepting NFA state)
    bool is_accepting = (current_category_mask != 0);

    if (is_accepting) {
        result->matched = true;
        result->matched_length = pos;
        result->final_state = current_state->flags;
        result->category_mask = current_category_mask;

        if (current_category_mask & 0x01) result->category = DFA_CMD_READONLY_SAFE;
        else if (current_category_mask & 0x02) result->category = DFA_CMD_READONLY_CAUTION;
        else if (current_category_mask & 0x04) result->category = DFA_CMD_MODIFYING;
        else if (current_category_mask & 0x08) result->category = DFA_CMD_DANGEROUS;
        else if (current_category_mask & 0x10) result->category = DFA_CMD_NETWORK;
        else if (current_category_mask & 0x20) result->category = DFA_CMD_ADMIN;
    }
    // NOTE: We removed the fallback to best_state
    // The DFA should only accept if the current state is accepting
    // If there's no valid transition, we don't accept (even if we saw an accepting state earlier)

    return result->matched;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
    return dfa_evaluate_with_limit(input, length, result, DFA_MAX_CAPTURES);
}
