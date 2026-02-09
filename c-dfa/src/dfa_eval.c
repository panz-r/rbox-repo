#include "../include/dfa.h"
#include "../include/dfa_types.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * DFA Evaluator - Lean Production Version (V5 Only)
 * 
 * Performance Constraints:
 * - O(1) memory allocation (stack only)
 * - Thread-safe matching hot-path
 * - Optimized rule dispatch for Version 5 compact format
 */

#ifndef DFA_EVAL_DEBUG
#define DFA_EVAL_DEBUG 1
#endif

#if DFA_EVAL_DEBUG
#include <stdio.h>
#define EVAL_DEBUG_PRINT(fmt, ...) fprintf(stderr, "DEBUG: " fmt, ##__VA_ARGS__)
#define EVAL_DEBUG_FLUSH() fflush(stderr)
#else
#define EVAL_DEBUG_PRINT(fmt, ...) ((void)0)
#define EVAL_DEBUG_FLUSH() ((void)0)
#endif

// Machine state - Set once via dfa_init
static const dfa_t* current_dfa = NULL;
static char current_identifier[256] = "";

#define MAX_EVAL_LENGTH 16384 
#define MAX_DEFER_STACK 16

typedef struct {
    size_t start_pos;
    bool active;
    int capture_id;
} eval_capture_t;

typedef struct {
    int capture_id;
    size_t start_pos;
} defer_entry_t;

static void set_capture_name(char* dst, int id) {
    memcpy(dst, "capture_", 8);
    if (id < 10) {
        dst[8] = (char)('0' + id);
        dst[9] = '\0';
    } else if (id < 100) {
        dst[8] = (char)('0' + (id / 10));
        dst[9] = (char)('0' + (id % 10));
        dst[10] = '\0';
    } else {
        dst[8] = '?'; dst[9] = '\0';
    }
}

static void process_markers(const dfa_state_t* state, eval_capture_t* active, 
                           size_t pos, dfa_result_t* result, int max_caps,
                           defer_entry_t* defer_stack, int* defer_depth) {
    uint16_t flags = state->flags;

    if (flags & DFA_STATE_CAPTURE_START) {
        int id = state->capture_start_id;
        if (id >= 0) {
            for (int i = 0; i < DFA_MAX_CAPTURES; i++) {
                if (!active[i].active) {
                    active[i].capture_id = id;
                    active[i].start_pos = pos;
                    active[i].active = true;
                    break;
                }
            }
        }
    }

    if (flags & DFA_STATE_CAPTURE_END) {
        int id = state->capture_end_id;
        if (id >= 0) {
            for (int i = 0; i < DFA_MAX_CAPTURES; i++) {
                if (active[i].active && active[i].capture_id == id) {
                    if (max_caps < 0 || result->capture_count < max_caps) {
                        if (result->capture_count < DFA_MAX_CAPTURES) {
                            dfa_capture_t* cap = &result->captures[result->capture_count++];
                            cap->start = active[i].start_pos;
                            cap->end = pos;
                            cap->active = false;
                            cap->completed = true;
                            set_capture_name(cap->name, id);
                            cap->capture_id = id;
                        }
                    }
                    active[i].active = false;
                    break;
                }
            }
        }
    }

    if (flags & DFA_STATE_CAPTURE_DEFER) {
        int id = state->capture_defer_id;
        if (id >= 0 && *defer_depth < MAX_DEFER_STACK) {
            for (int i = 0; i < DFA_MAX_CAPTURES; i++) {
                if (active[i].active && active[i].capture_id == id) {
                    defer_stack[*defer_depth].capture_id = id;
                    defer_stack[*defer_depth].start_pos = active[i].start_pos;
                    (*defer_depth)++;
                    break;
                }
            }
        }
    }
}

static void process_deferred(const dfa_state_t* next, defer_entry_t* stack, int* depth, 
                            size_t pos, dfa_result_t* res) {
    int d_count = *depth;
    if (d_count == 0) return;

    int write_idx = 0;
    for (int i = 0; i < d_count; i++) {
        bool still_deferred = false;
        if (next->flags & DFA_STATE_CAPTURE_DEFER) {
            if (next->capture_defer_id == stack[i].capture_id) still_deferred = true;
        }

        if (!still_deferred) {
            if (res->capture_count < DFA_MAX_CAPTURES) {
                dfa_capture_t* cap = &res->captures[res->capture_count++];
                cap->start = stack[i].start_pos;
                cap->end = pos;
                cap->active = false;
                cap->completed = true;
                set_capture_name(cap->name, stack[i].capture_id);
                cap->capture_id = stack[i].capture_id;
            }
        } else {
            if (write_idx != i) stack[write_idx] = stack[i];
            write_idx++;
        }
    }
    *depth = write_idx;
}

bool dfa_init(const void* data, size_t size) {
    return dfa_init_with_identifier(data, size, NULL);
}

bool dfa_init_with_identifier(const void* data, size_t size, const char* expected_id) {
    if (!data || size < sizeof(dfa_t)) return false;
    const dfa_t* dfa = (const dfa_t*)data;
    if (dfa->magic != DFA_MAGIC) return false;
    if (dfa->version != 5) return false; // V5 only
    if (dfa->state_count == 0 || dfa->initial_state >= size) return false;

    if (expected_id) {
        strncpy(current_identifier, expected_id, 255);
        current_identifier[255] = '\0';
    } else {
        current_identifier[0] = '\0';
    }

    current_dfa = dfa;
    EVAL_DEBUG_PRINT("DFA LOADED: initial_state=%u, state_count=%u, id_len=%u\n", 
                     dfa->initial_state, dfa->state_count, dfa->identifier_length);
    return true;
}

bool dfa_is_valid(void) { return current_dfa != NULL; }
const char* dfa_get_identifier(void) { return current_identifier; }
uint16_t dfa_get_version(void) { return current_dfa ? current_dfa->version : 0; }
uint16_t dfa_get_state_count(void) { return current_dfa ? current_dfa->state_count : 0; }
bool dfa_reset(void) { current_dfa = NULL; return true; }
const dfa_t* dfa_get_current(void) { return current_dfa; }

const char* dfa_category_string(dfa_command_category_t cat) {
    static const char* names[] = {"Unknown", "Read-only (Safe)", "Read-only (Caution)", 
                                 "Modifying", "Dangerous", "Network", "Admin"};
    int idx = (int)cat;
    return (idx >= 0 && idx <= 6) ? names[idx] : "Invalid";
}

bool dfa_evaluate_with_limit(const char* input, size_t length, dfa_result_t* result, int max_caps) {
    if (!current_dfa || !input || !result) return false;

    eval_capture_t active[DFA_MAX_CAPTURES];
    defer_entry_t defer_stack[MAX_DEFER_STACK];
    int defer_depth = 0;
    
    memset(active, 0, sizeof(active));
    memset(result, 0, sizeof(dfa_result_t));
    result->category = DFA_CMD_UNKNOWN;

    if (length == 0) length = strlen(input);
    const char* raw_base = (const char*)current_dfa;
    const dfa_state_t* curr = (const dfa_state_t*)(raw_base + current_dfa->initial_state);

    if (length == 0) {
        // Handle empty input string match if initial state is accepting or has EOS transition
        if (curr->eos_target != 0) {
            curr = (const dfa_state_t*)(raw_base + curr->eos_target);
        }
        uint8_t m = (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
        if (m != 0) {
            result->matched = true;
            result->matched_length = 0;
            result->category_mask = m;
            for (int i = 0; i < 8; i++) if (m & (1 << i)) { result->category = (dfa_command_category_t)(i + 1); break; }
            return true;
        }
        return true; 
    }

    size_t pos = 0;

    process_markers(curr, active, 0, result, max_caps, defer_stack, &defer_depth);

    while (pos < length && pos < MAX_EVAL_LENGTH) {
        unsigned char c = (unsigned char)input[pos];
        const dfa_state_t* next = NULL;

        if (curr->transition_count > 0) {
            const dfa_rule_t* r = (const dfa_rule_t*)(raw_base + curr->transitions_offset);
            EVAL_DEBUG_PRINT("State offset %ld, transitions: %d, input char: '%c' (%d)\n", 
                            (const char*)curr - raw_base, curr->transition_count, c, c);
            for (uint16_t i = 0; i < curr->transition_count; i++, r++) {
                bool m = false;
                EVAL_DEBUG_PRINT("  Rule %d: type=%d, d1=%d, d2=%d, target=%u\n", i, r->type, r->data1, r->data2, r->target);
                switch (r->type) {
                    case DFA_RULE_LITERAL: m = (c == r->data1); break;
                    case DFA_RULE_RANGE:   m = (c >= r->data1 && c <= r->data2); break;
                    case DFA_RULE_LITERAL_2: m = (c == r->data1 || c == r->data2); break;
                    case DFA_RULE_LITERAL_3: m = (c == r->data1 || c == r->data2 || c == r->data3); break;
                    case DFA_RULE_RANGE_LITERAL: m = ((c >= r->data1 && c <= r->data2) || c == r->data3); break;
                    case DFA_RULE_DEFAULT: m = true; break;
                    case DFA_RULE_NOT_LITERAL: m = (c != r->data1); break;
                    case DFA_RULE_NOT_RANGE:   m = (c < r->data1 || c > r->data2); break;
                }
                if (m) { 
                    if (r->target >= 1000000) { // Safety check against obvious corruption
                         fprintf(stderr, "FATAL: Evaluator encountered corrupt target offset %u\n", r->target);
                         return false;
                    }
                    next = (const dfa_state_t*)(raw_base + r->target); 
                    break; 
                }
            }
        }

        if (!next) return false;

        pos++;
        process_deferred(next, defer_stack, &defer_depth, pos, result);
        process_markers(next, active, pos, result, max_caps, defer_stack, &defer_depth);
        curr = next;
    }

    if (curr->eos_target != 0) {
        const dfa_state_t* eos = (const dfa_state_t*)(raw_base + curr->eos_target);
        process_deferred(eos, defer_stack, &defer_depth, pos, result);
        process_markers(eos, active, pos, result, max_caps, defer_stack, &defer_depth);
        curr = eos;
    }

    uint8_t mask = (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
    if (mask != 0) {
        result->matched = true;
        result->matched_length = pos;
        result->category_mask = mask;
        result->final_state = (uint32_t)((const char*)curr - raw_base);
        for (int i = 0; i < 8; i++) if (mask & (1 << i)) { result->category = (dfa_command_category_t)(i + 1); break; }
    }

    return result->matched;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
    return dfa_evaluate_with_limit(input, length, result, DFA_MAX_CAPTURES);
}
