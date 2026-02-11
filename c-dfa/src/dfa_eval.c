#include "../include/dfa.h"
#include "../include/dfa_types.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * DFA Evaluator - Phase 4: Path-Trace Evaluator with Capture Extraction
 * 
 * This evaluator records the matching path and uses it to filter markers
 * by the winning pattern ID, enabling correct capture extraction from
 * patterns with overlapping rules.
 */

#ifndef DFA_EVAL_DEBUG
#define DFA_EVAL_DEBUG 0
#endif

#if DFA_EVAL_DEBUG
#include <stdio.h>
#define EVAL_DEBUG_PRINT(fmt, ...) fprintf(stderr, "[EVAL] " fmt, ##__VA_ARGS__)
#define EVAL_DEBUG_FLUSH() fflush(stderr)
#else
#define EVAL_DEBUG_PRINT(fmt, ...) ((void)0)
#define EVAL_DEBUG_FLUSH() ((void)0)
#endif

// Machine state - Set once via dfa_init
static const dfa_t* current_dfa = NULL;
static char current_identifier[256] = "";

#define MAX_EVAL_LENGTH 16384 
#define MAX_TRACE_LENGTH 16384
#define MAX_CAPTURE_STACK 32

typedef struct {
    int capture_id;
    size_t start_pos;
    size_t end_pos;
} capture_range_t;

static void add_capture(dfa_result_t* result, int capture_id, size_t start, size_t end) {
    if (result->capture_count >= DFA_MAX_CAPTURES) return;
    dfa_capture_t* cap = &result->captures[result->capture_count++];
    cap->start = start;
    cap->end = end;
    cap->capture_id = capture_id;
    snprintf(cap->name, sizeof(cap->name), "capture_%d", capture_id);
    cap->active = false;
    cap->completed = true;
}

static void process_marker_list(const uint32_t* marker_base, size_t pos, 
                                 uint16_t winning_pattern_id,
                                 capture_range_t* capture_stack, int* stack_depth,
                                 dfa_result_t* result) {
    if (!marker_base) return;
    
    for (int i = 0; marker_base[i] != MARKER_SENTINEL && marker_base[i] != 0; i++) {
        uint32_t m = marker_base[i];
        uint16_t pattern_id = MARKER_GET_PATTERN_ID(m);
        uint16_t capture_id = MARKER_GET_UID(m);
        uint8_t type = MARKER_GET_TYPE(m);
        
        // Phase 4: Filter by winning pattern ID
        if (winning_pattern_id != UINT16_MAX && pattern_id != winning_pattern_id) {
            continue;
        }
        
        if (type == MARKER_TYPE_START) {
            if (*stack_depth < MAX_CAPTURE_STACK) {
                capture_stack[*stack_depth].capture_id = capture_id;
                capture_stack[*stack_depth].start_pos = pos;
                capture_stack[*stack_depth].end_pos = 0;
                (*stack_depth)++;
            }
        } else {
            for (int j = *stack_depth - 1; j >= 0; j--) {
                if (capture_stack[j].capture_id == capture_id && capture_stack[j].end_pos == 0) {
                    capture_stack[j].end_pos = pos;
                    add_capture(result, capture_id, capture_stack[j].start_pos, pos);
                    break;
                }
            }
        }
    }
}

bool dfa_init(const void* data, size_t size) {
    return dfa_init_with_identifier(data, size, NULL);
}

bool dfa_init_with_identifier(const void* data, size_t size, const char* expected_id) {
    if (!data || size < sizeof(dfa_t)) return false;
    const dfa_t* dfa = (const dfa_t*)data;
    if (dfa->magic != DFA_MAGIC) return false;
    if (dfa->version < 5 || dfa->version > 6) return false;
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

/**
 * Phase 4 Evaluator: Path-Trace with Winning Pattern Filter
 * 
 * Pass 1: Record the trace (state indices) during matching
 * Pass 2: Replay the trace to extract captures filtered by winning pattern
 */
bool dfa_evaluate_with_limit(const char* input, size_t length, dfa_result_t* result, int max_caps) {
    if (!current_dfa || !input || !result) return false;

    memset(result, 0, sizeof(dfa_result_t));
    result->category = DFA_CMD_UNKNOWN;

    if (length == 0) length = strlen(input);
    if (length == 0) {
        const char* raw_base = (const char*)current_dfa;
        const dfa_state_t* curr = (const dfa_state_t*)(raw_base + current_dfa->initial_state);
        if (curr->eos_target != 0) {
            curr = (const dfa_state_t*)(raw_base + curr->eos_target);
        }
        uint8_t m = (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
        if (m != 0) {
            result->matched = true;
            result->matched_length = 0;
            result->category_mask = m;
            for (int i = 0; i < 8; i++) if (m & (1 << i)) { result->category = (dfa_command_category_t)(i + 1); break; }
        }
        return result->matched;
    }

    const char* raw_base = (const char*)current_dfa;
    const dfa_state_t* curr = (const dfa_state_t*)(raw_base + current_dfa->initial_state);
    
    EVAL_DEBUG_PRINT("Starting evaluation, initial_state=%u, first_state_offset=%u\n", 
                     current_dfa->initial_state, (unsigned int)((const char*)curr - raw_base));
    EVAL_DEBUG_PRINT("State 0: tc=%u, to=%u, flags=0x%04X\n", 
                     curr->transition_count, curr->transitions_offset, curr->flags);
    
    const uint32_t* marker_base = NULL;
    if (current_dfa->metadata_offset != 0 && current_dfa->version >= 6) {
        marker_base = (const uint32_t*)((const char*)current_dfa + current_dfa->metadata_offset);
    }
    
    uint32_t trace_buffer[MAX_TRACE_LENGTH];
    int trace_depth = 0;
    
    if (trace_depth < MAX_TRACE_LENGTH) {
        trace_buffer[trace_depth++] = (uint32_t)((const char*)curr - raw_base);
    }
    
    size_t pos = 0;

    while (pos < length && pos < MAX_EVAL_LENGTH) {
        unsigned char c = (unsigned char)input[pos];
        const dfa_state_t* next = NULL;
        
        EVAL_DEBUG_PRINT("Pos %zu: char='%c'(0x%02X), state_offset=%u, tc=%u\n",
                         pos, c, c, (unsigned int)((const char*)curr - raw_base), curr->transition_count);

        if (curr->transition_count > 0) {
            const dfa_rule_t* r = (const dfa_rule_t*)(raw_base + curr->transitions_offset);
            for (uint16_t i = 0; i < curr->transition_count; i++, r++) {
                bool m = false;
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
                    EVAL_DEBUG_PRINT("  Rule %u: type=%u matched, target=%u\n", i, r->type, r->target);
                    if (r->target >= 1000000) {
                        fprintf(stderr, "FATAL: Evaluator encountered corrupt target offset %u\n", r->target);
                        return false;
                    }
                    next = (const dfa_state_t*)(raw_base + r->target);
                    break;
                }
            }
        }

        if (!next) {
            EVAL_DEBUG_PRINT("  No transition found for char '%c'\n", c);
            return false;
        }

        pos++;
        curr = next;
        if (trace_depth < MAX_TRACE_LENGTH) {
            trace_buffer[trace_depth++] = (uint32_t)((const char*)curr - raw_base);
        }
    }

    uint16_t winning_pattern_id = UINT16_MAX;  // UINT16_MAX = no accepting pattern
    if (curr->eos_target != 0) {
        const dfa_state_t* eos = (const dfa_state_t*)(raw_base + curr->eos_target);
        curr = eos;
        if (trace_depth < MAX_TRACE_LENGTH) {
            trace_buffer[trace_depth++] = (uint32_t)((const char*)curr - raw_base);
        }
        winning_pattern_id = curr->accepting_pattern_id;
    } else {
        winning_pattern_id = curr->accepting_pattern_id;
    }

    uint8_t mask = (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
    if (mask != 0 || winning_pattern_id != UINT16_MAX) {
        result->matched = true;
        result->matched_length = pos;
        result->category_mask = mask;
        result->final_state = (uint32_t)((const char*)curr - raw_base);
        for (int i = 0; i < 8; i++) if (mask & (1 << i)) { result->category = (dfa_command_category_t)(i + 1); break; }
        
        if (current_dfa->version >= 6 && winning_pattern_id != UINT16_MAX) {
            capture_range_t capture_stack[MAX_CAPTURE_STACK];
            int stack_depth = 0;
            
            for (int t = 1; t < trace_depth && t <= pos; t++) {
                uint32_t from_state_offset = trace_buffer[t - 1];
                uint32_t to_state_offset = trace_buffer[t];
                
    // Check if we're on a transition that has markers
    const dfa_state_t* from_state = (const dfa_state_t*)(raw_base + from_state_offset);
    
    const dfa_rule_t* r = (const dfa_rule_t*)(raw_base + from_state->transitions_offset);
    const uint32_t* transition_markers = NULL;
    
    for (uint16_t i = 0; i < from_state->transition_count; i++, r++) {
        if (r->target == to_state_offset) {
            if (r->marker_offset != 0 && marker_base) {
                transition_markers = marker_base + r->marker_offset;
                fprintf(stderr, "[EVAL] Found markers at rule offset %u\n", r->marker_offset);
            }
            break;
        }
    }
    
    if (transition_markers) {
        fprintf(stderr, "[EVAL] Processing markers, winning_pattern_id=%u\n", winning_pattern_id);
        for (int m = 0; transition_markers[m] != MARKER_SENTINEL && transition_markers[m] != 0; m++) {
            fprintf(stderr, "  marker[%d] = 0x%08X\n", m, transition_markers[m]);
        }
        process_marker_list(transition_markers, t - 1, winning_pattern_id,
                                       capture_stack, &stack_depth, result);
                }
            }
            
            if (curr->eos_marker_offset != 0 && marker_base) {
                const uint32_t* eos_markers = marker_base + curr->eos_marker_offset;
                process_marker_list(eos_markers, pos, winning_pattern_id,
                                   capture_stack, &stack_depth, result);
            }
        }
    }

    return result->matched;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
    return dfa_evaluate_with_limit(input, length, result, DFA_MAX_CAPTURES);
}
