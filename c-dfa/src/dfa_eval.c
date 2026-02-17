#include "../include/dfa.h"
#include "../include/dfa_types.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

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
static size_t current_dfa_size = 0;
static char current_identifier[256] = "";

#define MAX_EVAL_LENGTH 16384
#define MAX_TRACE_LENGTH 16384
#define MAX_CAPTURE_STACK 32

typedef struct {
    int capture_id;
    size_t start_pos;
    size_t end_pos;
} capture_range_t;

/*
 * Look up capture name from the DFA's name table.
 * The name table maps pattern IDs to human-readable capture names.
 */
static const char* get_capture_name_from_table(int capture_id, int pattern_id) {
    (void)capture_id;
    (void)pattern_id;
    if (!current_dfa || current_dfa->metadata_offset == 0) {
        return NULL;
    }

    const char* base = (const char*)current_dfa;
    uint32_t entry_count = *(const uint32_t*)(base + current_dfa->metadata_offset);

    const char* p = base + current_dfa->metadata_offset + 4;
    for (uint32_t i = 0; i < entry_count; i++) {
        uint16_t entry_pattern_id = *(const uint16_t*)p;
        uint16_t name_len = *(const uint16_t*)(p + 2);

        if (entry_pattern_id == (uint16_t)pattern_id) {
            static char name_buf[64];
            snprintf(name_buf, sizeof(name_buf), "%.*s", name_len, p + 4);
            return name_buf;
        }

        p += 4 + name_len;
    }
    return NULL;
}

static void add_capture(dfa_result_t* result, int capture_id, size_t start, size_t end, uint16_t pattern_id) {
    if (result->capture_count >= DFA_MAX_CAPTURES) return;
    dfa_capture_t* cap = &result->captures[result->capture_count++];
    cap->start = start;
    cap->end = end;
    cap->capture_id = capture_id;

    // Phase 4: Look up capture name from name table
    const char* name = get_capture_name_from_table(capture_id, pattern_id);
    if (name) {
        snprintf(cap->name, sizeof(cap->name), "%.31s", name);
    } else {
        snprintf(cap->name, sizeof(cap->name), "capture_%d", capture_id);
    }
    cap->active = false;
    cap->completed = true;
}

static void process_marker_list(const uint32_t* marker_base, size_t pos,
                                 uint16_t winning_pattern_id, uint8_t category_mask,
                                 capture_range_t* capture_stack, int* stack_depth,
                                 dfa_result_t* result) {
    if (!marker_base) return;

    bool filter_by_pattern = (category_mask != 0 && winning_pattern_id != UINT16_MAX);

    for (int i = 0; marker_base[i] != MARKER_SENTINEL; i++) {
        uint32_t m = marker_base[i];
        uint16_t pattern_id = MARKER_GET_PATTERN_ID(m);
        uint16_t capture_id = MARKER_GET_UID(m);
        uint8_t type = MARKER_GET_TYPE(m);

        if (filter_by_pattern && pattern_id != winning_pattern_id) {
            continue;
        }

        if (type == MARKER_TYPE_START) {
            if (*stack_depth < MAX_CAPTURE_STACK) {
                capture_stack[*stack_depth].capture_id = capture_id;
                capture_stack[*stack_depth].start_pos = pos;
                capture_stack[*stack_depth].end_pos = 0;
                (*stack_depth)++;
            }
        } else if (type == MARKER_TYPE_END) {
            if (*stack_depth > 0) {
                for (int j = *stack_depth - 1; j >= 0; j--) {
                    if (capture_stack[j].capture_id == capture_id && capture_stack[j].end_pos == 0) {
                        capture_stack[j].end_pos = pos;
                        add_capture(result, capture_id, capture_stack[j].start_pos, pos, pattern_id);
                        break;
                    }
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
    current_dfa_size = size;
    EVAL_DEBUG_PRINT("DFA LOADED: initial_state=%u, state_count=%u, id_len=%u, size=%zu\n", 
                     dfa->initial_state, dfa->state_count, dfa->identifier_length, size);
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
    (void)max_caps;  // Reserved for future capture limit feature
    if (!current_dfa || !input || !result) {
        fprintf(stderr, "EVAL ERROR: current_dfa=%p, input=%p, result=%p\n", (void*)current_dfa, (void*)input, (void*)result);
        return false;
    }

    fprintf(stderr, "EVAL: Starting evaluation of '%s', length=%zu\n", input, length);
    memset(result, 0, sizeof(dfa_result_t));
    result->category = DFA_CMD_UNKNOWN;

    // Runtime validation: verify current_dfa structure
    if (current_dfa->magic != DFA_MAGIC || current_dfa->version < 5 || current_dfa->version > 6) {
        fprintf(stderr, "ERROR: Invalid DFA state in evaluator\n");
        return false;
    }

    if (length == 0) length = strlen(input);
    if (length == 0) {
        const char* raw_base = (const char*)current_dfa;
        const dfa_state_t* initial = (const dfa_state_t*)(raw_base + current_dfa->initial_state);
        uint8_t initial_cat = (uint8_t)DFA_GET_CATEGORY_MASK(initial->flags);
        
        const dfa_state_t* curr = initial;
        uint8_t eos_cat = 0;
        if (initial->eos_target != 0) {
            curr = (const dfa_state_t*)(raw_base + initial->eos_target);
            eos_cat = (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
        }
        // Use category from initial state if available, otherwise use eos_target state's category
        // This fixes the issue where eos_target points to a fork state that doesn't have category
        // but the initial state has the correct category in its flags
        uint8_t m = initial_cat ? initial_cat : eos_cat;
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
    
    EVAL_DEBUG_PRINT("DFA LOADED: initial_state=%u, first_state_offset=%u\n", 
                     current_dfa->initial_state, (unsigned int)((const char*)curr - raw_base));
    EVAL_DEBUG_PRINT("State 0: tc=%u, to=%u, flags=0x%04X\n", 
                     curr->transition_count, curr->transitions_offset, curr->flags);
    
    // Validate initial state
    if ((const char*)curr - raw_base != current_dfa->initial_state) {
        fprintf(stderr, "ERROR: Initial state offset mismatch (expected %u, got %zu)\n",
                current_dfa->initial_state, (const char*)curr - raw_base);
        return false;
    }
    
    const uint8_t* marker_base = NULL;
    if (current_dfa->metadata_offset != 0 && current_dfa->version >= 6) {
        marker_base = (const uint8_t*)current_dfa + current_dfa->metadata_offset;
    }
    
    uint32_t trace_buffer[MAX_TRACE_LENGTH];
    int trace_depth = 0;
    
    if (trace_depth < MAX_TRACE_LENGTH) {
        trace_buffer[trace_depth++] = (uint32_t)((const char*)curr - raw_base);
    }
    
    size_t pos = 0;
    size_t dfa_total_size = current_dfa->initial_state + current_dfa->state_count * sizeof(dfa_state_t);
    size_t rules_start = dfa_total_size;

    while (pos < length && pos < MAX_EVAL_LENGTH) {
        unsigned char c = (unsigned char)input[pos];
        const dfa_state_t* next = NULL;
        
        EVAL_DEBUG_PRINT("Pos %zu: char='%c'(0x%02X), state_offset=%u, tc=%u\n",
                         pos, c, c, (unsigned int)((const char*)curr - raw_base), curr->transition_count);

        // Validate current state is within DFA bounds
        size_t curr_offset = (const char*)curr - raw_base;
        if (curr_offset < current_dfa->initial_state || curr_offset >= dfa_total_size) {
            fprintf(stderr, "ERROR: Current state offset %zu is out of bounds [%u, %zu)\n",
                    curr_offset, current_dfa->initial_state, dfa_total_size);
            return false;
        }

        if (curr->transition_count > 0) {
            // Validate transitions_offset is reasonable (should point to rules area after states)
            if (curr->transitions_offset >= rules_start && curr->transitions_offset < current_dfa_size) {
                const dfa_rule_t* r = (const dfa_rule_t*)(raw_base + curr->transitions_offset);
                for (uint16_t i = 0; i < curr->transition_count; i++, r++) {
                    // Validate target is within DFA bounds (should be at state start)
                    if (r->target < current_dfa->initial_state || r->target >= dfa_total_size) {
                        fprintf(stderr, "ERROR: Rule target %u is out of bounds [%u, %zu)\n",
                                r->target, current_dfa->initial_state, dfa_total_size);
                        return false;
                    }
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
            } else {
                fprintf(stderr, "ERROR: transitions_offset %u is out of bounds [%zu, %zu)\n",
                        curr->transitions_offset, rules_start, current_dfa_size);
                return false;
            }
        }

        if (!next) {
            fprintf(stderr, "EVAL DEBUG: No transition for char '%c' (0x%02X) at pos %zu\n", (c >= 32 && c < 127) ? c : '.', c, pos);
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
    EVAL_DEBUG_PRINT("POST-LOOP: curr_offset=%u, eos_target=%u, trace_depth=%d\n",
                     (unsigned int)((const char*)curr - raw_base), curr->eos_target, trace_depth);

    // Save source state info BEFORE EOS jump - the source state has the category/accepting info
    uint8_t source_category = (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
    uint16_t source_accepting = curr->accepting_pattern_id;
    uint32_t source_eos_target = curr->eos_target;
    
    fprintf(stderr, "EVAL DEBUG: Pre-EOS: flags=0x%04X, cat=0x%02x, accept=%u, eos_target=%u\n",
            curr->flags, source_category, source_accepting, source_eos_target);
    
    if (curr->eos_target != 0) {
        const dfa_state_t* eos = (const dfa_state_t*)(raw_base + curr->eos_target);
        curr = eos;
        fprintf(stderr, "EVAL DEBUG: After EOS jump: flags=0x%04X, accept=%u\n",
                curr->flags, curr->accepting_pattern_id);
        EVAL_DEBUG_PRINT("EOS: jumped to offset %u\n", (unsigned int)((const char*)curr - raw_base));
        if (trace_depth < MAX_TRACE_LENGTH) {
            trace_buffer[trace_depth++] = (uint32_t)((const char*)curr - raw_base);
        }
        // Use SOURCE state's category and accepting_pattern, not target's
        // The source state has category from fork states, target is just the EOS endpoint
        winning_pattern_id = source_accepting;
    } else {
        EVAL_DEBUG_PRINT("NO EOS: staying at offset %u\n", (unsigned int)((const char*)curr - raw_base));
        winning_pattern_id = curr->accepting_pattern_id;
    }

    // Use source state's category if available, otherwise use current state's
    uint8_t mask = source_category ? source_category : (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
    fprintf(stderr, "EVAL DEBUG: Final: source_cat=0x%02x, source_accept=%u, curr_flags=0x%04X, mask=0x%02X, winning=%u\n",
            source_category, source_accepting, curr->flags, mask, winning_pattern_id);
    EVAL_DEBUG_PRINT("CATEGORY: final_offset=%u, flags=0x%04X, mask=0x%02X, winning_pattern_id=%u\n",
                     (unsigned int)((const char*)curr - raw_base), curr->flags, mask, winning_pattern_id);

    // Check for valid accepting state: either has category mask OR has valid pattern_id
    // winning_pattern_id = 0 means "not accepting", UINT16_MAX means "no pattern"
    bool has_valid_accept = (mask != 0) || (winning_pattern_id != 0 && winning_pattern_id != UINT16_MAX);
    if (has_valid_accept) {
        result->matched = true;
        result->matched_length = pos;
        result->category_mask = mask;
        result->final_state = (uint32_t)((const char*)curr - raw_base);
        EVAL_DEBUG_PRINT("RESULT: matched=%d, len=%zu, cat=0x%02X, final_state=%u\n",
                         result->matched, pos, mask, result->final_state);
        for (int i = 0; i < 8; i++) if (mask & (1 << i)) { result->category = (dfa_command_category_t)(i + 1); break; }
        
        if (current_dfa->version >= 6 && winning_pattern_id != 0 && winning_pattern_id != UINT16_MAX) {
            capture_range_t capture_stack[MAX_CAPTURE_STACK];
            int stack_depth = 0;

            /*
             * PHASE 4: PASS 2 - REPLAY TRACE TO EXTRACT CAPTURES
             *
             * Markers are attached to TRANSITIONS (edges), not states.
             * The trace records: [initial_state, state_after_char0, state_after_char1, ...]
             *
             * When transitioning from trace[t-1] to trace[t]:
             *   - We consumed character at position (t-1)
             *   - Markers on that transition fire at position (t-1)
              *   - We filter by winning_pattern_id to only extract the matched pattern's captures
             */

            // Phase 4: Pass 2 - Replay trace and process markers at each transition
            /*
             * For each step in the trace (from state at t-1 to state at t):
             *   - Character position = t-1 (the character we just consumed)
             *   - Look up the rule that took us from trace[t-1] to trace[t]
             *   - Process any markers attached to that rule/transition
             *   - Markers are filtered by winning_pattern_id
             */
            for (int t = 1; t < trace_depth && (size_t)t <= pos; t++) {
                uint32_t from_state_offset = trace_buffer[t - 1];
                uint32_t to_state_offset = trace_buffer[t];

                // Find the rule that led to this transition
                const dfa_state_t* from_state = (const dfa_state_t*)(raw_base + from_state_offset);

                if (from_state->transition_count == 0 || from_state->transitions_offset == 0) {
                    continue;
                }

                /*
                 * Find the rule that led from from_state to to_state.
                 * Markers are stored on RULES (which represent transitions),
                 * so we must find the specific rule that matches our target.
                 */
                const dfa_rule_t* r = (const dfa_rule_t*)(raw_base + from_state->transitions_offset);
                const uint32_t* transition_markers = NULL;

                for (uint16_t i = 0; i < from_state->transition_count; i++, r++) {
                    if (r->target == to_state_offset) {
                        if (r->marker_offset != 0 && marker_base) {
                            transition_markers = (const uint32_t*)((const uint8_t*)current_dfa + r->marker_offset);
                        }
                        break;
                    }
                }

                if (transition_markers) {
                    process_marker_list(transition_markers, t - 1, winning_pattern_id, mask,
                                       capture_stack, &stack_depth, result);
                }
            }

            // Phase 4: Process EOS markers at the final position
            if (curr->eos_marker_offset != 0 && marker_base) {
                const uint32_t* eos_markers = (const uint32_t*)((const uint8_t*)current_dfa + curr->eos_marker_offset);
                process_marker_list(eos_markers, pos, winning_pattern_id, mask,
                                   capture_stack, &stack_depth, result);
            }
        }
    }

    return result->matched;
}

bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result) {
    return dfa_evaluate_with_limit(input, length, result, DFA_MAX_CAPTURES);
}
