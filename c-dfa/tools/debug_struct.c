#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../include/dfa_types.h"

int main() {
    printf("=== STRUCT SIZE ANALYSIS ===\n");
    printf("sizeof(dfa_state_t) = %zu (expected 18)\n", sizeof(dfa_state_t));
    printf("sizeof(dfa_t) = %zu (expected 23)\n", sizeof(dfa_t));
    printf("sizeof(dfa_rule_t) = %zu (expected 14)\n", sizeof(dfa_rule_t));
    
    printf("\n=== DFA_T OFFSETS ===\n");
    printf("offsetof(magic) = %zu\n", offsetof(dfa_t, magic));
    printf("offsetof(version) = %zu\n", offsetof(dfa_t, version));
    printf("offsetof(state_count) = %zu\n", offsetof(dfa_t, state_count));
    printf("offsetof(initial_state) = %zu\n", offsetof(dfa_t, initial_state));
    printf("offsetof(accepting_mask) = %zu\n", offsetof(dfa_t, accepting_mask));
    printf("offsetof(flags) = %zu\n", offsetof(dfa_t, flags));
    printf("offsetof(identifier_length) = %zu\n", offsetof(dfa_t, identifier_length));
    printf("offsetof(metadata_offset) = %zu\n", offsetof(dfa_t, metadata_offset));
    printf("offsetof(identifier) = %zu\n", offsetof(dfa_t, identifier));
    
    printf("\n=== DFA_STATE_T OFFSETS ===\n");
    printf("offsetof(transitions_offset) = %zu\n", offsetof(dfa_state_t, transitions_offset));
    printf("offsetof(transition_count) = %zu\n", offsetof(dfa_state_t, transition_count));
    printf("offsetof(flags) = %zu\n", offsetof(dfa_state_t, flags));
    printf("offsetof(accepting_pattern_id) = %zu\n", offsetof(dfa_state_t, accepting_pattern_id));
    printf("offsetof(eos_target) = %zu\n", offsetof(dfa_state_t, eos_target));
    printf("offsetof(eos_marker_offset) = %zu\n", offsetof(dfa_state_t, eos_marker_offset));
    
    printf("\n=== STATE CALCULATION TEST ===\n");
    size_t header_size = 23;
    size_t id_len = 6;
    size_t initial_state = header_size + id_len;
    printf("header_size = %zu, id_len = %zu, initial_state = %zu\n", header_size, id_len, initial_state);
    
    printf("\nState offsets (each state is %zu bytes):\n", sizeof(dfa_state_t));
    printf("State 0 offset: %zu\n", initial_state);
    printf("State 1 offset: %zu\n", initial_state + sizeof(dfa_state_t));
    printf("State 2 offset: %zu\n", initial_state + 2 * sizeof(dfa_state_t));
    printf("State 3 offset: %zu\n", initial_state + 3 * sizeof(dfa_state_t));
    
    printf("\n=== PACKING VERIFICATION ===\n");
    size_t to_off = offsetof(dfa_state_t, transition_count) - offsetof(dfa_state_t, transitions_offset);
    size_t tc_off = offsetof(dfa_state_t, flags) - offsetof(dfa_state_t, transition_count);
    size_t f_off = offsetof(dfa_state_t, accepting_pattern_id) - offsetof(dfa_state_t, flags);
    size_t ap_off = offsetof(dfa_state_t, eos_target) - offsetof(dfa_state_t, accepting_pattern_id);
    size_t et_off = offsetof(dfa_state_t, eos_marker_offset) - offsetof(dfa_state_t, eos_target);
    
    printf("transitions_offset field size: %zu bytes\n", to_off);
    printf("transition_count field size: %zu bytes\n", tc_off);
    printf("flags field size: %zu bytes\n", f_off);
    printf("accepting_pattern_id field size: %zu bytes\n", ap_off);
    printf("eos_target field size: %zu bytes\n", et_off);
    printf("eos_marker_offset extends to: %zu bytes total\n", sizeof(dfa_state_t));
    
    return 0;
}
