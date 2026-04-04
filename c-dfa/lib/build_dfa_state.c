/**
 * Dynamic build_dfa_state_t implementation (Phase 6)
 */

#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define INITIAL_NFA_CAPACITY 64
#define NFA_GROWTH_FACTOR 2

build_dfa_state_t* build_dfa_state_create(int alphabet_size, int initial_nfa_capacity) {
    if (alphabet_size <= 0) alphabet_size = 1;
    if (initial_nfa_capacity <= 0) initial_nfa_capacity = INITIAL_NFA_CAPACITY;

    build_dfa_state_t* state = calloc(1, sizeof(build_dfa_state_t));
    if (!state) return NULL;

    if (alphabet_size > 0 && (size_t)alphabet_size > SIZE_MAX / sizeof(int)) {
        build_dfa_state_destroy(state);
        return NULL;
    }
    if (initial_nfa_capacity > 0 && (size_t)initial_nfa_capacity > SIZE_MAX / sizeof(int)) {
        build_dfa_state_destroy(state);
        return NULL;
    }

    state->transitions = malloc((size_t)alphabet_size * sizeof(int));
    state->transitions_from_any = malloc((size_t)alphabet_size * sizeof(bool));
    state->marker_offsets = malloc((size_t)alphabet_size * sizeof(uint32_t));
    state->nfa_states = malloc((size_t)initial_nfa_capacity * sizeof(int));

    if (!state->transitions || !state->transitions_from_any ||
        !state->marker_offsets || !state->nfa_states) {
        build_dfa_state_destroy(state);
        return NULL;
    }

    // Initialize transitions to "no transition"
    for (int i = 0; i < alphabet_size; i++) {
        state->transitions[i] = -1;
        state->transitions_from_any[i] = false;
        state->marker_offsets[i] = 0;
    }

    state->nfa_state_count = 0;
    state->nfa_state_capacity = initial_nfa_capacity;
    state->alphabet_size = alphabet_size;

    // Initialize metadata fields to zero/default
    state->transitions_offset = 0;
    state->transition_count = 0;
    state->flags = 0;
    state->accepting_pattern_id = 0;
    state->eos_target = 0;
    state->eos_marker_offset = 0;
    state->first_accepting_pattern = 0;
    state->reachable_accepting_patterns = 0;
    state->identity_hash = 0;

    return state;
}

void build_dfa_state_destroy(build_dfa_state_t* state) {
    if (!state) return;
    free(state->transitions);
    free(state->transitions_from_any);
    free(state->marker_offsets);
    free(state->nfa_states);
    free(state);
}

void build_dfa_state_destroy_array(build_dfa_state_t** states, int count) {
    if (!states) return;
    for (int i = 0; i < count; i++) {
        build_dfa_state_destroy(states[i]);
    }
    free(states);
}

bool build_dfa_state_grow_nfa(build_dfa_state_t* state, int additional) {
    int needed = state->nfa_state_count + additional;
    if (needed <= state->nfa_state_capacity) return true;

    int new_capacity = state->nfa_state_capacity;
    while (new_capacity < needed) {
        if (new_capacity > INT_MAX / NFA_GROWTH_FACTOR) return false;
        new_capacity *= NFA_GROWTH_FACTOR;
    }

    if (new_capacity > 0 && (size_t)new_capacity > SIZE_MAX / sizeof(int)) return false;

    void* tmp = realloc(state->nfa_states, (size_t)new_capacity * sizeof(int));
    if (!tmp) return false;
    state->nfa_states = tmp;
    state->nfa_state_capacity = new_capacity;
    return true;
}

build_dfa_state_t* build_dfa_state_clone(const build_dfa_state_t* src) {
    if (!src) return NULL;

    // Ensure we allocate enough capacity for all NFA states
    int required_nfa_capacity = src->nfa_state_count;
    if (required_nfa_capacity < src->nfa_state_capacity) {
        required_nfa_capacity = src->nfa_state_capacity;
    }

    build_dfa_state_t* dst = build_dfa_state_create(src->alphabet_size, required_nfa_capacity);
    if (!dst) return NULL;

    // Copy metadata fields
    dst->transitions_offset = src->transitions_offset;
    dst->transition_count = src->transition_count;
    dst->flags = src->flags;
    dst->accepting_pattern_id = src->accepting_pattern_id;
    dst->eos_target = src->eos_target;
    dst->eos_marker_offset = src->eos_marker_offset;
    dst->first_accepting_pattern = src->first_accepting_pattern;
    dst->reachable_accepting_patterns = src->reachable_accepting_patterns;
    dst->nfa_state_count = src->nfa_state_count;
    dst->identity_hash = src->identity_hash;

    // Copy arrays
    if (src->alphabet_size > 0) {
        memcpy(dst->transitions, src->transitions, sizeof(int) * src->alphabet_size);
        memcpy(dst->transitions_from_any, src->transitions_from_any, sizeof(bool) * src->alphabet_size);
        memcpy(dst->marker_offsets, src->marker_offsets, sizeof(uint32_t) * src->alphabet_size);
    }
    if (src->nfa_state_count > 0) {
        memcpy(dst->nfa_states, src->nfa_states, sizeof(int) * src->nfa_state_count);
    }

    return dst;
}