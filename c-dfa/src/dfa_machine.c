/**
 * dfa_machine.c - DFA machine lifecycle functions
 * Part of the full library (libreadonlybox_dfa.a), NOT the eval library.
 */

#include "dfa_internal.h"
#include <string.h>
#include <stdio.h>

bool dfa_machine_init(dfa_machine_t* m, const void* dfa_data, size_t size) {
    return dfa_machine_init_with_id(m, dfa_data, size, NULL);
}

bool dfa_machine_init_with_id(dfa_machine_t* m, const void* dfa_data, size_t size, const char* expected_id) {
    if (!m || !dfa_data || size < sizeof(dfa_t)) return false;

    const dfa_t* dfa = (const dfa_t*)dfa_data;
    if (dfa->magic != DFA_MAGIC) return false;
    if (dfa->version < 9 || dfa->version > 10) return false;
    if (dfa->state_count == 0 || dfa->initial_state >= size) return false;

    // Validate identifier match at load time (if requested)
    if (expected_id) {
        if (dfa->identifier_length != strlen(expected_id) ||
            memcmp(dfa->identifier, expected_id, dfa->identifier_length) != 0) {
            return false;
        }
    }

    m->dfa = dfa;
    m->dfa_size = size;

    if (expected_id) {
        strncpy(m->identifier, expected_id, sizeof(m->identifier) - 1);
        m->identifier[sizeof(m->identifier) - 1] = '\0';
    } else {
        m->identifier[0] = '\0';
    }

    return true;
}

void dfa_machine_reset(dfa_machine_t* m) {
    if (m) {
        m->dfa = NULL;
        m->dfa_size = 0;
        m->identifier[0] = '\0';
    }
}

bool dfa_machine_is_valid(const dfa_machine_t* m) {
    return m && m->dfa != NULL;
}

const dfa_t* dfa_machine_get_dfa(const dfa_machine_t* m) {
    return m ? m->dfa : NULL;
}

const char* dfa_machine_get_identifier(const dfa_machine_t* m) {
    return m ? m->identifier : "";
}

uint16_t dfa_machine_get_version(const dfa_machine_t* m) {
    return (m && m->dfa) ? m->dfa->version : 0;
}

uint16_t dfa_machine_get_state_count(const dfa_machine_t* m) {
    return (m && m->dfa) ? m->dfa->state_count : 0;
}
