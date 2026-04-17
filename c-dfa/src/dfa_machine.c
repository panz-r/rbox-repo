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
    const uint8_t* d = (const uint8_t*)dfa_data;
    if (dfa_fmt_magic(d) != DFA_MAGIC) return false;
    if (dfa_fmt_version(d) < 9 || dfa_fmt_version(d) > DFA_VERSION) return false;
    if (dfa_fmt_state_count(d) == 0 || dfa_fmt_initial_state(d) >= size) return false;

    // Validate identifier match at load time (if requested)
    if (expected_id) {
        uint8_t id_len = dfa_fmt_id_len(d);
        const uint8_t* id_data = dfa_fmt_identifier(d);
        if (id_len != strlen(expected_id) || memcmp(id_data, expected_id, id_len) != 0) {
            return false;
        }
    }

    m->dfa = (const dfa_t*)d;
    m->dfa_size = size;

    if (expected_id) {
        snprintf(m->identifier, sizeof(m->identifier), "%s", expected_id);
    } else {
        m->identifier[0] = '\0';
    }

    return true;
}

void dfa_machine_reset(dfa_machine_t* m) {
    m->dfa = NULL;
    m->dfa_size = 0;
    m->identifier[0] = '\0';
}

bool dfa_machine_is_valid(const dfa_machine_t* m) {
    return m->dfa != NULL;
}

const dfa_t* dfa_machine_get_dfa(const dfa_machine_t* m) {
    return m->dfa;
}

const char* dfa_machine_get_identifier(const dfa_machine_t* m) {
    return m->identifier;
}

uint16_t dfa_machine_get_version(const dfa_machine_t* m) {
    if (!m->dfa) return 0;
    return m->dfa->version;
}

uint16_t dfa_machine_get_state_count(const dfa_machine_t* m) {
    if (!m->dfa) return 0;
    return m->dfa->state_count;
}
