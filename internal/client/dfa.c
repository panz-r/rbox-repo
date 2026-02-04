#include "dfa.h"
#include <stdio.h>
#include <string.h>

extern const unsigned char readonlybox_dfa_data[];
extern const size_t readonlybox_dfa_size;
extern const char* readonlybox_dfa_identifier;

static bool g_dfa_initialized = false;

int dfa_should_allow(const char* cmd) {
    if (cmd == NULL || cmd[0] == '\0') {
        return 0;
    }

    if (!g_dfa_initialized) {
        if (!dfa_init_with_identifier(readonlybox_dfa_data, readonlybox_dfa_size, readonlybox_dfa_identifier)) {
            return 0;
        }
        g_dfa_initialized = true;
    }

    dfa_result_t result;
    if (dfa_evaluate(cmd, 0, &result)) {
        return (result.category_mask & CAT_MASK_SAFE) && result.matched;
    }
    return 0;
}

void dfa_debug(const char* cmd) {
    if (cmd == NULL || cmd[0] == '\0') {
        return;
    }

    if (!g_dfa_initialized) {
        if (!dfa_init_with_identifier(readonlybox_dfa_data, readonlybox_dfa_size, readonlybox_dfa_identifier)) {
            fprintf(stderr, "DFA init failed (identifier mismatch or invalid data)\n");
            return;
        }
        g_dfa_initialized = true;
    }

    dfa_result_t result;
    if (dfa_evaluate(cmd, 0, &result)) {
        fprintf(stderr, "DFA result for '%s': matched=%s, category_mask=0x%02x, length=%zu\n",
                cmd, result.matched ? "yes" : "no",
                result.category_mask,
                result.matched_length);
    }
}
