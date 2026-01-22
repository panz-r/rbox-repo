#include "dfa.h"
#include <stdio.h>
#include <string.h>

extern const unsigned char readonlybox_dfa_data[];
extern const size_t readonlybox_dfa_size;

static bool g_dfa_initialized = false;

int dfa_should_allow(const char* cmd) {
    if (cmd == NULL || cmd[0] == '\0') {
        return 0;
    }

    if (!g_dfa_initialized) {
        if (!dfa_init(readonlybox_dfa_data, readonlybox_dfa_size)) {
            return 0;
        }
        g_dfa_initialized = true;
    }

    dfa_result_t result;
    if (dfa_evaluate(cmd, 0, &result)) {
        return result.category == DFA_CMD_READONLY_SAFE && result.matched;
    }
    return 0;
}

void dfa_debug(const char* cmd) {
    if (cmd == NULL || cmd[0] == '\0') {
        return;
    }

    if (!g_dfa_initialized) {
        if (!dfa_init(readonlybox_dfa_data, readonlybox_dfa_size)) {
            fprintf(stderr, "DFA init failed\n");
            return;
        }
        g_dfa_initialized = true;
    }

    dfa_result_t result;
    if (dfa_evaluate(cmd, 0, &result)) {
        fprintf(stderr, "DFA result for '%s': matched=%s, category=%s, length=%zu\n",
                cmd, result.matched ? "yes" : "no",
                dfa_category_string(result.category),
                result.matched_length);
    }
}
