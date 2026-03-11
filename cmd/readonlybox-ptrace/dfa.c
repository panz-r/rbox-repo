#include "dfa.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

extern const unsigned char readonlybox_dfa_data[];
extern const size_t readonlybox_dfa_data_size;

/* Expected DFA identifier - must match pattern file IDENTIFIER */
static const char* EXPECTED_IDENTIFIER = "ReadOnlyBox Client Safe Commands v1.1";

static pthread_once_t dfa_init_once = PTHREAD_ONCE_INIT;
static bool g_dfa_initialized = false;

static void dfa_init_once_wrapper(void) {
    if (!dfa_init_with_identifier(readonlybox_dfa_data, readonlybox_dfa_data_size, EXPECTED_IDENTIFIER)) {
        fprintf(stderr, "DFA initialization failed: identifier mismatch\n");
        return;
    }
    g_dfa_initialized = true;
}

int dfa_should_allow(const char* cmd) {
    if (cmd == NULL || cmd[0] == '\0') {
        return 0;
    }

    pthread_once(&dfa_init_once, dfa_init_once_wrapper);

    if (!g_dfa_initialized) {
        return 0;
    }

    dfa_result_t result;
    if (dfa_evaluate(cmd, strlen(cmd), &result)) {
        return (result.category_mask & CAT_MASK_AUTOALLOW) && result.matched;
    }
    return 0;
}

int dfa_get_category_mask(const char* cmd, uint8_t* out_mask) {
    if (cmd == NULL || cmd[0] == '\0' || out_mask == NULL) {
        if (out_mask) *out_mask = 0;
        return 0;
    }

    pthread_once(&dfa_init_once, dfa_init_once_wrapper);

    if (!g_dfa_initialized) {
        *out_mask = 0;
        return 0;
    }

    dfa_result_t result;
    if (dfa_evaluate(cmd, strlen(cmd), &result)) {
        *out_mask = result.category_mask;
        return result.matched;
    }
    *out_mask = 0;
    return 0;
}

void dfa_debug(const char* cmd) {
    if (cmd == NULL || cmd[0] == '\0') {
        return;
    }

    pthread_once(&dfa_init_once, dfa_init_once_wrapper);

    if (!g_dfa_initialized) {
        fprintf(stderr, "DFA not initialized\n");
        return;
    }

    dfa_result_t result;
    if (dfa_evaluate(cmd, 0, &result)) {
        fprintf(stderr, "DFA result for '%s': matched=%s, category_mask=0x%02x, length=%zu\n",
                cmd, result.matched ? "yes" : "no",
                result.category_mask,
                result.matched_length);
    }
}
