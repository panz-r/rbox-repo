#include "dfa.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "debug.h"

extern const unsigned char rbox_ptrace_dfa[];
extern const size_t rbox_ptrace_dfa_size;

/* Expected DFA identifier - must match pattern file IDENTIFIER */
static const char* EXPECTED_IDENTIFIER = "rbox-ptrace-cmd-v1";

static pthread_once_t dfa_init_once = PTHREAD_ONCE_INIT;
static bool g_dfa_initialized = false;

static void dfa_init_once_wrapper(void) {
    if (!dfa_eval_validate_id(rbox_ptrace_dfa, rbox_ptrace_dfa_size, EXPECTED_IDENTIFIER)) {
        LOG_ERROR("DFA initialization failed: identifier mismatch");
        exit(1);
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
    if (dfa_eval(rbox_ptrace_dfa, rbox_ptrace_dfa_size, cmd, strlen(cmd), &result)) {
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
    if (dfa_eval(rbox_ptrace_dfa, rbox_ptrace_dfa_size, cmd, strlen(cmd), &result)) {
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
        LOG_ERROR("DFA not initialized");
        return;
    }

    dfa_result_t result;
    if (dfa_eval(rbox_ptrace_dfa, rbox_ptrace_dfa_size, cmd, strlen(cmd), &result)) {
        fprintf(stderr, "DFA result for '%s': matched=%s, category_mask=0x%02x, length=%zu\n",
                cmd, result.matched ? "yes" : "no",
                result.category_mask,
                result.matched_length);
    }
}
