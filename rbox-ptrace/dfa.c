#include "dfa.h"
#include <stdio.h>
#include <string.h>

#include "debug.h"

extern const unsigned char rbox_ptrace_dfa[];
extern const size_t rbox_ptrace_dfa_size;

/* Expected DFA identifier - must match pattern file IDENTIFIER */
static const char* EXPECTED_IDENTIFIER = "rbox-ptrace-cmd-v1";

int dfa_init(void) {
    if (!dfa_eval_validate_id(rbox_ptrace_dfa, rbox_ptrace_dfa_size, EXPECTED_IDENTIFIER)) {
        fprintf(stderr, "DFA initialization failed: identifier mismatch\n");
        return -1;
    }
    return 0;
}

int dfa_get_category_mask(const char* cmd, uint8_t* out_mask) {
    if (cmd == NULL || cmd[0] == '\0' || out_mask == NULL) {
        if (out_mask) *out_mask = 0;
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

    dfa_result_t result;
    if (dfa_eval(rbox_ptrace_dfa, rbox_ptrace_dfa_size, cmd, strlen(cmd), &result)) {
        fprintf(stderr, "DFA result for '%s': matched=%s, category_mask=0x%02x, length=%zu\n",
                cmd, result.matched ? "yes" : "no",
                result.category_mask,
                result.matched_length);
    }
}
