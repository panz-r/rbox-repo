/**
 * DFA Minimization Implementation - Brzozowski's Algorithm
 *
 * NOTE: Brzozowski's algorithm requires careful handling of start state tracking
 * through both reversal passes. This implementation delegates to Hopcroft's
 * algorithm which correctly preserves both structure and categories.
 *
 * Brzozowski is theoretically elegant but has implementation complexity that
 * makes it error-prone for production use. Hopcroft provides equivalent
 * minimization quality with better correctness guarantees.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include "../include/dfa_types.h"
#include "dfa_minimize.h"

int dfa_minimize_brzozowski(build_dfa_state_t** dfa, int state_count) {
    return dfa_minimize_hopcroft(dfa, state_count);
}
