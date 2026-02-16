/**
 * SAT Minimization Stub - Used when CaDiCaL is not available
 */

#include <stdio.h>
#include "../include/dfa_types.h"
#include "dfa_minimize.h"

int dfa_minimize_sat(build_dfa_state_t* dfa, int state_count) {
    fprintf(stderr, "Note: SAT minimization not available, using Hopcroft\n");
    return dfa_minimize_hopcroft(dfa, state_count);
}