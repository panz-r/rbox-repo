/**
 * nfa2dfa.h - Library API for NFA-to-DFA conversion
 *
 * Declares functions from nfa2dfa.c that are exposed when building
 * the library (compiled with NFA2DFA_BUILDING_LIB).
 */

#ifndef NFA2DFA_LIB_H
#define NFA2DFA_LIB_H

#include "../tools/nfa2dfa_context.h"

#ifdef __cplusplus
extern "C" {
#endif

void init_hash_table(nfa2dfa_context_t* ctx);
void load_nfa_file(nfa2dfa_context_t* ctx, const char* filename);
void nfa_to_dfa(nfa2dfa_context_t* ctx);
void flatten_dfa(nfa2dfa_context_t* ctx);
void write_dfa_file(nfa2dfa_context_t* ctx, const char* filename);

#ifdef __cplusplus
}
#endif

#endif // NFA2DFA_LIB_H
