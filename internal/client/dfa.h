#ifndef READONLYBOX_DFA_H
#define READONLYBOX_DFA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../../c-dfa/include/dfa.h"

#define DFA_STATE_ACCEPTING  0x0001
#define DFA_STATE_ERROR      0x0002
#define DFA_STATE_DEAD       0x0004

int dfa_should_allow(const char* cmd);
void dfa_debug(const char* cmd);

#endif // READONLYBOX_DFA_H
