#include <stdio.h>
#include <stdint.h>
#include "../include/dfa_types.h"

int main() {
    printf("sizeof(dfa_header_t) = %zu\n", sizeof(dfa_header_t));
    printf("sizeof(dfa_t) = %zu\n", sizeof(dfa_t));
    printf("sizeof(dfa_state_t) = %zu\n", sizeof(dfa_state_t));
    printf("sizeof(dfa_transition_t) = %zu\n", sizeof(dfa_transition_t));
    return 0;
}
