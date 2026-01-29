#include <stdio.h>
#include "include/dfa_types.h"

int main() {
    printf("sizeof(dfa_t) = %zu\n", sizeof(dfa_t));
    printf("sizeof(dfa_state_t) = %zu\n", sizeof(dfa_state_t));
    printf("sizeof(dfa_transition_t) = %zu\n", sizeof(dfa_transition_t));
    printf("sizeof(uint32_t) = %zu\n", sizeof(uint32_t));
    printf("sizeof(uint16_t) = %zu\n", sizeof(uint16_t));
    return 0;
}
