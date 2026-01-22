#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t state_count;
    uint32_t initial_state;
    uint32_t accepting_mask;
    uint16_t alphabet_size;
    uint16_t reserved;
} dfa_header_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t state_count;
    uint32_t initial_state;
    uint32_t accepting_mask;
    uint16_t alphabet_size;
    uint16_t reserved;
    void* states;  // not flexible array for size test
} dfa_t;

int main() {
    printf("sizeof(dfa_header_t) = %zu\n", sizeof(dfa_header_t));
    printf("sizeof(dfa_t) = %zu\n", sizeof(dfa_t));
    printf("sizeof(dfa_state_t) = %zu\n", sizeof(void*));
    return 0;
}
