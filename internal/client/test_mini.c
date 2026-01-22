#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "dfa.h"

extern const unsigned char mini_data[];
extern const size_t mini_size;

static const dfa_header_t* g_header = NULL;
static const dfa_state_t* g_states = NULL;
static size_t g_trans_start = 0;
static const uint8_t* g_alpha_map = NULL;

int char_to_symbol(unsigned char c) {
    if (g_alpha_map != NULL && c < 256) {
        return g_alpha_map[c];
    }
    return c;
}

int mini_init() {
    if (mini_size < sizeof(dfa_header_t)) return 0;
    g_header = (dfa_header_t*)mini_data;
    if (g_header->magic != DFA_MAGIC) return 0;
    
    g_states = (dfa_state_t*)(mini_data + g_header->initial_state);
    g_alpha_map = (uint8_t*)(mini_data + 32);
    g_trans_start = g_header->initial_state + g_header->state_count * 8;
    
    printf("Init: states=%d, init=%d, alphabet_size=%d, trans_start=%zu\n",
           g_header->state_count, g_header->initial_state, 
           g_header->alphabet_size, g_trans_start);
    printf("Alphabet: 'g'->%d, 'i'->%d, ' '->%d, 'l'->%d\n",
           g_alpha_map[0x67], g_alpha_map[0x69], g_alpha_map[0x20], g_alpha_map[0x6c]);
    
    return 1;
}

int evaluate(const char* input) {
    const dfa_state_t* state = g_states;
    size_t len = strlen(input);
    
    printf("EVAL: '%s' (len=%zu)\n", input, len);
    
    for (size_t pos = 0; pos < len; pos++) {
        unsigned char c = (unsigned char)input[pos];
        int symbol = char_to_symbol(c);
        
        printf("  pos=%zu, char='%c'(0x%02x), symbol=%d, trans_count=%d\n",
               pos, c >= 32 ? c : '?', c, symbol, state->transition_count);
        
        if (state->transition_count == 0) {
            printf("  NO TRANSITIONS, breaking\n");
            return 0;
        }
        
        int found = 0;
        for (int i = 0; i < state->transition_count; i++) {
            uint8_t ch = mini_data[g_trans_start + state->transitions_offset + i * 5];
            uint32_t next = *(uint32_t*)&mini_data[g_trans_start + state->transitions_offset + i * 5 + 1];
            printf("    trans[%d]: char=%d, next=%d\n", i, ch, next);
            if (ch == symbol) {
                state = (dfa_state_t*)(mini_data + next);
                found = 1;
                break;
            }
        }
        
        if (!found) {
            printf("  NO MATCHING TRANSITION\n");
            return 0;
        }
    }
    
    int accepting = (state->flags & DFA_STATE_ACCEPTING) ? 1 : 0;
    printf("  Final state: accepting=%d\n", accepting);
    return accepting;
}

int main() {
    mini_init();
    
    const char* tests[] = {"git log", "ls", "git", "gi", "g"};
    for (int i = 0; i < 5; i++) {
        int result = evaluate(tests[i]);
        printf("RESULT: '%s' -> %s\n\n", tests[i], result ? "ACCEPT" : "REJECT");
    }
    
    return 0;
}
