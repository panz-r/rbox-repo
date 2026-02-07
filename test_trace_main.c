#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa.h"
#include "dfa_types.h"

void trace_evaluate(const char* input) {
    const dfa_t* dfa = dfa_get_current();
    size_t raw_base = (size_t)dfa;
    
    size_t initial_state_offset = dfa->initial_state;
    const dfa_state_t* current_state = (const dfa_state_t*)((const char*)dfa + initial_state_offset);
    
    size_t length = strlen(input);
    size_t pos = 0;
    
    printf("Tracing: '%s'\n", input);
    printf("Initial state offset: %zu\n", initial_state_offset);
    
    for (pos = 0; pos < length; pos++) {
        unsigned char c = (unsigned char)input[pos];
        size_t current_offset = (size_t)current_state - raw_base;
        
        printf("  Pos %zu: char '%c' (0x%02x), state offset %zu, trans=%u\n",
               pos, c, c, current_offset, current_state->transition_count);
        
        if (current_state->transition_count > 0) {
            size_t trans_offset = current_state->transitions_offset;
            const dfa_transition_t* trans = (const dfa_transition_t*)((const char*)raw_base + trans_offset);
            
            // Find matching transition
            bool found = false;
            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                if (trans[i].character == DFA_CHAR_ANY || (unsigned char)trans[i].character == c) {
                    current_state = (const dfa_state_t*)((const char*)raw_base + trans[i].next_state_offset);
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                printf("  No transition found for '%c'\n", c);
                break;
            }
        } else {
            printf("  No transitions from this state\n");
            break;
        }
    }
    
    size_t final_offset = (size_t)current_state - raw_base;
    uint8_t category = DFA_GET_CATEGORY_MASK(current_state->flags);
    printf("Final: matched %zu chars, category 0x%02x\n\n", pos, category);
}

int main() {
    FILE* f = fopen("readonlybox.dfa", "rb");
    if (!f) { printf("Failed to open DFA\n"); return 1; }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    if (!dfa_init(data, size)) {
        printf("Failed to init DFA\n");
        return 1;
    }
    
    trace_evaluate("git log -n 5");
    trace_evaluate("ls -la");
    trace_evaluate("cat file.txt");
    
    free(data);
    return 0;
}
