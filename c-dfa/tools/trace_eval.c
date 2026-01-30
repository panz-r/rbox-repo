#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// DFA structures (simplified for testing)
typedef struct {
    uint32_t transitions_offset;
    uint16_t transition_count;
    uint16_t flags;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
    int8_t eos_target;
} dfa_state_t;

typedef struct __attribute__((packed)) {
    char character;
    uint32_t next_state_offset;
} dfa_transition_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t state_count;
    uint32_t initial_state;
    uint32_t accepting_mask;
    uint16_t flags;
    uint16_t reserved;
} dfa_header_t;

#define DFA_GET_CATEGORY_MASK(flags) ((flags) >> 8)
#define DFA_CHAR_ANY 0x00
#define DFA_CHAR_EOS 0x05

typedef struct {
    uint8_t category_mask;
    uint32_t final_state;
    bool matched;
    size_t matched_length;
} dfa_result_t;

void trace_evaluate(const char* dfa_data, const char* input) {
    const dfa_header_t* header = (const dfa_header_t*)dfa_data;
    size_t raw_base = (size_t)dfa_data;
    
    printf("Input: '%s'\n", input);
    printf("DFA states: %d, initial offset: %d\n\n", header->state_count, header->initial_state);
    
    size_t initial_offset = header->initial_state;
    const dfa_state_t* current_state = (const dfa_state_t*)(raw_base + initial_offset);
    
    size_t length = strlen(input);
    size_t pos = 0;
    
    printf("Tracing evaluation:\n");
    printf("Pos | Char | State Offset | flags  | cat_mask | transitions | Action\n");
    printf("----|------|--------------|--------|----------|-------------|-------\n");
    
    for (pos = 0; pos < length; pos++) {
        unsigned char c = (unsigned char)input[pos];
        size_t current_offset = (size_t)current_state - raw_base;
        uint8_t cat_mask = DFA_GET_CATEGORY_MASK(current_state->flags);
        
        printf("%3zu | '%c'  | %08X     | 0x%04X | 0x%02X     | %d           | ",
               pos, c, (unsigned)current_offset, current_state->flags, cat_mask,
               current_state->transition_count);
        
        bool transition_found = false;
        
        if (current_state->transition_count > 0) {
            const dfa_transition_t* trans = (const dfa_transition_t*)(raw_base + current_state->transitions_offset);
            
            for (uint16_t i = 0; i < current_state->transition_count; i++) {
                unsigned char trans_char = (unsigned char)trans[i].character;
                
                if (trans_char == DFA_CHAR_ANY || trans_char == c) {
                    uint32_t next_offset = trans[i].next_state_offset;
                    current_state = (const dfa_state_t*)(raw_base + next_offset);
                    printf("-> next state at offset %08X", next_offset);
                    transition_found = true;
                    break;
                }
            }
        }
        
        if (!transition_found) {
            printf("NO TRANSITION (dead end)");
        }
        printf("\n");
        
        if (!transition_found) {
            printf("\nDEAD END at position %zu\n", pos);
            printf("Final category_mask: 0x%02X\n", DFA_GET_CATEGORY_MASK(current_state->flags));
            return;
        }
    }
    
    // End of input reached
    size_t final_offset = (size_t)current_state - raw_base;
    uint8_t final_cat_mask = DFA_GET_CATEGORY_MASK(current_state->flags);
    
    printf("\nEND OF INPUT reached\n");
    printf("Final state offset: %08X\n", (unsigned)final_offset);
    printf("Final flags: 0x%04X\n", current_state->flags);
    printf("Final category_mask: 0x%02X\n", final_cat_mask);
    printf("EOS target: %d\n", current_state->eos_target);
    
    if (current_state->eos_target >= 0) {
        const dfa_state_t* eos_state = (const dfa_state_t*)(raw_base + 20 + current_state->eos_target * 12);
        printf("EOS state flags: 0x%04X\n", eos_state->flags);
        printf("EOS category_mask: 0x%02X\n", DFA_GET_CATEGORY_MASK(eos_state->flags));
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dfa_file> [input_string]\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *dfa_data = malloc(size);
    fread(dfa_data, 1, size, f);
    fclose(f);
    
    const char *input = (argc > 2) ? argv[2] : "git status";
    trace_evaluate(dfa_data, input);
    
    free(dfa_data);
    return 0;
}
