#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t transitions[256];
    uint16_t transition_count;
    uint16_t flags;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
    int8_t eos_target;
} dfa_state_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t state_count;
    uint32_t initial_state;
    uint32_t accepting_mask;
    uint16_t flags;
    uint8_t identifier_length;
    char identifier[256];
} dfa_header_t;

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dfa_file> <input_string>\n", argv[0]);
        return 1;
    }

    const char *dfa_file = argv[1];
    const char *input = argv[2];

    FILE *f = fopen(dfa_file, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open DFA file: %s\n", dfa_file);
        return 1;
    }

    dfa_header_t header;
    fread(&header, sizeof(header), 1, f);

    if (header.magic != 0xDFA1DFA1) {
        fprintf(stderr, "Error: Invalid DFA file (bad magic)\n");
        fclose(f);
        return 1;
    }

    // Read states
    dfa_state_t *states = malloc(header.state_count * sizeof(dfa_state_t));
    for (int i = 0; i < header.state_count; i++) {
        fread(&states[i], sizeof(dfa_state_t), 1, f);
    }
    fclose(f);

    // Evaluate input
    size_t state_offset = header.initial_state;
    size_t header_size = 19 + header.identifier_length;
    size_t state_idx = (state_offset - header_size) / sizeof(dfa_state_t);

    if (state_idx >= header.state_count) {
        printf("NO MATCH\n");
        free(states);
        return 0;
    }

    size_t pos = 0;
    size_t input_len = strlen(input);

    while (pos <= input_len) {
        dfa_state_t *current = &states[state_idx];

        // Check if accepting
        uint8_t category_mask = (current->flags >> 8) & 0xFF;
        if (category_mask != 0 && pos == input_len) {
            printf("MATCH\n");
            free(states);
            return 0;
        }

        if (pos >= input_len) {
            break;
        }

        unsigned char c = input[pos];
        int next_state_offset = current->transitions[c];

        if (next_state_offset == 0) {
            // No transition for this character
            break;
        }

        state_idx = (next_state_offset - header_size) / sizeof(dfa_state_t);
        if (state_idx >= header.state_count) {
            break;
        }
        pos++;
    }

    printf("NO MATCH\n");
    free(states);
    return 0;
}
