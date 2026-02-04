#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define DFA_MAGIC 0xDFA1DFA1

typedef struct __attribute__((packed)) {
    uint32_t transitions_offset;
    uint16_t transition_count;
    uint16_t flags;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
    uint32_t eos_target;
} dfa_state_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t state_count;
    uint32_t initial_state;
    uint32_t accepting_mask;
    uint16_t flags;
    uint8_t identifier_length;
    uint8_t identifier[];
} dfa_t;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dfa_file>\n", argv[0]);
        return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    if (!file) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }

    dfa_t header;
    size_t bytes_read = fread(&header, 1, sizeof(header), file);
    if (bytes_read != sizeof(header)) {
        fprintf(stderr, "Failed to read header\n");
        fclose(file);
        return 1;
    }

    printf("=== DFA Header ===\n");
    printf("Magic: 0x%08X %s\n", header.magic, header.magic == DFA_MAGIC ? "(OK)" : "(BAD)");
    printf("Version: %u\n", header.version);
    printf("State count: %u\n", header.state_count);
    printf("Initial state offset: %u (0x%X)\n", header.initial_state, header.initial_state);
    printf("Accepting mask: 0x%08X\n", header.accepting_mask);
    printf("Flags: 0x%04X\n", header.flags);
    printf("Identifier length: %u\n", header.identifier_length);

    if (header.identifier_length > 0 && header.identifier_length < 256) {
        printf("Identifier: ");
        for (int i = 0; i < header.identifier_length && i < 50; i++) {
            printf("%c", header.identifier[i]);
        }
        printf("\n");
    }

    // Calculate expected header size
    size_t expected_header_size = 19 + header.identifier_length;
    printf("\nExpected header size: %zu bytes\n", expected_header_size);
    printf("sizeof(dfa_t): %zu bytes\n", sizeof(dfa_t));

    // Read identifier from file at correct offset
    if (header.identifier_length > 0) {
        fseek(file, 19, SEEK_SET);
        char identifier[256];
        fread(identifier, 1, header.identifier_length, file);
        identifier[header.identifier_length] = '\0';
        printf("Identifier from file: '%s'\n", identifier);
    }

    // Read initial state at correct offset (offset 8 = after magic(4) + version(2) + state_count(2))
    fseek(file, 8, SEEK_SET);
    uint32_t actual_initial_state;
    fread(&actual_initial_state, 4, 1, file);
    printf("Actual initial_state (from file offset 8): %u (0x%X)\n", actual_initial_state, actual_initial_state);

    // Read initial state
    fseek(file, header.initial_state, SEEK_SET);
    dfa_state_t initial_state;
    fread(&initial_state, 1, sizeof(initial_state), file);

    printf("\n=== Initial State (offset %u) ===\n", header.initial_state);
    printf("Transitions offset: %u\n", initial_state.transitions_offset);
    printf("Transition count: %u\n", initial_state.transition_count);
    printf("Flags: 0x%04X\n", initial_state.flags);
    printf("Capture start ID: %d\n", initial_state.capture_start_id);
    printf("Capture end ID: %d\n", initial_state.capture_end_id);
    printf("Capture defer ID: %d\n", initial_state.capture_defer_id);
    printf("EOS target: %u\n", initial_state.eos_target);

    // Read transitions
    if (initial_state.transitions_offset > 0 && initial_state.transition_count > 0) {
        printf("\n=== First Transitions ===\n");
        fseek(file, initial_state.transitions_offset, SEEK_SET);
        for (int i = 0; i < initial_state.transition_count && i < 10; i++) {
            char c;
            uint32_t next_offset;
            fread(&c, 1, 1, file);
            fread(&next_offset, 4, 1, file);
            unsigned char uc = (unsigned char)c;
            printf("[%d] char='%c' (%d), next_offset=%u (0x%X)\n",
                   i, uc >= 32 && uc < 127 ? uc : '?', uc, next_offset, next_offset);
        }
    }

    fclose(file);
    return 0;
}
