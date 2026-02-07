#!/bin/bash
# Dump DFA structure for analysis

cd /home/panz/osrc/lms-test/readonlybox/c-dfa

# Create a program to dump DFA details
cat > dump_dfa.c << 'EOF'
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DFA_FORMAT_VERSION 3
#define MAX_CHARS 256

typedef struct {
    uint16_t targets[MAX_CHARS];
    uint16_t eos_target;
    uint16_t flags;  // bits 0-7: category mask, bits 8-15: reserved
} DFAState;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dfa_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("Cannot open %s\n", argv[1]);
        return 1;
    }

    // Read header
    char magic[4];
    uint8_t version;
    uint16_t num_states;
    uint16_t num_symbols;

    fread(magic, 1, 4, f);
    fread(&version, 1, 1, f);
    fread(&num_states, 2, 1, f);
    fread(&num_symbols, 2, 1, f);

    printf("DFA Dump\n");
    printf("========\n");
    printf("Magic: %c%c%c%c\n", magic[0], magic[1], magic[2], magic[3]);
    printf("Version: %d\n", version);
    printf("States: %d\n", num_states);
    printf("Symbols: %d\n", num_symbols);
    printf("\n");

    // Read state table
    uint16_t state_offsets[num_states];
    for (int i = 0; i < num_states; i++) {
        fread(&state_offsets[i], 2, 1, f);
    }

    // Read each state
    for (int i = 0; i < num_states; i++) {
        DFAState state;
        fseek(f, state_offsets[i], SEEK_SET);
        fread(&state, sizeof(DFAState), 1, f);

        uint8_t cat_mask = state.flags & 0xFF;
        int has_eos = state.eos_target != 0xFFFF;

        if (cat_mask != 0 || has_eos) {
            printf("State %d: cat_mask=0x%02X eos_target=%s%d\n",
                   i, cat_mask, has_eos ? "" : "none", has_eos ? state.eos_target : 0);
        }
    }

    fclose(f);
    return 0;
}
EOF

gcc -o dump_dfa dump_dfa.c -Wall
./dump_dfa test_accept.dfa > dfa_dump.txt

# Also run the full debug test
cd /home/panz/osrc/lms-test/readonlybox
./dfa_test --acceptance-test c-dfa/test_accept.dfa 2>&1 | head -100

echo "=== DFA Dump ==="
cat c-dfa/dfa_dump.txt

rm -f c-dfa/dump_dfa c-dfa/dump_dfa.c

#bash