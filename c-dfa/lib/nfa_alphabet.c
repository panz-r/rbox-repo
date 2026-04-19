/**
 * nfa_alphabet.c - Alphabet construction and symbol lookup
 *
 * Handles loading alphabet from file and constructing alphabet
 * from pattern files for NFA builder.
 */

#include "nfa_builder.h"
#include "../include/dfa_errors.h"
#include "../include/cdfa_defines.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void nfa_alphabet_load(nfa_builder_context_t* ctx, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        FATAL_SYS("Cannot open alphabet file '%s'", filename);
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
    ctx->alphabet_size = 0;

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }

        int symbol_id, start_char, end_char;
        char special[16] = "";

        if (sscanf(line, "%d %d %d %15s", &symbol_id, &start_char, &end_char, special) >= 3) {
            if (ctx->alphabet_size >= MAX_SYMBOLS) {
                FATAL("Maximum symbols (%d) reached", MAX_SYMBOLS);
                exit(EXIT_FAILURE);
            }

            ctx->alphabet[ctx->alphabet_size].symbol_id = symbol_id;
            ctx->alphabet[ctx->alphabet_size].start_char = start_char;
            ctx->alphabet[ctx->alphabet_size].end_char = end_char;
            ctx->alphabet[ctx->alphabet_size].is_special = (strcmp(special, "special") == 0);
            ctx->alphabet_size++;
        }
    }

    fclose(file);
    if (ctx->flag_verbose) {
        fprintf(stderr, "Loaded alphabet with %d symbols from %s\n", ctx->alphabet_size, filename);
    }
}

bool nfa_alphabet_construct_from_patterns(nfa_builder_context_t* ctx, ATTR_UNUSED const char* spec_file) {

    // Build alphabet directly in context
    int size = 0;

    // 1. Literal Bytes (0-255)
    for (int i = 0; i < BYTE_VALUE_MAX; i++) {
        ctx->alphabet[size].start_char = i;
        ctx->alphabet[size].end_char = i;
        ctx->alphabet[size].symbol_id = i;
        ctx->alphabet[size].is_special = false;
        size++;
    }
    
    // 2. Virtual Symbols (256+)
    // ANY
    ctx->alphabet[VSYM_BYTE_ANY].start_char = 0;
    ctx->alphabet[VSYM_BYTE_ANY].end_char = 255;
    ctx->alphabet[VSYM_BYTE_ANY].symbol_id = VSYM_BYTE_ANY;
    ctx->alphabet[VSYM_BYTE_ANY].is_special = true;
    size++;

    // EPSILON
    ctx->alphabet[VSYM_EPS].start_char = 1;
    ctx->alphabet[VSYM_EPS].end_char = 1;
    ctx->alphabet[VSYM_EPS].symbol_id = VSYM_EPS;
    ctx->alphabet[VSYM_EPS].is_special = true;
    size++;

    // EOS
    ctx->alphabet[VSYM_EOS].start_char = 5;
    ctx->alphabet[VSYM_EOS].end_char = 5;
    ctx->alphabet[VSYM_EOS].symbol_id = VSYM_EOS;
    ctx->alphabet[VSYM_EOS].is_special = true;
    size++;

    // Normalized SPACE
    ctx->alphabet[VSYM_SPACE].start_char = 32;
    ctx->alphabet[VSYM_SPACE].end_char = 32;
    ctx->alphabet[VSYM_SPACE].symbol_id = VSYM_SPACE;
    ctx->alphabet[VSYM_SPACE].is_special = true;
    size++;

    // Normalized TAB
    ctx->alphabet[VSYM_TAB].start_char = 9;
    ctx->alphabet[VSYM_TAB].end_char = 9;
    ctx->alphabet[VSYM_TAB].symbol_id = VSYM_TAB;
    ctx->alphabet[VSYM_TAB].is_special = true;
    size++;

    ctx->alphabet_size = size;

    if (ctx->flag_verbose) {
        fprintf(stderr, "  Literal symbols: 256\n");
        fprintf(stderr, "  Virtual symbols: %d\n", size - 256);
        fprintf(stderr, "  Total alphabet size: %d\n", size);
        fprintf(stderr, "\nAlphabet constructed successfully\n");
    }

    return true;
}

int nfa_alphabet_find_symbol_id(unsigned char c) {
    return (int)c;
}

int nfa_alphabet_find_special_symbol_id(int special_char) {
    switch (special_char) {
        case DFA_CHAR_ANY:     return VSYM_BYTE_ANY;
        case DFA_CHAR_EPSILON: return VSYM_EPS;
        case DFA_CHAR_EOS:     return VSYM_EOS;
        case 32:               return VSYM_SPACE;
        case 9:                return VSYM_TAB;
        default:               return -1;
    }
}
