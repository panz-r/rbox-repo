#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"
#include "../include/nfa.h"

/**
 * NFA to DFA Converter (Version 3)
 *
 * Converts alphabet-based NFA to compact character-based DFA format.
 * Output format: Version 3 (no alphabet_map, character-based transitions)
 */

// Character class definition
typedef struct {
    int start_char;
    int end_char;
    int symbol_id;
    bool is_special;
} char_class_t;

// Negated transition structure for NFA
typedef struct {
    int target_state;
    char excluded_chars[MAX_SYMBOLS];
    int excluded_count;
} negated_transition_t;

// NFA State for reading NFA files
typedef struct {
    bool accepting;
    char* tags[MAX_STATES];
    int tag_count;
    int transitions[MAX_SYMBOLS];
    int transition_count;

    // Negated transitions
    negated_transition_t negated_transitions[MAX_SYMBOLS];
    int negated_transition_count;
} nfa_state_t;

// Build-time DFA State
typedef struct {
    uint32_t transitions_offset;
    uint16_t transition_count;
    uint16_t flags;
    bool accepting;
    int transitions[MAX_SYMBOLS];
    int nfa_states[MAX_STATES];
    int nfa_state_count;
} build_dfa_state_t;

// Global variables
static nfa_state_t nfa[MAX_STATES];
static build_dfa_state_t dfa[MAX_STATES];
static char_class_t alphabet[MAX_SYMBOLS];
static int nfa_state_count = 0;
static int dfa_state_count = 0;
static int alphabet_size = 0;

// Initialize NFA
void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].accepting = false;
        nfa[i].tag_count = 0;
        for (int j = 0; j < MAX_STATES; j++) {
            nfa[i].tags[j] = NULL;
        }
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].transitions[j] = -1;
        }
        nfa[i].transition_count = 0;

        nfa[i].negated_transition_count = 0;
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].negated_transitions[j].target_state = -1;
            nfa[i].negated_transitions[j].excluded_count = 0;
        }
    }
    nfa_state_count = 0;
}

// Initialize DFA
void dfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        dfa[i].accepting = false;
        dfa[i].flags = 0;
        dfa[i].transition_count = 0;
        dfa[i].nfa_state_count = 0;
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            dfa[i].transitions[j] = -1;
        }
        for (int j = 0; j < MAX_STATES; j++) {
            dfa[i].nfa_states[j] = -1;
        }
    }
    dfa_state_count = 0;
}

// Add DFA state
int dfa_add_state(bool accepting, int* nfa_states, int nfa_count) {
    if (dfa_state_count >= MAX_STATES) {
        fprintf(stderr, "Error: Maximum DFA states reached\n");
        exit(1);
    }

    int state = dfa_state_count;
    dfa[state].accepting = accepting;
    dfa[state].flags = accepting ? DFA_STATE_ACCEPTING : 0;
    dfa[state].transition_count = 0;
    dfa[state].nfa_state_count = 0;

    for (int i = 0; i < nfa_count && i < MAX_STATES; i++) {
        dfa[state].nfa_states[i] = nfa_states[i];
        dfa[state].nfa_state_count++;
    }

    dfa_state_count++;
    return state;
}

// Compute epsilon closure
void epsilon_closure(int* states, int* count, int max_states) {
    int added = 1;
    while (added && *count < max_states) {
        added = 0;
        for (int i = 0; i < *count; i++) {
            int state = states[i];
            if (state < 0 || state >= nfa_state_count) continue;

            int any_symbol = -1;
            for (int s = 0; s < alphabet_size; s++) {
                if (alphabet[s].start_char == DFA_CHAR_ANY) {
                    any_symbol = s;
                    break;
                }
            }

            if (any_symbol >= 0 && nfa[state].transitions[any_symbol] != -1) {
                int target = nfa[state].transitions[any_symbol];
                bool found = false;
                for (int j = 0; j < *count; j++) {
                    if (states[j] == target) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    states[*count] = target;
                    (*count)++;
                    added = 1;
                }
            }
        }
    }
}

// Move NFA states on symbol
void nfa_move(int* states, int* count, int symbol_id, int max_states) {
    int new_states[MAX_STATES];
    int new_count = 0;

    for (int i = 0; i < *count; i++) {
        int state = states[i];
        if (state < 0 || state >= nfa_state_count) continue;

        if (nfa[state].transitions[symbol_id] != -1) {
            int target = nfa[state].transitions[symbol_id];
            bool found = false;
            for (int j = 0; j < new_count; j++) {
                if (new_states[j] == target) {
                    found = true;
                    break;
                }
            }
            if (!found && new_count < max_states) {
                new_states[new_count] = target;
                new_count++;
            }
        }

        for (int n = 0; n < nfa[state].negated_transition_count; n++) {
            negated_transition_t* neg_trans = &nfa[state].negated_transitions[n];
            bool is_excluded = false;
            for (int e = 0; e < neg_trans->excluded_count; e++) {
                if (neg_trans->excluded_chars[e] == symbol_id) {
                    is_excluded = true;
                    break;
                }
            }
            if (!is_excluded) {
                int target = neg_trans->target_state;
                bool found = false;
                for (int j = 0; j < new_count; j++) {
                    if (new_states[j] == target) {
                        found = true;
                        break;
                    }
                }
                if (!found && new_count < max_states) {
                    new_states[new_count] = target;
                    new_count++;
                }
            }
        }
    }

    for (int i = 0; i < new_count && i < max_states; i++) {
        states[i] = new_states[i];
    }
    *count = new_count;
}

// Convert NFA to DFA
void nfa_to_dfa(void) {
    dfa_init();

    int initial_nfa_states[MAX_STATES];
    initial_nfa_states[0] = 0;
    int initial_count = 1;

    epsilon_closure(initial_nfa_states, &initial_count, MAX_STATES);

    bool accepting = false;
    for (int i = 0; i < initial_count; i++) {
        if (nfa[initial_nfa_states[i]].accepting) {
            accepting = true;
            break;
        }
    }

    int initial_dfa = dfa_add_state(accepting, initial_nfa_states, initial_count);

    int queue[MAX_STATES];
    int queue_start = 0;
    int queue_end = 1;
    queue[0] = initial_dfa;

    while (queue_start < queue_end) {
        int current_dfa = queue[queue_start];
        queue_start++;

        for (int symbol_id = 0; symbol_id < alphabet_size; symbol_id++) {
            int move_states[MAX_STATES];
            int move_count = 0;

            for (int i = 0; i < dfa[current_dfa].nfa_state_count; i++) {
                move_states[i] = dfa[current_dfa].nfa_states[i];
                move_count++;
            }

            nfa_move(move_states, &move_count, symbol_id, MAX_STATES);

            if (move_count == 0) {
                continue;
            }

            epsilon_closure(move_states, &move_count, MAX_STATES);

            bool move_accepting = false;
            for (int i = 0; i < move_count; i++) {
                if (nfa[move_states[i]].accepting) {
                    move_accepting = true;
                    break;
                }
            }

            int existing_state = -1;
            for (int i = 0; i < dfa_state_count; i++) {
                if (dfa[i].nfa_state_count != move_count) {
                    continue;
                }

                bool match = true;
                for (int j = 0; j < move_count; j++) {
                    bool found = false;
                    for (int k = 0; k < dfa[i].nfa_state_count; k++) {
                        if (dfa[i].nfa_states[k] == move_states[j]) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    existing_state = i;
                    break;
                }
            }

            if (existing_state != -1) {
                dfa[current_dfa].transitions[symbol_id] = existing_state;
                dfa[current_dfa].transition_count++;
            } else {
                int new_dfa = dfa_add_state(move_accepting, move_states, move_count);
                dfa[current_dfa].transitions[symbol_id] = new_dfa;
                dfa[current_dfa].transition_count++;

                if (queue_end < MAX_STATES) {
                    queue[queue_end] = new_dfa;
                    queue_end++;
                }
            }
        }
    }
}

// Flatten DFA: convert symbol-based transitions to character-based
void flatten_dfa(void) {
    // Skip symbol 0 if it's DFA_CHAR_ANY (wildcard at character 0)
    // Character 0 is reserved for END MARKER
    int start_symbol = 0;
    if (alphabet_size > 0 && alphabet[0].start_char == 0 && alphabet[0].is_special) {
        start_symbol = 1;  // Skip the ANY symbol
    }

    for (int state = 0; state < dfa_state_count; state++) {
        int new_transitions[MAX_SYMBOLS];
        int new_count = 0;

        for (int i = 0; i < MAX_SYMBOLS; i++) {
            new_transitions[i] = -1;
        }

        for (int s = start_symbol; s < alphabet_size; s++) {
            if (dfa[state].transitions[s] != -1) {
                int target = dfa[state].transitions[s];
                int start_char = alphabet[s].start_char;
                int end_char = alphabet[s].end_char;

                // Skip if start character is 0 (shouldn't happen for non-ANY symbols)
                if (start_char == 0) {
                    continue;
                }

                // Expand character range: create transition for each character in the range
                for (int c = start_char; c <= end_char; c++) {
                    if (c >= 0 && c < MAX_SYMBOLS && new_transitions[c] == -1) {
                        new_transitions[c] = target;
                        new_count++;
                    }
                }
            }
        }

        for (int i = 0; i < MAX_SYMBOLS; i++) {
            dfa[state].transitions[i] = new_transitions[i];
        }
        dfa[state].transition_count = new_count;
    }
}

// Load NFA file
void load_nfa_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        exit(1);
    }

    char first_line[MAX_LINE_LENGTH];
    if (fgets(first_line, sizeof(first_line), file) == NULL) {
        fprintf(stderr, "Error: Empty NFA file\n");
        fclose(file);
        exit(1);
    }

    if (strstr(first_line, "NFA_ALPHABET") == NULL) {
        fprintf(stderr, "Error: Unsupported NFA format. Expected NFA_ALPHABET format.\n");
        fclose(file);
        exit(1);
    }

    rewind(file);

    char line[MAX_LINE_LENGTH];
    char header[64];
    int current_state = -1;

    nfa_init();

    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        if (line[0] == '\0') {
            continue;
        }

        if (sscanf(line, "%63s", header) == 1) {
            if (strcmp(header, "NFA_ALPHABET") == 0) {
                continue;
            } else if (strstr(header, "AlphabetSize:") == header) {
                sscanf(line, "AlphabetSize: %d", &alphabet_size);
            } else if (strstr(header, "States:") == header) {
                sscanf(line, "States: %d", &nfa_state_count);
            } else if (strstr(header, "Initial:") == header) {
                continue;
            } else if (strstr(header, "Alphabet:") == header) {
                current_state = -2;
            } else if (strstr(header, "State") == header) {
                sscanf(line, "State %d:", &current_state);
            } else if (current_state == -2 && strstr(header, "Symbol") == header) {
                int symbol_id, start_char, end_char;
                char special[16] = "";
                if (sscanf(line, "  Symbol %d: %d-%d %15s",
                          &symbol_id, &start_char, &end_char, special) >= 3) {
                    if (symbol_id < MAX_SYMBOLS) {
                        alphabet[symbol_id].symbol_id = symbol_id;
                        alphabet[symbol_id].start_char = (char)start_char;
                        alphabet[symbol_id].end_char = (char)end_char;
                        alphabet[symbol_id].is_special = (strcmp(special, "special") == 0);
                    }
                }
            }
        }

        if (current_state >= 0) {
            if (strstr(line, "Accepting:") != NULL) {
                char accepting_str[16];
                sscanf(line, "  Accepting: %15s", accepting_str);
                nfa[current_state].accepting = (strcmp(accepting_str, "yes") == 0);
            } else if (strstr(line, "Symbol") != NULL) {
                int symbol_id, target_state;
                if (sscanf(line, "    Symbol %d -> %d", &symbol_id, &target_state) == 2) {
                    if (symbol_id < MAX_SYMBOLS && target_state < MAX_STATES) {
                        nfa[current_state].transitions[symbol_id] = target_state;
                        nfa[current_state].transition_count++;
                    }
                }
            } else if (strstr(line, "NotSymbol") != NULL) {
                char excluded_str[MAX_SYMBOLS * 3];
                int target_state;
                if (sscanf(line, "    NotSymbol %255s -> %d", excluded_str, &target_state) == 2) {
                    if (target_state < MAX_STATES && nfa[current_state].negated_transition_count < MAX_SYMBOLS) {
                        negated_transition_t* neg_trans = &nfa[current_state].negated_transitions[
                            nfa[current_state].negated_transition_count++];
                        neg_trans->target_state = target_state;
                        neg_trans->excluded_count = 0;

                        char* token = strtok(excluded_str, ",");
                        while (token != NULL && neg_trans->excluded_count < MAX_SYMBOLS) {
                            int excluded_char = atoi(token);
                            neg_trans->excluded_chars[neg_trans->excluded_count++] = excluded_char;
                            token = strtok(NULL, ",");
                        }
                    }
                }
            }
        }
    }

    fclose(file);
    printf("Loaded NFA with %d states and %d symbols from %s\n", nfa_state_count, alphabet_size, filename);
}

// Write DFA to binary file (Version 3 format)
void write_dfa_file(const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create file %s\n", filename);
        return;
    }

    // Calculate total size needed
    size_t dfa_size = sizeof(dfa_t);
    size_t states_size = dfa_state_count * sizeof(dfa_state_t);

    // Count transitions (each state needs space for its transitions plus end marker)
    size_t total_transitions = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        total_transitions += dfa[i].transition_count + 1;
    }
    size_t transitions_size = total_transitions * sizeof(dfa_transition_t);

    dfa_size += states_size + transitions_size;

    // Allocate memory
    dfa_t* dfa_struct = malloc(dfa_size);
    if (dfa_struct == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return;
    }

    // Initialize DFA header (Version 3)
    dfa_struct->magic = DFA_MAGIC;
    dfa_struct->version = DFA_VERSION;
    dfa_struct->state_count = dfa_state_count;
    dfa_struct->initial_state = sizeof(dfa_t);
    dfa_struct->accepting_mask = 0;
    dfa_struct->flags = 0;
    dfa_struct->reserved = 0;

    // Set up pointers
    dfa_state_t* states = (dfa_state_t*)((char*)dfa_struct + sizeof(dfa_t));
    dfa_transition_t* transitions = (dfa_transition_t*)((char*)states + states_size);

    // Build transition table
    size_t current_transition = 0;
    uint32_t accepting_mask = 0;

    for (int i = 0; i < dfa_state_count; i++) {
        // transitions_offset is offset from start of transitions section
        states[i].transitions_offset = current_transition * sizeof(dfa_transition_t);
        states[i].transition_count = dfa[i].transition_count;
        states[i].flags = dfa[i].flags;

        if (dfa[i].accepting) {
            accepting_mask |= (1 << i);
        }

        // Copy transitions (character-based after flattening)
        for (int c = 0; c < MAX_SYMBOLS; c++) {
            if (dfa[i].transitions[c] != -1) {
                if (current_transition >= total_transitions) {
                    fprintf(stderr, "Error: Transition count mismatch for state %d\n", i);
                    free(dfa_struct);
                    fclose(file);
                    return;
                }

                transitions[current_transition].character = (char)c;
                transitions[current_transition].next_state_offset =
                    sizeof(dfa_t) + (dfa[i].transitions[c] * sizeof(dfa_state_t));
                current_transition++;
            }
        }

        // Add end marker
        if (current_transition >= total_transitions) {
            fprintf(stderr, "Error: Transition count mismatch (end marker)\n");
            free(dfa_struct);
            fclose(file);
            return;
        }
        transitions[current_transition].character = 0;
        transitions[current_transition].next_state_offset = 0;
        current_transition++;
    }

    dfa_struct->accepting_mask = accepting_mask;

    // Write DFA to file
    fwrite(dfa_struct, dfa_size, 1, file);
    fclose(file);

    free(dfa_struct);

    printf("Wrote DFA with %d states to %s\n", dfa_state_count, filename);
    printf("DFA size: %zu bytes\n", dfa_size);
    printf("Compression: %.2f%% of original NFA\n", (dfa_size * 100.0) / (nfa_state_count * MAX_SYMBOLS));
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nfa_file> [dfa_file]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "NFA to DFA Converter (Version 3)\n");
        fprintf(stderr, "Outputs character-based DFA without alphabet_map\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s readonlybox.nfa readonlybox.dfa\n", argv[0]);
        return 1;
    }

    const char* nfa_file = argv[1];
    const char* dfa_file = argc > 2 ? argv[2] : "readonlybox.dfa";

    printf("NFA to DFA Converter (Version 3)\n");
    printf("================================\n\n");

    load_nfa_file(nfa_file);

    printf("Converting NFA to DFA...\n");
    nfa_to_dfa();

    printf("Flattening DFA (symbol -> character)...\n");
    flatten_dfa();

    write_dfa_file(dfa_file);

    printf("\nConversion complete!\n");
    printf("DFA is ready for use in ReadOnlyBox\n");

    return 0;
}
