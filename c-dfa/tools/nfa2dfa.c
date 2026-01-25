#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"
#include "../include/nfa.h"

// Forward declaration
int find_symbol_id(char c);

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
    char multi_targets[MAX_SYMBOLS][256];  // For storing additional targets as CSV
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
    bool transitions_from_any[MAX_SYMBOLS];
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
            nfa[i].multi_targets[j][0] = '\0';
        }
        nfa[i].transition_count = 0;
        nfa[i].negated_transition_count = 0;
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
            dfa[i].transitions_from_any[j] = false;
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

        // Check first transition
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

        // Check additional targets in multi_targets
        if (nfa[state].multi_targets[symbol_id][0] != '\0') {
            char* p = nfa[state].multi_targets[symbol_id];
            while (p != NULL && *p != '\0') {
                if (*p == ',') p++;  // Skip leading comma
                int target = atoi(p);
                if (target >= 0 && target < MAX_STATES) {
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
                p = strchr(p, ',');
                if (p) p++;
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
            if (move_count == 0) continue;
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
                if (dfa[i].nfa_state_count != move_count) continue;
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
    int start_symbol = 0;
    if (alphabet_size > 0 && alphabet[0].start_char == 0 && alphabet[0].is_special) {
        start_symbol = 1;
    }
    // Find ANY symbol (special with start_char == 0)
    int any_symbol = -1;
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].is_special && alphabet[s].start_char == 0) {
            any_symbol = s;
            break;
        }
    }
    for (int state = 0; state < dfa_state_count; state++) {
        int new_transitions[MAX_SYMBOLS];
        bool new_from_any[MAX_SYMBOLS];
        int new_count = 0;
        for (int i = 0; i < MAX_SYMBOLS; i++) {
            new_transitions[i] = -1;
            new_from_any[i] = false;
        }
        // FIRST PASS: specific character transitions (higher priority)
        // Skip symbol 0 (ANY) - it's handled in second pass
        for (int s = alphabet_size - 1; s >= start_symbol; s--) {
            if (s == any_symbol) continue;  // Skip ANY in first pass
            if (dfa[state].transitions[s] != -1) {
                int target = dfa[state].transitions[s];
                int start_char = alphabet[s].start_char;
                int end_char = alphabet[s].end_char;
                for (int c = start_char; c <= end_char; c++) {
                    if (c >= 0 && c < MAX_SYMBOLS && new_transitions[c] == -1) {
                        new_transitions[c] = target;
                        new_from_any[c] = false;
                        new_count++;
                    }
                }
            }
        }
        // SECOND PASS: ANY symbol to fill missing characters
        if (any_symbol >= 0 && dfa[state].transitions[any_symbol] != -1) {
            int any_target = dfa[state].transitions[any_symbol];
            for (int c = 0; c < MAX_SYMBOLS; c++) {
                if (new_transitions[c] == -1) {
                    new_transitions[c] = any_target;
                    new_from_any[c] = true;
                    new_count++;
                }
            }
        }
        for (int i = 0; i < MAX_SYMBOLS; i++) {
            dfa[state].transitions[i] = new_transitions[i];
            dfa[state].transitions_from_any[i] = new_from_any[i];
        }
        dfa[state].transition_count = new_count;
    }
}

// Load NFA file
// Find symbol ID for a character
int find_symbol_id(char c) {
    for (int i = 0; i < alphabet_size; i++) {
        if (c >= alphabet[i].start_char && c <= alphabet[i].end_char) {
            return alphabet[i].symbol_id;
        }
    }
    return -1; // Not found
}

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
        if (line[0] == '\0') continue;
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
                if (sscanf(line, "  Symbol %d: %d-%d (%15[^)]",
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
                int symbol_id;
                // Parse format: "Symbol %d -> %d[,%d[,%d...]]" or "Symbol %d -> ,%d[,%d...]"
                char* arrow = strstr(line, "->");
                if (arrow != NULL) {
                    if (sscanf(line, "    Symbol %d", &symbol_id) == 1) {
                        char* targets_str = arrow + 2;
                        // Skip leading whitespace
                        while (*targets_str == ' ') targets_str++;

                        // Parse targets separated by commas
                        char* p = targets_str;
                        int target_count = 0;

                        while (p != NULL && *p != '\0' && *p != '\n') {
                            // Find next comma or end
                            char* comma = strchr(p, ',');
                            size_t len = comma ? (comma - p) : strlen(p);

                            // Skip trailing spaces
                            while (len > 0 && p[len-1] == ' ') len--;

                            if (len > 0) {
                                char target_str[32];
                                strncpy(target_str, p, len);
                                target_str[len] = '\0';

                                int target = atoi(target_str);
                                if (target >= 0 && target < MAX_STATES) {
                                    if (target_count == 0) {
                                        // First target goes in transitions array
                                        nfa[current_state].transitions[symbol_id] = target;
                                        nfa[current_state].transition_count++;
                                    } else {
                                        // Additional targets go to multi_targets
                                        char num_str[32];
                                        sprintf(num_str, ",%d", target);
                                        if (strlen(nfa[current_state].multi_targets[symbol_id]) + strlen(num_str) < 255) {
                                            strcat(nfa[current_state].multi_targets[symbol_id], num_str);
                                            nfa[current_state].transition_count++;
                                        }
                                    }
                                    target_count++;
                                }
                            }

                            if (comma) {
                                p = comma + 1;
                            } else {
                                break;
                            }
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
    size_t header_size = sizeof(dfa_t);
    size_t states_size = dfa_state_count * sizeof(dfa_state_t);
    size_t total_transitions = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        total_transitions += dfa[i].transition_count + 1;
    }
    size_t transitions_size = total_transitions * sizeof(dfa_transition_t);
    size_t dfa_size = header_size + states_size + transitions_size;
    dfa_t* dfa_struct = malloc(dfa_size);
    if (dfa_struct == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return;
    }
    memset(dfa_struct, 0, dfa_size);
    dfa_struct->magic = DFA_MAGIC;
    dfa_struct->version = DFA_VERSION;
    dfa_struct->state_count = dfa_state_count;
    dfa_struct->initial_state = sizeof(dfa_t);
    dfa_struct->accepting_mask = 0;
    dfa_struct->flags = 0;
    dfa_struct->reserved = 0;
    dfa_state_t* states = (dfa_state_t*)((char*)dfa_struct + sizeof(dfa_t));
    dfa_transition_t* transitions = (dfa_transition_t*)((char*)states + states_size);
    size_t current_transition = 0;
    uint32_t accepting_mask = 0;
    // Pre-calculate all transition offsets for each state
    int state_trans_offsets[MAX_STATES];
    for (int i = 0; i < dfa_state_count; i++) {
        state_trans_offsets[i] = current_transition * sizeof(dfa_transition_t);
        current_transition += dfa[i].transition_count + 1; // +1 for end marker
    }
    current_transition = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        states[i].transitions_offset = state_trans_offsets[i];
        states[i].transition_count = dfa[i].transition_count;
        states[i].flags = dfa[i].flags;
        if (dfa[i].accepting) {
            accepting_mask |= (1 << i);
        }
        // FIRST PASS: specific character transitions
        for (int c = 0; c < MAX_SYMBOLS; c++) {
            if (dfa[i].transitions[c] != -1 && !dfa[i].transitions_from_any[c]) {
                if (current_transition >= total_transitions) {
                    fprintf(stderr, "Error: Transition count mismatch for state %d\n", i);
                    free(dfa_struct);
                    fclose(file);
                    return;
                }
                transitions[current_transition].character = (char)c;
                int target_state = dfa[i].transitions[c];
                // next_state_offset is the offset from start of DFA structure to the TARGET STATE's structure
                // which is: sizeof(dfa_t) + (state_index * sizeof(dfa_state_t))
                transitions[current_transition].next_state_offset =
                    sizeof(dfa_t) + (target_state * sizeof(dfa_state_t));
                current_transition++;
            }
        }
        // SECOND PASS: ANY wildcard transitions
        for (int c = 0; c < MAX_SYMBOLS; c++) {
            if (dfa[i].transitions[c] != -1 && dfa[i].transitions_from_any[c]) {
                if (current_transition >= total_transitions) {
                    fprintf(stderr, "Error: Transition count mismatch for state %d\n", i);
                    free(dfa_struct);
                    fclose(file);
                    return;
                }
                transitions[current_transition].character = (char)c;
                int target_state = dfa[i].transitions[c];
                transitions[current_transition].next_state_offset =
                    sizeof(dfa_t) + (target_state * sizeof(dfa_state_t));
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
    fwrite(dfa_struct, dfa_size, 1, file);
    fclose(file);
    free(dfa_struct);
    printf("Wrote DFA with %d states to %s\n", dfa_state_count, filename);
    printf("DFA size: %zu bytes\n", dfa_size);
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nfa_file> [dfa_file]\n", argv[0]);
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
    return 0;
}

