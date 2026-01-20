#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"

/**
 * NFA to DFA Converter with Alphabet Support
 *
 * This tool reads alphabet-based NFA files and converts them to compact DFA binary format.
 */

#define MAX_STATES 4096
#define MAX_SYMBOLS 64
#define MAX_LINE_LENGTH 2048

// Character class definition
typedef struct {
    char start_char;
    char end_char;
    int symbol_id;
    bool is_special;
} char_class_t;

// Build-time DFA State
typedef struct {
    uint32_t transitions_offset;  // Offset to transition table (runtime format)
    uint16_t transition_count;    // Number of transitions
    uint16_t flags;               // State flags (accepting, error, etc.)
    bool accepting;               // Build-time accepting flag
    int transitions[MAX_SYMBOLS]; // -1 = no transition, otherwise state index
    int nfa_states[MAX_STATES];   // Set of NFA states
    int nfa_state_count;
} build_dfa_state_t;

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
    int transitions[MAX_SYMBOLS]; // -1 = no transition, otherwise state index
    int transition_count;
    
    // Negated transitions
    negated_transition_t negated_transitions[MAX_SYMBOLS];
    int negated_transition_count;
} nfa_state_t;

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
        
        // Initialize negated transitions
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

    // Copy NFA states
    for (int i = 0; i < nfa_count && i < MAX_STATES; i++) {
        dfa[state].nfa_states[i] = nfa_states[i];
        dfa[state].nfa_state_count++;
    }

    dfa_state_count++;
    return state;
}

// Compute epsilon closure for NFA states
void epsilon_closure(int* states, int* count, int max_states) {
    // Simple implementation - in a real system, this would be more sophisticated
    // For now, we'll just use the states as-is
}

// Move NFA states on symbol
void nfa_move(int* states, int* count, int symbol_id, int max_states) {
    int new_states[MAX_STATES];
    int new_count = 0;

    for (int i = 0; i < *count; i++) {
        int state = states[i];
        if (state < 0 || state >= nfa_state_count) continue;

        // Check direct transition
        if (nfa[state].transitions[symbol_id] != -1) {
            int target = nfa[state].transitions[symbol_id];

            // Check if already in new_states
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

        // Check wildcard transition (ANY)
        if (symbol_id == DFA_CHAR_ANY) {
            for (int s = 0; s < alphabet_size; s++) {
                if (nfa[state].transitions[s] != -1) {
                    int target = nfa[state].transitions[s];

                    // Check if already in new_states
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
        
        // Check negated transitions
        for (int n = 0; n < nfa[state].negated_transition_count; n++) {
            negated_transition_t* neg_trans = &nfa[state].negated_transitions[n];
            
            // Check if this symbol is NOT in the excluded list
            bool is_excluded = false;
            for (int e = 0; e < neg_trans->excluded_count; e++) {
                if (neg_trans->excluded_chars[e] == symbol_id) {
                    is_excluded = true;
                    break;
                }
            }
            
            if (!is_excluded) {
                int target = neg_trans->target_state;
                
                // Check if already in new_states
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

    // Copy back
    for (int i = 0; i < new_count && i < max_states; i++) {
        states[i] = new_states[i];
    }
    *count = new_count;
}

// Convert NFA to DFA using subset construction with alphabet
void nfa_to_dfa(void) {
    dfa_init();

    // Initial DFA state: epsilon closure of NFA initial state
    int initial_nfa_states[MAX_STATES];
    initial_nfa_states[0] = 0;
    int initial_count = 1;

    epsilon_closure(initial_nfa_states, &initial_count, MAX_STATES);

    // Check if any NFA state is accepting
    bool accepting = false;
    for (int i = 0; i < initial_count; i++) {
        if (nfa[initial_nfa_states[i]].accepting) {
            accepting = true;
            break;
        }
    }

    // Add initial DFA state
    int initial_dfa = dfa_add_state(accepting, initial_nfa_states, initial_count);

    // Queue for unprocessed DFA states
    int queue[MAX_STATES];
    int queue_start = 0;
    int queue_end = 1;
    queue[0] = initial_dfa;

    // Process queue
    while (queue_start < queue_end) {
        int current_dfa = queue[queue_start];
        queue_start++;

        printf("Processing DFA state %d (contains %d NFA states)\n", current_dfa, dfa[current_dfa].nfa_state_count);

        // Try each symbol in the alphabet
        for (int symbol_id = 0; symbol_id < alphabet_size; symbol_id++) {
            // Compute move on this symbol
            int move_states[MAX_STATES];
            int move_count = 0;

            // Copy current NFA states
            for (int i = 0; i < dfa[current_dfa].nfa_state_count; i++) {
                move_states[i] = dfa[current_dfa].nfa_states[i];
                move_count++;
            }

            // Apply move
            nfa_move(move_states, &move_count, symbol_id, MAX_STATES);

            if (move_count == 0) {
                continue; // No transition for this symbol
            }

            // Compute epsilon closure
            epsilon_closure(move_states, &move_count, MAX_STATES);

            // Check if any NFA state is accepting
    bool move_accepting = false;
    for (int i = 0; i < move_count; i++) {
        if (nfa[move_states[i]].accepting) {
            move_accepting = true;
            printf("    Found accepting NFA state %d\n", move_states[i]);
            break;
        }
    }

            // Check if this set of NFA states already exists as a DFA state
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
                // Reuse existing DFA state
                dfa[current_dfa].transitions[symbol_id] = existing_state;
                dfa[current_dfa].transition_count++;
                printf("  Symbol %d -> existing state %d\n", symbol_id, existing_state);
            } else {
                // Create new DFA state
                int new_dfa = dfa_add_state(move_accepting, move_states, move_count);
                dfa[current_dfa].transitions[symbol_id] = new_dfa;
                dfa[current_dfa].transition_count++;
                printf("  Symbol %d -> new state %d (accepting: %s)\n", symbol_id, new_dfa, move_accepting ? "yes" : "no");

                // Add to queue for processing
                if (queue_end < MAX_STATES) {
                    queue[queue_end] = new_dfa;
                    queue_end++;
                }
            }
        }
    }
}

// Load alphabet-based NFA file
void load_nfa_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        exit(1);
    }

    // Check file format - first line should indicate NFA_ALPHABET format
    char first_line[MAX_LINE_LENGTH];
    if (fgets(first_line, sizeof(first_line), file) == NULL) {
        fprintf(stderr, "Error: Empty NFA file\n");
        fclose(file);
        exit(1);
    }
    
    // Only support NFA_ALPHABET format
    if (strstr(first_line, "NFA_ALPHABET") == NULL) {
        fprintf(stderr, "Error: Unsupported NFA format. Expected NFA_ALPHABET format.\n");
        fprintf(stderr, "This tool only works with alphabet-based NFAs generated by nfa_builder_with_alphabet.\n");
        fclose(file);
        exit(1);
    }
    
    // Reset file pointer to beginning
    rewind(file);

    char line[MAX_LINE_LENGTH];
    char header[64];
    int current_state = -1;

    nfa_init();

    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        // Skip empty lines
        if (line[0] == '\0') {
            continue;
        }

        // Parse header
        if (sscanf(line, "%63s", header) == 1) {
            if (strcmp(header, "NFA_ALPHABET") == 0) {
                // This is our format
                continue;
            } else if (strstr(header, "AlphabetSize:") == header) {
                sscanf(line, "AlphabetSize: %d", &alphabet_size);
            } else if (strstr(header, "States:") == header) {
                sscanf(line, "States: %d", &nfa_state_count);
            } else if (strstr(header, "Initial:") == header) {
                // Initial state info
            } else if (strstr(header, "Alphabet:") == header) {
                // Start of alphabet section
                current_state = -2; // Special marker for alphabet section
            } else if (strstr(header, "State") == header) {
                // Start of state definition
                sscanf(line, "State %d:", &current_state);
            } else if (current_state == -2 && strstr(header, "Symbol") == header) {
                // Parse alphabet entry
                int symbol_id, start_char, end_char;
                char special[16] = "";
                if (sscanf(line, "  Symbol %d: %d-%d %15s",
                          &symbol_id, &start_char, &end_char, special) >= 3) {
                    // Store alphabet entry
                    if (symbol_id < MAX_SYMBOLS) {
                        alphabet[symbol_id].symbol_id = symbol_id;
                        alphabet[symbol_id].start_char = (char)start_char;
                        alphabet[symbol_id].end_char = (char)end_char;
                        alphabet[symbol_id].is_special = (strcmp(special, "special") == 0);
                    }
                }
            }
        }

        // Parse state properties
        if (current_state >= 0) {
            if (strstr(line, "Accepting:") != NULL) {
                char accepting_str[16];
                sscanf(line, "  Accepting: %15s", accepting_str);
                nfa[current_state].accepting = (strcmp(accepting_str, "yes") == 0);
            } else if (strstr(line, "Tags:") == line) {
                // Parse tags (simplified)
                char* tags = strchr(line, ':');
                if (tags) {
                    tags += 2; // Skip ": "
                    // In a real implementation, we'd parse the tags
                }
            } else if (strstr(line, "Transitions:") == line) {
                // Transition count
            } else if (strstr(line, "Symbol") != NULL) {
                // Parse transition - check for the pattern with spaces
                int symbol_id, target_state;
                if (sscanf(line, "    Symbol %d -> %d", &symbol_id, &target_state) == 2) {
                    if (symbol_id < MAX_SYMBOLS && target_state < MAX_STATES) {
                        nfa[current_state].transitions[symbol_id] = target_state;
                        nfa[current_state].transition_count++;
                    }
                }
            } else if (strstr(line, "NotSymbol") != NULL) {
                // Parse negated transition
                char excluded_str[MAX_SYMBOLS * 3]; // Enough for comma-separated chars
                int target_state;
                if (sscanf(line, "    NotSymbol %255s -> %d", excluded_str, &target_state) == 2) {
                    if (target_state < MAX_STATES && nfa[current_state].negated_transition_count < MAX_SYMBOLS) {
                        negated_transition_t* neg_trans = &nfa[current_state].negated_transitions[
                            nfa[current_state].negated_transition_count++];
                        neg_trans->target_state = target_state;
                        neg_trans->excluded_count = 0;
                        
                        // Parse comma-separated excluded characters
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
    
    // Debug: Count accepting states in NFA
    int accepting_count = 0;
    for (int i = 0; i < nfa_state_count; i++) {
        if (nfa[i].accepting) {
            accepting_count++;
        }
    }
    printf("NFA has %d accepting states\n", accepting_count);
    
    // Debug: Print state 0 transitions
    printf("State 0 transitions:\n");
    for (int s = 0; s < alphabet_size; s++) {
        if (nfa[0].transitions[s] != -1) {
            printf("  Symbol %d -> %d\n", s, nfa[0].transitions[s]);
        }
    }
    printf("State 0 transition count: %d\n", nfa[0].transition_count);
}

// Write DFA to binary file
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
        total_transitions += dfa[i].transition_count + 1; // +1 for end marker
    }
    size_t transitions_size = total_transitions * sizeof(dfa_transition_t);

    // Add space for alphabet mapping (version 2+)
    size_t alphabet_map_size = 256; // Full character mapping (256 bytes)
    dfa_size += alphabet_map_size;
    
    // Store the actual alphabet size from the loaded alphabet
    size_t actual_alphabet_size = alphabet_size;

    dfa_size += states_size + transitions_size;

    // Allocate memory for DFA structure
    dfa_t* dfa_struct = malloc(dfa_size);
    if (dfa_struct == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return;
    }

    // Initialize DFA header
    dfa_struct->magic = DFA_MAGIC;
    dfa_struct->version = DFA_VERSION;
    dfa_struct->state_count = dfa_state_count;
    dfa_struct->initial_state = sizeof(dfa_t) + alphabet_map_size; // Initial state follows header + alphabet
    dfa_struct->accepting_mask = 0; // Will be computed below
    dfa_struct->alphabet_size = actual_alphabet_size; // Store actual alphabet entries
    dfa_struct->reserved = 0;

    // Set up pointers
    char* alphabet_map = (char*)dfa_struct + sizeof(dfa_t);
    dfa_state_t* states = (dfa_state_t*)((char*)alphabet_map + alphabet_map_size);
    dfa_transition_t* transitions = (dfa_transition_t*)((char*)states + states_size);
    
    // Initialize alphabet mapping (identity mapping for now)
    for (int i = 0; i < 256; i++) {
        alphabet_map[i] = i; // Default: character maps to itself
    }
    
    // Apply our specific alphabet mapping
    for (int i = 0; i < alphabet_map_size; i++) {
        if (alphabet[i].symbol_id < 256) {
            // Map all characters in this range to the symbol ID
            for (int c = alphabet[i].start_char; c <= alphabet[i].end_char; c++) {
                if (c < 256) {
                    alphabet_map[c] = alphabet[i].symbol_id;
                }
            }
        }
    }

    // Build transition table
    size_t current_transition = 0;
    uint32_t accepting_mask = 0;

    for (int i = 0; i < dfa_state_count; i++) {
        states[i].transitions_offset = sizeof(dfa_t) + states_size + (current_transition * sizeof(dfa_transition_t));
        states[i].transition_count = dfa[i].transition_count;
        states[i].flags = dfa[i].flags;

        if (dfa[i].accepting) {
            accepting_mask |= (1 << i);
        }

        // Copy transitions
        for (int s = 0; s < MAX_SYMBOLS; s++) {
            if (dfa[i].transitions[s] != -1) {
                // Only count if we have space
                if (current_transition >= total_transitions) {
                    fprintf(stderr, "Error: Transition count mismatch for state %d\n", i);
                    fprintf(stderr, "  Expected: %zu, Got: %d\n", total_transitions, current_transition);
                    free(dfa_struct);
                    fclose(file);
                    return;
                }
                if (current_transition >= total_transitions) {
                    fprintf(stderr, "Error: Transition count mismatch\n");
                    free(dfa_struct);
                    fclose(file);
                    return;
                }

                transitions[current_transition].character = (char)s; // Symbol ID as character
                transitions[current_transition].next_state_offset =
                    sizeof(dfa_t) + (dfa[i].transitions[s] * sizeof(dfa_state_t));
                current_transition++;
            }
        }

        // Add end marker
        if (current_transition >= total_transitions) {
            fprintf(stderr, "Error: Transition count mismatch\n");
            free(dfa_struct);
            fclose(file);
            return;
        }
        transitions[current_transition].character = 0; // End marker
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
        fprintf(stderr, "NFA to DFA Converter with Alphabet Support\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s readonlybox.nfa readonlybox.dfa\n", argv[0]);
        return 1;
    }

    const char* nfa_file = argv[1];
    const char* dfa_file = argc > 2 ? argv[2] : "readonlybox.dfa";

    printf("NFA to DFA Converter with Alphabet Support\n");
    printf("==========================================\n\n");

    // Load NFA file
    load_nfa_file(nfa_file);

    // Convert NFA to DFA
    printf("Converting NFA to DFA...\n");
    nfa_to_dfa();

    // Write DFA file
    write_dfa_file(dfa_file);

    printf("\nConversion complete!\n");
    printf("DFA is ready for use in ReadOnlyBox\n");

    return 0;
}