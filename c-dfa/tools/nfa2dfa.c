#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"

/**
 * NFA to DFA Converter
 *
 * This tool reads a command specification file and generates:
 * 1. NFA (Non-deterministic Finite Automata)
 * 2. DFA (Deterministic Finite Automata)
 * 3. Serialized DFA binary
 *
 * The specification file format:
 * - One command pattern per line
 * - Patterns use simple glob syntax
 * - Lines starting with # are comments
 * - Empty lines are ignored
 *
 * Example:
 * cat *.txt
 * grep -r pattern /
 * git log --oneline
 */

#define MAX_STATES 1024
#define MAX_CHARS 256
#define MAX_PATTERNS 512
#define MAX_LINE_LENGTH 1024

// NFA State
typedef struct {
    bool accepting;
    int transitions[MAX_CHARS]; // -1 = no transition, otherwise state index
    int transition_count;
} nfa_state_t;

// DFA State
typedef struct {
    bool accepting;
    int transitions[MAX_CHARS]; // -1 = no transition, otherwise state index
    int transition_count;
    int nfa_states[MAX_STATES]; // Set of NFA states
    int nfa_state_count;
} dfa_state_t;

// Command pattern
typedef struct {
    char pattern[MAX_LINE_LENGTH];
    int category; // 0=safe, 1=caution, 2=modifying, 3=dangerous
} command_pattern_t;

// Global variables
static nfa_state_t nfa[MAX_STATES];
static dfa_state_t dfa[MAX_STATES];
static command_pattern_t patterns[MAX_PATTERNS];
static int nfa_state_count = 0;
static int dfa_state_count = 0;
static int pattern_count = 0;

// Initialize NFA
void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].accepting = false;
        for (int j = 0; j < MAX_CHARS; j++) {
            nfa[i].transitions[j] = -1;
        }
        nfa[i].transition_count = 0;
    }
    nfa_state_count = 1; // State 0 is initial state
}

// Add NFA state
int nfa_add_state(bool accepting) {
    if (nfa_state_count >= MAX_STATES) {
        fprintf(stderr, "Error: Maximum NFA states reached\n");
        exit(1);
    }

    int state = nfa_state_count;
    nfa[state].accepting = accepting;
    for (int j = 0; j < MAX_CHARS; j++) {
        nfa[state].transitions[j] = -1;
    }
    nfa[state].transition_count = 0;
    nfa_state_count++;

    return state;
}

// Add NFA transition
void nfa_add_transition(int from, int to, char c) {
    if (from < 0 || from >= nfa_state_count || to < 0 || to >= nfa_state_count) {
        fprintf(stderr, "Error: Invalid state index\n");
        exit(1);
    }

    if (c < 0 || c >= MAX_CHARS) {
        fprintf(stderr, "Error: Invalid character\n");
        exit(1);
    }

    nfa[from].transitions[c] = to;
    nfa[from].transition_count++;
}

// Parse pattern and build NFA
void parse_pattern(const char* pattern, int category) {
    int current_state = 0;
    int pattern_len = strlen(pattern);

    for (int i = 0; i < pattern_len; i++) {
        char c = pattern[i];

        if (c == '*') {
            // Wildcard: create epsilon transitions
            int new_state = nfa_add_state(false);
            nfa_add_transition(current_state, new_state, DFA_CHAR_ANY);
            nfa_add_transition(new_state, new_state, DFA_CHAR_ANY);
            current_state = new_state;
        } else if (c == '?') {
            // Single character wildcard
            int new_state = nfa_add_state(false);
            nfa_add_transition(current_state, new_state, DFA_CHAR_ANY);
            current_state = new_state;
        } else if (c == '\\') {
            // Escape character
            if (i + 1 < pattern_len) {
                i++;
                int new_state = nfa_add_state(false);
                nfa_add_transition(current_state, new_state, pattern[i]);
                current_state = new_state;
            }
        } else {
            // Regular character
            int new_state = nfa_add_state(false);
            nfa_add_transition(current_state, new_state, c);
            current_state = new_state;
        }
    }

    // Mark final state as accepting
    nfa[current_state].accepting = true;

    // Store pattern
    if (pattern_count < MAX_PATTERNS) {
        strncpy(patterns[pattern_count].pattern, pattern, MAX_LINE_LENGTH - 1);
        patterns[pattern_count].category = category;
        pattern_count++;
    }
}

// Initialize DFA
void dfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        dfa[i].accepting = false;
        for (int j = 0; j < MAX_CHARS; j++) {
            dfa[i].transitions[j] = -1;
        }
        dfa[i].transition_count = 0;
        dfa[i].nfa_state_count = 0;
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
    for (int j = 0; j < MAX_CHARS; j++) {
        dfa[state].transitions[j] = -1;
    }
    dfa[state].transition_count = 0;

    // Copy NFA states
    for (int i = 0; i < nfa_count && i < MAX_STATES; i++) {
        dfa[state].nfa_states[i] = nfa_states[i];
    }
    dfa[state].nfa_state_count = nfa_count < MAX_STATES ? nfa_count : MAX_STATES;

    dfa_state_count++;
    return state;
}

// Compute epsilon closure for NFA states
void epsilon_closure(int* states, int* count, int max_states) {
    // Simple implementation - in a real system, this would be more sophisticated
    // For now, we'll just use the states as-is
}

// Move NFA states on character
void nfa_move(int* states, int* count, char c, int max_states) {
    int new_states[MAX_STATES];
    int new_count = 0;

    for (int i = 0; i < *count; i++) {
        int state = states[i];
        if (state < 0 || state >= nfa_state_count) continue;

        // Check direct transition
        if (nfa[state].transitions[c] != -1) {
            int target = nfa[state].transitions[c];

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
        if (nfa[state].transitions[DFA_CHAR_ANY] != -1) {
            int target = nfa[state].transitions[DFA_CHAR_ANY];

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

    // Copy back
    for (int i = 0; i < new_count && i < max_states; i++) {
        states[i] = new_states[i];
    }
    *count = new_count;
}

// Convert NFA to DFA using subset construction
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

        // Try each possible input character
        for (char c = 0; c < MAX_CHARS; c++) {
            // Compute move on character c
            int moved_states[MAX_STATES];
            int moved_count = dfa[current_dfa].nfa_state_count;

            for (int i = 0; i < moved_count; i++) {
                moved_states[i] = dfa[current_dfa].nfa_states[i];
            }

            nfa_move(moved_states, &moved_count, c, MAX_STATES);
            epsilon_closure(moved_states, &moved_count, MAX_STATES);

            if (moved_count == 0) {
                // No transition
                continue;
            }

            // Check if this set of NFA states already exists in DFA
            int existing_dfa = -1;
            for (int i = 0; i < dfa_state_count; i++) {
                if (dfa[i].nfa_state_count != moved_count) {
                    continue;
                }

                bool match = true;
                for (int j = 0; j < moved_count; j++) {
                    bool found = false;
                    for (int k = 0; k < dfa[i].nfa_state_count; k++) {
                        if (dfa[i].nfa_states[k] == moved_states[j]) {
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
                    existing_dfa = i;
                    break;
                }
            }

            if (existing_dfa != -1) {
                // Reuse existing DFA state
                dfa[current_dfa].transitions[c] = existing_dfa;
                dfa[current_dfa].transition_count++;
            } else {
                // Create new DFA state
                bool new_accepting = false;
                for (int i = 0; i < moved_count; i++) {
                    if (nfa[moved_states[i]].accepting) {
                        new_accepting = true;
                        break;
                    }
                }

                int new_dfa = dfa_add_state(new_accepting, moved_states, moved_count);
                dfa[current_dfa].transitions[c] = new_dfa;
                dfa[current_dfa].transition_count++;

                // Add to queue
                if (queue_end < MAX_STATES) {
                    queue[queue_end] = new_dfa;
                    queue_end++;
                }
            }
        }
    }
}

// Read command specification file
void read_spec_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        exit(1);
    }

    char line[MAX_LINE_LENGTH];
    int line_num = 0;

    nfa_init();

    while (fgets(line, sizeof(line), file)) {
        line_num++;

        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        // Parse category prefix if present
        int category = 0; // Default: safe
        char* pattern = line;

        if (line[0] == '[') {
            // Category specification
            char* end = strchr(line, ']');
            if (end != NULL) {
                *end = '\0';
                pattern = end + 1;

                // Skip whitespace
                while (*pattern == ' ' || *pattern == '\t') {
                    pattern++;
                }

                // Parse category
                if (strstr(line, "safe") != NULL) {
                    category = 0;
                } else if (strstr(line, "caution") != NULL) {
                    category = 1;
                } else if (strstr(line, "modifying") != NULL) {
                    category = 2;
                } else if (strstr(line, "dangerous") != NULL) {
                    category = 3;
                } else if (strstr(line, "network") != NULL) {
                    category = 4;
                } else if (strstr(line, "admin") != NULL) {
                    category = 5;
                }
            }
        }

        // Skip empty patterns
        if (pattern[0] == '\0') {
            continue;
        }

        // Parse and add pattern
        parse_pattern(pattern, category);
    }

    fclose(file);

    printf("Read %d patterns from %s\n", pattern_count, filename);
}

// Write DFA to binary file
void write_dfa_binary(const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create file %s\n", filename);
        exit(1);
    }

    // Calculate total size needed
    size_t states_size = dfa_state_count * sizeof(dfa_state_t);

    // Calculate transition table size
    size_t transitions_size = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        transitions_size += dfa[i].transition_count * sizeof(dfa_transition_t);
    }

    // DFA header
    struct {
        uint32_t magic;
        uint16_t version;
        uint16_t state_count;
        uint32_t initial_state;
        uint32_t accepting_mask;
    } header;

    header.magic = 0xDFA1DFA1; // DFA magic number
    header.version = 1;
    header.state_count = dfa_state_count;
    header.initial_state = sizeof(header); // Initial state follows header
    header.accepting_mask = 0; // To be calculated

    // Write header
    fwrite(&header, sizeof(header), 1, file);

    // Calculate state offsets
    size_t* state_offsets = malloc(dfa_state_count * sizeof(size_t));
    size_t current_offset = sizeof(header);

    for (int i = 0; i < dfa_state_count; i++) {
        state_offsets[i] = current_offset;
        current_offset += sizeof(dfa_state_t);
    }

    // Write states (with corrected offsets)
    for (int i = 0; i < dfa_state_count; i++) {
        dfa_state_t state = dfa[i];

        // Fix transition offsets
        if (state.transition_count > 0) {
            state.transitions_offset = current_offset;

            // Write transitions
            const dfa_transition_t* trans = (const dfa_transition_t*)(
                (const char*)&dfa[i] + sizeof(dfa_state_t));

            fwrite(trans, sizeof(dfa_transition_t), state.transition_count, file);
            current_offset += state.transition_count * sizeof(dfa_transition_t);
        } else {
            state.transitions_offset = 0;
        }

        // Write state
        fwrite(&state, sizeof(dfa_state_t), 1, file);
    }

    fclose(file);
    free(state_offsets);

    printf("Wrote DFA with %d states to %s\n", dfa_state_count, filename);
}

// Write DFA to human-readable file (for debugging)
void write_dfa_text(const char* filename) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create file %s\n", filename);
        return;
    }

    fprintf(file, "DFA States: %d\n", dfa_state_count);
    fprintf(file, "Initial State: 0\n\n");

    for (int i = 0; i < dfa_state_count; i++) {
        fprintf(file, "State %d:\n", i);
        fprintf(file, "  Accepting: %s\n", dfa[i].accepting ? "yes" : "no");
        fprintf(file, "  Transitions: %d\n", dfa[i].transition_count);

        if (dfa[i].transition_count > 0) {
            const dfa_transition_t* trans = (const dfa_transition_t*)(
                (const char*)&dfa[i] + sizeof(dfa_state_t));

            for (int j = 0; j < dfa[i].transition_count; j++) {
                char c = trans[j].character;
                int target = trans[j].next_state_offset / sizeof(dfa_state_t);

                if (c == DFA_CHAR_ANY) {
                    fprintf(file, "    ANY -> %d\n", target);
                } else if (isprint(c)) {
                    fprintf(file, "    '%c' -> %d\n", c, target);
                } else {
                    fprintf(file, "    0x%02x -> %d\n", (unsigned char)c, target);
                }
            }
        }

        fprintf(file, "\n");
    }

    fclose(file);
    printf("Wrote DFA text representation to %s\n", filename);
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <spec_file> [output.dfa]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Converts command specification to DFA binary.\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s commands.txt readonlybox.dfa\n", argv[0]);
        return 1;
    }

    const char* spec_file = argv[1];
    const char* output_file = argc > 2 ? argv[2] : "readonlybox.dfa";

    printf("NFA to DFA Converter\n");
    printf("====================\n\n");

    // Read specification
    read_spec_file(spec_file);

    // Convert NFA to DFA
    printf("Converting NFA to DFA...\n");
    nfa_to_dfa();
    printf("Created DFA with %d states\n\n", dfa_state_count);

    // Write DFA binary
    printf("Writing DFA binary...\n");
    write_dfa_binary(output_file);

    // Write text representation for debugging
    char text_file[1024];
    snprintf(text_file, sizeof(text_file), "%s.txt", output_file);
    write_dfa_text(text_file);

    printf("\nDone!\n");
    return 0;
}