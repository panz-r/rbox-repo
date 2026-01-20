#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"

// Forward declarations for minimization functions
static uint64_t compute_state_signature(int state);
static int find_equivalent_state(uint64_t signature, int current_state);
static void add_state_to_signature_table(int state, uint64_t signature);

/**
 * Advanced NFA Builder with Termination Tags
 *
 * This tool builds NFA (Non-deterministic Finite Automata) from advanced
 * command specifications that include:
 * - Command categories (safe, caution, modifying, etc.)
 * - Subcategories (file, text, system, etc.)
 * - Operations (read, write, execute, etc.)
 * - Actions (allow, block, audit, etc.)
 *
 * The NFA is then converted to DFA by nfa2dfa.
 */

#define MAX_STATES 4096
#define MAX_CHARS 256
#define MAX_PATTERNS 2048
#define MAX_LINE_LENGTH 2048
#define MAX_TAGS 16
#define SIGNATURE_TABLE_SIZE 1024

// NFA State with termination tags
typedef struct {
    bool accepting;
    char* tags[MAX_TAGS];          // Termination tags
    int tag_count;
    int transitions[MAX_CHARS];    // -1 = no transition, otherwise state index
    int transition_count;
} nfa_state_t;

// State signature for on-the-fly minimization
typedef struct StateSignature {
    uint64_t signature;
    int state_index;
    struct StateSignature* next; // For hash table collision handling
} StateSignature;

// Command pattern with metadata
typedef struct {
    char pattern[MAX_LINE_LENGTH];
    char category[64];
    char subcategory[64];
    char operations[256];
    char action[32];
    int category_id;
    int subcategory_id;
} command_pattern_t;

// Global variables
static nfa_state_t nfa[MAX_STATES];
static command_pattern_t patterns[MAX_PATTERNS];
static int nfa_state_count = 0;
static int pattern_count = 0;
static StateSignature* signature_table[SIGNATURE_TABLE_SIZE] = {NULL};

// Category IDs
enum {
    CAT_SAFE = 0,
    CAT_CAUTION,
    CAT_MODIFYING,
    CAT_DANGEROUS,
    CAT_NETWORK,
    CAT_ADMIN,
    CAT_BUILD,
    CAT_CONTAINER,
    CAT_COUNT
};

const char* category_names[CAT_COUNT] = {
    "safe", "caution", "modifying", "dangerous",
    "network", "admin", "build", "container"
};

// Initialize NFA
void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].accepting = false;
        nfa[i].tag_count = 0;
        for (int j = 0; j < MAX_TAGS; j++) {
            nfa[i].tags[j] = NULL;
        }
        for (int j = 0; j < MAX_CHARS; j++) {
            nfa[i].transitions[j] = -1;
        }
        nfa[i].transition_count = 0;
    }
    nfa_state_count = 1; // State 0 is initial state
}

// Add NFA state with on-the-fly minimization
int nfa_add_state(bool accepting) {
    if (nfa_state_count >= MAX_STATES) {
        fprintf(stderr, "Error: Maximum NFA states reached\n");
        exit(1);
    }

    int state = nfa_state_count;
    nfa[state].accepting = accepting;
    nfa[state].tag_count = 0;
    for (int j = 0; j < MAX_TAGS; j++) {
        nfa[state].tags[j] = NULL;
    }
    for (int j = 0; j < MAX_CHARS; j++) {
        nfa[state].transitions[j] = -1;
    }
    nfa[state].transition_count = 0;
    nfa_state_count++;

    return state;
}

// Add NFA state with on-the-fly minimization check
int nfa_add_state_with_minimization(bool accepting) {
    // First create the state normally
    int new_state = nfa_add_state(accepting);

    // Compute signature for this state
    uint64_t signature = compute_state_signature(new_state);

    // Check if an equivalent state already exists
    int equivalent_state = find_equivalent_state(signature, new_state);

    if (equivalent_state != -1) {
        // Found equivalent state, revert the new state and return the existing one
        nfa_state_count--; // Revert the state count

        // Clean up the new state
        for (int j = 0; j < nfa[new_state].tag_count; j++) {
            free(nfa[new_state].tags[j]);
            nfa[new_state].tags[j] = NULL;
        }
        nfa[new_state].tag_count = 0;
        nfa[new_state].accepting = false;
        nfa[new_state].transition_count = 0;
        for (int j = 0; j < MAX_CHARS; j++) {
            nfa[new_state].transitions[j] = -1;
        }

        return equivalent_state; // Return the existing equivalent state
    }

    // No equivalent state found, add this state to signature table
    add_state_to_signature_table(new_state, signature);

    return new_state;
}

// Simple string duplication function
static char* my_strdup(const char* str) {
    if (str == NULL) return NULL;
    size_t len = strlen(str) + 1;
    char* copy = malloc(len);
    if (copy) {
        memcpy(copy, str, len);
    }
    return copy;
}

// Hash function for signature table
static unsigned int hash_signature(uint64_t signature) {
    return (unsigned int)(signature % SIGNATURE_TABLE_SIZE);
}

// Compute state signature for equivalence detection
static uint64_t compute_state_signature(int state) {
    uint64_t signature = 0;

    // Include accepting status in signature
    if (nfa[state].accepting) {
        signature |= 0x8000000000000000ULL;
    }

    // Include tags in signature (simple hash of tag strings)
    for (int i = 0; i < nfa[state].tag_count; i++) {
        if (nfa[state].tags[i] != NULL) {
            const char* tag = nfa[state].tags[i];
            while (*tag) {
                signature = signature * 31 + *tag;
                tag++;
            }
        }
    }

    // Include transitions in signature
    for (int c = 0; c < MAX_CHARS; c++) {
        if (nfa[state].transitions[c] != -1) {
            signature = signature * 31 + c;
            signature = signature * 31 + nfa[state].transitions[c];
        }
    }

    return signature;
}

// Find equivalent state using signature
static int find_equivalent_state(uint64_t signature, int current_state) {
    unsigned int hash = hash_signature(signature);
    StateSignature* entry = signature_table[hash];

    while (entry != NULL) {
        if (entry->signature == signature) {
            // Found a state with matching signature, verify it's truly equivalent
            int candidate_state = entry->state_index;

            // Check if states are truly equivalent
            if (nfa[current_state].accepting == nfa[candidate_state].accepting &&
                nfa[current_state].tag_count == nfa[candidate_state].tag_count) {

                // Check tags
                bool tags_match = true;
                for (int i = 0; i < nfa[current_state].tag_count; i++) {
                    if (strcmp(nfa[current_state].tags[i], nfa[candidate_state].tags[i]) != 0) {
                        tags_match = false;
                        break;
                    }
                }

                // Check transitions
                bool transitions_match = true;
                for (int c = 0; c < MAX_CHARS; c++) {
                    if (nfa[current_state].transitions[c] != nfa[candidate_state].transitions[c]) {
                        transitions_match = false;
                        break;
                    }
                }

                if (tags_match && transitions_match) {
                    return candidate_state; // States are equivalent
                }
            }
        }
        entry = entry->next;
    }

    return -1; // No equivalent state found
}

// Add state to signature table
static void add_state_to_signature_table(int state, uint64_t signature) {
    unsigned int hash = hash_signature(signature);

    StateSignature* new_entry = malloc(sizeof(StateSignature));
    if (new_entry == NULL) {
        return; // Memory allocation failed
    }

    new_entry->signature = signature;
    new_entry->state_index = state;
    new_entry->next = signature_table[hash];
    signature_table[hash] = new_entry;
}

// Add tag to state
void nfa_add_tag(int state, const char* tag) {
    if (state < 0 || state >= nfa_state_count) {
        return;
    }

    if (nfa[state].tag_count >= MAX_TAGS) {
        return;
    }

    nfa[state].tags[nfa[state].tag_count] = my_strdup(tag);
    nfa[state].tag_count++;
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

// Parse category ID
int parse_category(const char* name) {
    for (int i = 0; i < CAT_COUNT; i++) {
        if (strcmp(name, category_names[i]) == 0) {
            return i;
        }
    }
    return CAT_SAFE; // Default to safe
}

// Parse advanced pattern
void parse_advanced_pattern(const char* line) {
    // Format: [category:subcategory:operations] pattern -> action

    char category[64] = "safe";
    char subcategory[64] = "";
    char operations[256] = "";
    char action[32] = "allow";
    char pattern[MAX_LINE_LENGTH] = "";

    // Skip leading whitespace
    while (*line == ' ' || *line == '\t') line++;

    // Parse category section
    if (*line == '[') {
        line++;
        char* end = strchr(line, ']');
        if (end != NULL) {
            char category_section[256];
            strncpy(category_section, line, end - line);
            category_section[end - line] = '\0';

            // Parse category:subcategory:operations
            char* tok = strtok(category_section, ":");
            if (tok != NULL) {
                strncpy(category, tok, sizeof(category) - 1);
            }

            tok = strtok(NULL, ":");
            if (tok != NULL) {
                strncpy(subcategory, tok, sizeof(subcategory) - 1);
            }

            tok = strtok(NULL, ":");
            if (tok != NULL) {
                strncpy(operations, tok, sizeof(operations) - 1);
            }

            line = end + 1;
        }
    }

    // Skip whitespace after category
    while (*line == ' ' || *line == '\t') line++;

    // Parse pattern
    char* arrow = strstr(line, "->");
    if (arrow != NULL) {
        strncpy(pattern, line, arrow - line);
        pattern[arrow - line] = '\0';

        // Trim whitespace
        char* end = pattern + strlen(pattern) - 1;
        while (end >= pattern && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        // Parse action
        arrow += 2; // Skip "->"
        while (*arrow == ' ' || *arrow == '\t') arrow++;
        strncpy(action, arrow, sizeof(action) - 1);

        // Trim action
        end = action + strlen(action) - 1;
        while (end >= action && (*end == ' ' || *end == '\t' || *end == '\n')) {
            *end = '\0';
            end--;
        }
    } else {
        // No action specified, use entire line as pattern
        strncpy(pattern, line, sizeof(pattern) - 1);
    }

    // Skip empty patterns
    if (pattern[0] == '\0') {
        return;
    }

    // Store pattern
    if (pattern_count < MAX_PATTERNS) {
        strncpy(patterns[pattern_count].pattern, pattern, MAX_LINE_LENGTH - 1);
        strncpy(patterns[pattern_count].category, category, sizeof(category) - 1);
        strncpy(patterns[pattern_count].subcategory, subcategory, sizeof(subcategory) - 1);
        strncpy(patterns[pattern_count].operations, operations, sizeof(operations) - 1);
        strncpy(patterns[pattern_count].action, action, sizeof(action) - 1);
        patterns[pattern_count].category_id = parse_category(category);
        pattern_count++;
    }

    // Build NFA for this pattern with enhanced whitespace handling
    int current_state = 0;
    int pattern_len = strlen(pattern);
    bool in_quote = false;

    for (int i = 0; i < pattern_len; i++) {
        char c = pattern[i];

        // Handle quoted verbatim sections
        if (c == '\'' && !in_quote) {
            // Start of quoted section - skip the quote character
            in_quote = true;
            continue;
        } else if (c == '\'' && in_quote) {
            // End of quoted section - skip the quote character
            in_quote = false;
            continue;
        }

        // Handle escape sequences
        if (c == '\\' && i + 1 < pattern_len) {
            i++;
            char escaped_char = pattern[i];

            // Handle special escape sequences
            switch (escaped_char) {
                case 't': escaped_char = '\t'; break;
                case 'n': escaped_char = '\n'; break;
                case 'r': escaped_char = '\r'; break;
                case 's': escaped_char = ' '; break;  // space
                case '\'': escaped_char = '\''; break; // single quote
                case '\\': escaped_char = '\\'; break; // backslash
                // Add more escape sequences as needed
            }

            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, escaped_char);
            current_state = new_state;
            continue;
        }

        // Handle whitespace based on quote context
        if (c == ' ' && !in_quote) {
            // Normalizing whitespace - matches any sequence of 1+ space/tab chars
            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, DFA_CHAR_NORMALIZING_SPACE);
            // Add self-loop for additional whitespace characters
            nfa_add_transition(new_state, new_state, DFA_CHAR_NORMALIZING_SPACE);
            current_state = new_state;
        } else if (c == ' ' && in_quote) {
            // Verbatim whitespace - matches exactly one space character
            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, DFA_CHAR_VERBATIM_SPACE);
            current_state = new_state;
        } else if (c == '*') {
            // Wildcard: create epsilon transitions
            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, DFA_CHAR_ANY);
            nfa_add_transition(new_state, new_state, DFA_CHAR_ANY);
            current_state = new_state;
        } else if (c == '?') {
            // Single character wildcard
            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, DFA_CHAR_ANY);
            current_state = new_state;
        } else {
            // Regular character
            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, c);
            current_state = new_state;
        }
    }

    // Mark final state as accepting and add tags
    // First, we need to set the tags and then check for minimization
    nfa[current_state].accepting = true;
    nfa_add_tag(current_state, category);
    if (subcategory[0] != '\0') {
        nfa_add_tag(current_state, subcategory);
    }
    if (operations[0] != '\0') {
        nfa_add_tag(current_state, operations);
    }
    nfa_add_tag(current_state, action);

    // Now check if this accepting state is equivalent to any existing state
    uint64_t signature = compute_state_signature(current_state);
    int equivalent_state = find_equivalent_state(signature, current_state);

    if (equivalent_state != -1) {
        // Merge with existing equivalent state
        current_state = equivalent_state;
    } else {
        // Add to signature table
        add_state_to_signature_table(current_state, signature);
    }
}

// Read advanced command specification file
void read_advanced_spec_file(const char* filename) {
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

        // Parse and add pattern
        parse_advanced_pattern(line);
    }

    fclose(file);

    printf("Read %d patterns from %s\n", pattern_count, filename);
}

// Write NFA to file (for nfa2dfa to process)
void write_nfa_file(const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create file %s\n", filename);
        return;
    }

    // Write header
    fprintf(file, "NFA\n");
    fprintf(file, "States: %d\n", nfa_state_count);
    fprintf(file, "Initial: 0\n\n");

    // Write states
    for (int i = 0; i < nfa_state_count; i++) {
        fprintf(file, "State %d:\n", i);
        fprintf(file, "  Accepting: %s\n", nfa[i].accepting ? "yes" : "no");

        if (nfa[i].tag_count > 0) {
            fprintf(file, "  Tags:");
            for (int j = 0; j < nfa[i].tag_count; j++) {
                fprintf(file, " %s", nfa[i].tags[j]);
            }
            fprintf(file, "\n");
        }

        fprintf(file, "  Transitions: %d\n", nfa[i].transition_count);

        for (int c = 0; c < MAX_CHARS; c++) {
            if (nfa[i].transitions[c] != -1) {
                if (isprint(c)) {
                    fprintf(file, "    '%c' -> %d\n", c, nfa[i].transitions[c]);
                } else if (c == DFA_CHAR_ANY) {
                    fprintf(file, "    ANY -> %d\n", nfa[i].transitions[c]);
                } else {
                    fprintf(file, "    0x%02x -> %d\n", c, nfa[i].transitions[c]);
                }
            }
        }

        fprintf(file, "\n");
    }

    fclose(file);
    printf("Wrote NFA with %d states to %s\n", nfa_state_count, filename);
}

// Cleanup
void cleanup(void) {
    for (int i = 0; i < nfa_state_count; i++) {
        for (int j = 0; j < nfa[i].tag_count; j++) {
            free(nfa[i].tags[j]);
        }
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <spec_file> [output.nfa]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Advanced NFA Builder with Termination Tags\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s commands_advanced.txt readonlybox.nfa\n", argv[0]);
        return 1;
    }

    const char* spec_file = argv[1];
    const char* output_file = argc > 2 ? argv[2] : "readonlybox.nfa";

    printf("Advanced NFA Builder\n");
    printf("====================\n\n");

    // Read specification
    read_advanced_spec_file(spec_file);

    // Write NFA file
    write_nfa_file(output_file);

    // Cleanup
    cleanup();

    printf("\nDone!\n");
    printf("Next step: Run nfa2dfa to convert NFA to DFA\n");
    printf("  nfa2dfa %s readonlybox.dfa\n", output_file);

    return 0;
}