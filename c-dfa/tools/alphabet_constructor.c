#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"

/**
 * Alphabet Constructor for NFA/DFA Optimization
 *
 * This tool analyzes command patterns and constructs an optimized alphabet
 * by grouping characters with identical transition behavior. This reduces
 * the DFA state space and improves efficiency.
 */

#define MAX_PATTERNS 2048
#define MAX_LINE_LENGTH 2048
#define MAX_CHARS 256

// Character class definition
typedef struct {
    char start_char;
    char end_char;
    int symbol_id;
    bool is_special; // true for special symbols like ANY, EPSILON, etc.
} char_class_t;

// Global variables
static char_class_t char_classes[MAX_CHARS];
static int char_class_count = 0;
static int symbol_counter = 0;

// Initialize character classes
void init_char_classes(void) {
    for (int i = 0; i < MAX_CHARS; i++) {
        char_classes[i].start_char = 0;
        char_classes[i].end_char = 0;
        char_classes[i].symbol_id = -1;
        char_classes[i].is_special = false;
    }
    char_class_count = 0;
    symbol_counter = 0;
}

// Add a character class
void add_char_class(char start, char end, bool is_special) {
    if (char_class_count >= MAX_CHARS) {
        fprintf(stderr, "Error: Maximum character classes reached\n");
        exit(1);
    }

    char_classes[char_class_count].start_char = start;
    char_classes[char_class_count].end_char = end;
    char_classes[char_class_count].symbol_id = symbol_counter++;
    char_classes[char_class_count].is_special = is_special;
    char_class_count++;
}

// Check if a character is in any existing class
int find_char_class(char c) {
    for (int i = 0; i < char_class_count; i++) {
        if (c >= char_classes[i].start_char && c <= char_classes[i].end_char) {
            return char_classes[i].symbol_id;
        }
    }
    return -1; // Not found
}

// Analyze patterns to identify character classes
void analyze_patterns(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        exit(1);
    }

    char line[MAX_LINE_LENGTH];
    bool char_seen[MAX_CHARS] = {false};

    // First pass: identify all characters used in patterns
    while (fgets(line, sizeof(line), file)) {
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        // Find the pattern part (after category and before ->)
        char* pattern_start = strchr(line, ']');
        if (pattern_start == NULL) {
            pattern_start = line;
        } else {
            pattern_start++;
        }

        char* arrow = strstr(pattern_start, "->");
        if (arrow != NULL) {
            *arrow = '\0'; // Terminate pattern at arrow
        }

        // Trim whitespace
        while (*pattern_start == ' ' || *pattern_start == '\t') pattern_start++;
        char* pattern_end = pattern_start + strlen(pattern_start) - 1;
        while (pattern_end >= pattern_start && (*pattern_end == ' ' || *pattern_end == '\t' || *pattern_end == '\n')) {
            *pattern_end = '\0';
            pattern_end--;
        }

        // Analyze characters in pattern
        for (char* p = pattern_start; *p != '\0'; p++) {
            char c = *p;

            // Skip quotes and escape sequences for now
            if (c == '\'' || c == '\\') {
                p++; // Skip next character too
                continue;
            }

            // Handle wildcards
            if (c == '*' || c == '?') {
                char_seen[DFA_CHAR_ANY] = true;
                continue;
            }

            // Handle space characters
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                char_seen[DFA_CHAR_WHITESPACE] = true;
                continue;
            }

            // Mark regular character as seen
            if (c >= 0 && c < MAX_CHARS) {
                char_seen[(unsigned char)c] = true;
            }
        }
    }

    fclose(file);
}

// Build optimized alphabet based on character usage
void build_optimized_alphabet(void) {
    // Always include special symbols first
    add_char_class(DFA_CHAR_ANY, DFA_CHAR_ANY, true);
    add_char_class(DFA_CHAR_EPSILON, DFA_CHAR_EPSILON, true);
    add_char_class(DFA_CHAR_WHITESPACE, DFA_CHAR_WHITESPACE, true);
    add_char_class(DFA_CHAR_VERBATIM_SPACE, DFA_CHAR_VERBATIM_SPACE, true);
    add_char_class(DFA_CHAR_NORMALIZING_SPACE, DFA_CHAR_NORMALIZING_SPACE, true);

    // Group printable ASCII characters
    // Strategy: group characters that are likely to have similar behavior

    // 1. Alphanumeric characters (most common)
    add_char_class('a', 'z', false);
    add_char_class('A', 'Z', false);
    add_char_class('0', '9', false);

    // 2. Common punctuation and symbols
    add_char_class(' ', ' ', false); // Regular space
    add_char_class('.', '.', false); // Dot (common in commands)
    add_char_class('/', '/', false); // Path separator
    add_char_class('-', '-', false); // Option prefix
    add_char_class('=', '=', false); // Assignment
    add_char_class('_', '_', false); // Underscore

    // 3. Less common symbols (group together)
    add_char_class('!', '/', false); // Excluding already handled chars
    add_char_class(':', '@', false);
    add_char_class('[', '`', false);
    add_char_class('{', '~', false);

    // 4. Control characters (group together)
    add_char_class(0, 31, false); // Control chars
    add_char_class(127, 127, false); // DEL
}

// Write alphabet mapping to file
void write_alphabet_file(const char* filename) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create file %s\n", filename);
        return;
    }

    fprintf(file, "# Alphabet Mapping for ReadOnlyBox DFA\n");
    fprintf(file, "# Generated by alphabet_constructor\n");
    fprintf(file, "# Format: symbol_id start_char end_char [special]\n");
    fprintf(file, "\n");

    for (int i = 0; i < char_class_count; i++) {
        fprintf(file, "%d %d %d",
                char_classes[i].symbol_id,
                (int)char_classes[i].start_char,
                (int)char_classes[i].end_char);

        if (char_classes[i].is_special) {
            fprintf(file, " special");
        }

        // Add descriptive name for special characters
        if (char_classes[i].start_char == char_classes[i].end_char) {
            if (char_classes[i].start_char == DFA_CHAR_ANY) {
                fprintf(file, " # ANY");
            } else if (char_classes[i].start_char == DFA_CHAR_EPSILON) {
                fprintf(file, " # EPSILON");
            } else if (char_classes[i].start_char == DFA_CHAR_WHITESPACE) {
                fprintf(file, " # WHITESPACE");
            } else if (char_classes[i].start_char == DFA_CHAR_VERBATIM_SPACE) {
                fprintf(file, " # VERBATIM_SPACE");
            } else if (char_classes[i].start_char == DFA_CHAR_NORMALIZING_SPACE) {
                fprintf(file, " # NORMALIZING_SPACE");
            } else if (isprint(char_classes[i].start_char)) {
                fprintf(file, " # '%c'", char_classes[i].start_char);
            } else {
                fprintf(file, " # 0x%02x", (int)char_classes[i].start_char);
            }
        } else {
            if (isprint(char_classes[i].start_char) && isprint(char_classes[i].end_char)) {
                fprintf(file, " # '%c'-'%c'", char_classes[i].start_char, char_classes[i].end_char);
            } else {
                fprintf(file, " # 0x%02x-0x%02x", (int)char_classes[i].start_char, (int)char_classes[i].end_char);
            }
        }

        fprintf(file, "\n");
    }

    fprintf(file, "\n# Total symbols: %d\n", symbol_counter);
    fprintf(file, "# Original character space: 256\n");
    fprintf(file, "# Compression ratio: %.2f%%\n", (symbol_counter * 100.0) / 256.0);

    fclose(file);
    printf("Wrote alphabet mapping with %d symbols to %s\n", symbol_counter, filename);
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <patterns_file> [alphabet_file]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Alphabet Constructor for ReadOnlyBox DFA Optimization\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s test_commands.txt alphabet.map\n", argv[0]);
        return 1;
    }

    const char* patterns_file = argv[1];
    const char* alphabet_file = argc > 2 ? argv[2] : "alphabet.map";

    printf("Alphabet Constructor for ReadOnlyBox\n");
    printf("=====================================\n\n");

    // Initialize
    init_char_classes();

    // Analyze patterns
    printf("Analyzing patterns from %s...\n", patterns_file);
    analyze_patterns(patterns_file);

    // Build optimized alphabet
    printf("Building optimized alphabet...\n");
    build_optimized_alphabet();

    // Write alphabet file
    write_alphabet_file(alphabet_file);

    printf("\nAlphabet construction complete!\n");
    printf("Next step: Use this alphabet in NFA construction\n");
    printf("  nfa_builder_with_alphabet %s %s optimized.nfa\n", patterns_file, alphabet_file);

    return 0;
}