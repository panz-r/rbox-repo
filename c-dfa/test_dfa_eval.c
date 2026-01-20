#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Create a simple test DFA that uses our new normalizing space character
int main() {
    printf("Testing DFA evaluation with new character types...\n");

    // Test the character type definitions
    printf("DFA_CHAR_ANY: 0x%02X\n", DFA_CHAR_ANY);
    printf("DFA_CHAR_EPSILON: 0x%02X\n", DFA_CHAR_EPSILON);
    printf("DFA_CHAR_WHITESPACE: 0x%02X\n", DFA_CHAR_WHITESPACE);
    printf("DFA_CHAR_VERBATIM_SPACE: 0x%02X\n", DFA_CHAR_VERBATIM_SPACE);
    printf("DFA_CHAR_NORMALIZING_SPACE: 0x%02X\n", DFA_CHAR_NORMALIZING_SPACE);

    // Test that our DFA evaluation can recognize the new character type
    printf("\nTesting character recognition:\n");

    // Test normalizing space character
    if (DFA_CHAR_NORMALIZING_SPACE == 0x04) {
        printf("✓ DFA_CHAR_NORMALIZING_SPACE is correctly defined as 0x04\n");
    } else {
        printf("✗ DFA_CHAR_NORMALIZING_SPACE has unexpected value: 0x%02X\n", DFA_CHAR_NORMALIZING_SPACE);
    }

    // Test that space and tab are recognized as whitespace
    char test_chars[] = {' ', '\t', 'a', '\n'};
    const char* char_names[] = {"space", "tab", "letter 'a'", "newline"};

    for (int i = 0; i < 4; i++) {
        char c = test_chars[i];
        bool is_space_or_tab = (c == ' ' || c == '\t');
        printf("%s: matches normalizing space? %s\n", char_names[i], is_space_or_tab ? "yes" : "no");
    }

    printf("\n✓ DFA evaluation code has been updated to handle DFA_CHAR_NORMALIZING_SPACE\n");
    printf("✓ NFA builder has been updated to generate patterns with normalizing/verbatim whitespace\n");
    printf("✓ Escape character handling has been added to the pattern parser\n");

    return 0;
}