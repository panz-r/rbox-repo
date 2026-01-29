#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_SYMBOLS 256

typedef struct {
    int symbol_id;
    int start_char;
    int end_char;
    bool is_special;
} char_class_t;

static char_class_t alphabet[MAX_SYMBOLS];
static int alphabet_size = 0;

void load_alphabet(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Cannot open alphabet file %s\n", filename);
        exit(1);
    }

    char line[256];
    alphabet_size = 0;

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }

        int symbol_id, start_char, end_char;
        char special[16] = "";

        if (sscanf(line, "%d %d %d %15s", &symbol_id, &start_char, &end_char, special) >= 3) {
            if (alphabet_size >= MAX_SYMBOLS) {
                fprintf(stderr, "Error: Maximum symbols reached\n");
                exit(1);
            }

            alphabet[alphabet_size].symbol_id = symbol_id;
            alphabet[alphabet_size].start_char = start_char;
            alphabet[alphabet_size].end_char = end_char;
            alphabet[alphabet_size].is_special = (strcmp(special, "special") == 0);
            alphabet_size++;
        }
    }

    fclose(file);
    printf("Loaded alphabet with %d symbols\n", alphabet_size);
}

int find_symbol_id(unsigned char c) {
    for (int i = 0; i < alphabet_size; i++) {
        if (c >= alphabet[i].start_char && c <= alphabet[i].end_char) {
            return alphabet[i].symbol_id;
        }
    }
    return -1;
}

int main() {
    load_alphabet("tools/alphabet.map");
    
    printf("\nChecking character class [a-zA-Z0-9_./-]:\n");
    
    // Parse character class manually
    const char* class_str = "[a-zA-Z0-9_./-]";
    const char* p = class_str + 1;  // Skip [
    
    // Collect all chars in the class
    char chars[256];
    int char_count = 0;
    
    while (*p && *p != ']' && char_count < 255) {
        if (*p == '-') {
            // Check if it's a range
            if (char_count > 0 && *(p+1) && *(p+1) != ']' && 
                isalnum((unsigned char)chars[char_count-1]) && 
                isalnum((unsigned char)*(p+1))) {
                // It's a range - add all chars in range
                char start = chars[char_count-1];
                char end = *(p+1);
                chars[char_count-1] = start;  // Keep start
                for (char c = start + 1; c <= end && char_count < 250; c++) {
                    chars[char_count++] = c;
                }
                p += 2;  // Skip - and end char
                continue;
            } else {
                // Literal dash
                chars[char_count++] = '-';
                p++;
                continue;
            }
        }
        chars[char_count++] = *p;
        p++;
    }
    
    printf("Characters in class: ");
    for (int i = 0; i < char_count; i++) {
        printf("%c", chars[i]);
    }
    printf("\n");
    
    printf("\nSymbol IDs for filename chars:\n");
    const char* test_chars = "test.txt";
    for (int i = 0; test_chars[i]; i++) {
        int sid = find_symbol_id(test_chars[i]);
        printf("  '%c' -> symbol %d\n", test_chars[i], sid);
    }
    
    printf("\nMissing symbol IDs in character class:\n");
    bool missing[256] = {false};
    for (int i = 0; i < char_count; i++) {
        int sid = find_symbol_id(chars[i]);
        if (sid == -1) {
            printf("  '%c' (%d) - NO SYMBOL!\n", chars[i], (int)(unsigned char)chars[i]);
        }
    }
    
    return 0;
}
