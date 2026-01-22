#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_STATES 4096
#define MAX_SYMBOLS 256
#define MAX_LINE_LENGTH 2048

typedef struct {
    char start_char;
    char end_char;
    int symbol_id;
    int is_special;
} char_class_t;

char_class_t alphabet[MAX_SYMBOLS];
int alphabet_size = 0;

void load_nfa_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file %s\n", filename);
        exit(1);
    }

    char line[MAX_LINE_LENGTH];
    char header[64];
    int current_state = -1;

    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        if (line[0] == '\0') {
            continue;
        }

        if (sscanf(line, "%63s", header) == 1) {
            if (strstr(header, "AlphabetSize:") == header) {
                sscanf(line, "AlphabetSize: %d", &alphabet_size);
            } else if (strstr(header, "Alphabet:") == header) {
                current_state = -2;
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
    }
    fclose(file);
}

int main() {
    load_nfa_file("../readonlybox.nfa");
    
    printf("Alphabet size: %d\n", alphabet_size);
    for (int i = 0; i < alphabet_size; i++) {
        printf("  alphabet[%d].symbol_id = %d\n", i, alphabet[i].symbol_id);
    }
    
    // Check what's at s=0 and s=5
    printf("\nFor s=0: alphabet[0].symbol_id = %d\n", alphabet[0].symbol_id);
    printf("For s=5: alphabet[5].symbol_id = %d\n", alphabet[5].symbol_id);
    
    return 0;
}
