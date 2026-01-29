#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_STATES 16384
#define MAX_SYMBOLS 256
#define MAX_TAGS 16

typedef struct {
    uint8_t category_mask;
    char* tags[MAX_TAGS];
    int tag_count;
    int transitions[MAX_SYMBOLS];
    int transition_count;
} nfa_state_t;

static nfa_state_t nfa[MAX_STATES];
static int nfa_state_count = 0;

void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].category_mask = 0;
        nfa[i].tag_count = 0;
        for (int j = 0; j < MAX_TAGS; j++) {
            nfa[i].tags[j] = NULL;
        }
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].transitions[j] = -1;
        }
        nfa[i].transition_count = 0;
    }
    nfa_state_count = 1;
}

int find_symbol_id(unsigned char c, int alphabet[][3], int alphabet_size) {
    for (int i = 0; i < alphabet_size; i++) {
        if (c >= alphabet[i][0] && c <= alphabet[i][1]) {
            return alphabet[i][2];
        }
    }
    return -1;
}

void load_nfa(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open NFA file\n");
        return;
    }
    
    // Read header
    char magic[4];
    fread(magic, 1, 4, f);
    fread(&nfa_state_count, sizeof(int), 1, f);
    
    printf("NFA has %d states\n", nfa_state_count);
    
    fclose(f);
}

int main() {
    // Load alphabet
    int alphabet[32][3];
    int alphabet_size = 0;
    
    FILE* f = fopen("tools/alphabet.map", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f) && alphabet_size < 32) {
            if (line[0] == '#') continue;
            int sid, start, end;
            if (sscanf(line, "%d %d %d", &sid, &start, &end) >= 3) {
                alphabet[alphabet_size][0] = start;
                alphabet[alphabet_size][1] = end;
                alphabet[alphabet_size][2] = sid;
                alphabet_size++;
            }
        }
        fclose(f);
    }
    
    // Find which state has the cat transitions
    // First, load NFA
    load_nfa("readonlybox.nfa");
    
    // Print transitions from state 0
    printf("\nTransitions from state 0:\n");
    for (int s = 0; s < 100; s++) {
        int trans_count = 0;
        for (int i = 0; i < MAX_SYMBOLS; i++) {
            if (nfa[s].transitions[i] != -1) trans_count++;
        }
        if (trans_count > 0) {
            printf("State %d: %d transitions\n", s, trans_count);
            for (int i = 0; i < 20 && i < MAX_SYMBOLS; i++) {
                if (nfa[s].transitions[i] != -1) {
                    printf("  char=%d ('%c') -> state %d\n", i, i >= 32 && i < 127 ? i : '?', nfa[s].transitions[i]);
                }
            }
        }
    }
    
    return 0;
}
