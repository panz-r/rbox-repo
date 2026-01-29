#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_STATES 16384
#define MAX_SYMBOLS 256
#define MAX_TAGS 16

// From nfa.h
typedef struct {
    uint8_t category_mask;
    char* tags[MAX_TAGS];
    int tag_count;
    int transitions[MAX_SYMBOLS];
    int transition_count;
} nfa_state_t;

static nfa_state_t nfa[MAX_STATES];
static int nfa_state_count = 0;

void load_nfa(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open NFA file\n");
        return;
    }
    
    char magic[4];
    fread(magic, 1, 4, f);
    fread(&nfa_state_count, sizeof(int), 1, f);
    
    printf("NFA has %d states\n", nfa_state_count);
    
    // Read states
    for (int i = 0; i < nfa_state_count && i < 500; i++) {
        fread(&nfa[i].category_mask, 1, 1, f);
        fread(&nfa[i].tag_count, sizeof(int), 1, f);
        for (int j = 0; j < MAX_TAGS; j++) {
            short len;
            if (fread(&len, sizeof(short), 1, f) != 1) break;
            if (len > 0) {
                nfa[i].tags[j] = malloc(len + 1);
                fread(nfa[i].tags[j], len, 1, f);
                nfa[i].tags[j][len] = '\0';
            }
        }
        fread(&nfa[i].transition_count, sizeof(int), 1, f);
        for (int j = 0; j < nfa[i].transition_count && j < MAX_SYMBOLS; j++) {
            fread(&nfa[i].transitions[j], sizeof(int), 1, f);
        }
        // Skip multi_targets and negated_transitions for now
        int mt_len;
        fread(&mt_len, sizeof(int), 1, f);
        fseek(f, mt_len, SEEK_CUR);
        int nt_count;
        fread(&nt_count, sizeof(int), 1, f);
        fseek(f, nt_count * (MAX_SYMBOLS + sizeof(int)), SEEK_CUR);
    }
    
    fclose(f);
}

int main() {
    load_nfa("readonlybox.nfa");
    
    // Find states with "git" transitions
    printf("\nSearching for 'g' transitions from state 0:\n");
    for (int t = 0; t < nfa[0].transition_count && t < 20; t++) {
        printf("  symbol %d -> state %d\n", t, nfa[0].transitions[t]);
    }
    
    // Find state with 'g' transition (symbol 3 for a-z, but 'g' is 103)
    // Actually symbol 3 is a-z range (97-122), so 'g' maps to symbol 3
    printf("\nLooking for 'g' (symbol 3) from state 0:\n");
    for (int t = 0; t < nfa[0].transition_count; t++) {
        if (nfa[0].transitions[t] == 3) {  // symbol 3
            printf("  Found symbol 3 at transition index %d\n", t);
        }
    }
    
    return 0;
}
