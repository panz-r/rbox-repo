#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint8_t character;
    uint32_t next_state_offset;
} dfa_transition_t;

int main() {
    printf("sizeof(dfa_transition_t) = %zu\n", sizeof(dfa_transition_t));
    
    // Read binary file
    FILE* f = fopen("/home/panz/osrc/lms-test/readonlybox/c-dfa/readonlybox.dfa", "rb");
    if (!f) return 1;
    
    fseek(f, 1852, SEEK_SET);  // transitions start
    dfa_transition_t trans[2];
    fread(&trans, sizeof(trans), 1, f);
    fclose(f);
    
    printf("Trans[0]: character=%d, next_state_offset=%d\n", trans[0].character, trans[0].next_state_offset);
    printf("Trans[1]: character=%d, next_state_offset=%d\n", trans[1].character, trans[1].next_state_offset);
    
    return 0;
}
