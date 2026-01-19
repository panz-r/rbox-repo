#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <setjmp.h>

#define MAX_STATES 512
#define MAX_CHARS 128
#define MAX_PATTERNS 256
#define MAX_LINE_LENGTH 1024

typedef struct {
    bool accepting;
    int next_state[MAX_CHARS];
    int transition_count;
} dfa_state_t;

typedef struct {
    char pattern[MAX_LINE_LENGTH];
    int category;
} command_pattern_t;

static dfa_state_t dfa[MAX_STATES];
static command_pattern_t patterns[MAX_PATTERNS];
static int dfa_state_count = 0;
static int pattern_count = 0;

void dfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        dfa[i].accepting = false;
        for (int j = 0; j < MAX_CHARS; j++) {
            dfa[i].next_state[j] = -1;
        }
        dfa[i].transition_count = 0;
    }
    dfa_state_count = 1;
}

int dfa_add_state(bool accepting) {
    if (dfa_state_count >= MAX_STATES) {
        fprintf(stderr, "Error: Maximum states reached\n");
        exit(1);
    }
    int state = dfa_state_count;
    dfa[state].accepting = accepting;
    dfa_state_count++;
    return state;
}

void dfa_add_transition(int from, int to, unsigned char c) {
    if (from < 0 || from >= dfa_state_count || to < 0 || to >= MAX_STATES) return;
    if (c >= MAX_CHARS) return;
    if (dfa[from].next_state[c] < 0) {
        dfa[from].transition_count++;
    }
    dfa[from].next_state[c] = to;
}

void read_spec_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        exit(1);
    }

    char line[MAX_LINE_LENGTH];

    dfa_init();

    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;

        int category = 0;
        char* pattern = line;

        if (line[0] == '[') {
            char* end = strchr(line, ']');
            if (end != NULL) {
                *end = '\0';
                pattern = end + 1;
                while (*pattern == ' ' || *pattern == '\t') pattern++;
                if (strstr(line, "safe") != NULL) category = 0;
                else if (strstr(line, "caution") != NULL) category = 1;
                else if (strstr(line, "modifying") != NULL) category = 2;
                else if (strstr(line, "dangerous") != NULL) category = 3;
                else if (strstr(line, "network") != NULL) category = 4;
                else if (strstr(line, "admin") != NULL) category = 5;
            }
        }

        if (pattern[0] == '\0') continue;

        if (pattern_count < MAX_PATTERNS) {
            strncpy(patterns[pattern_count].pattern, pattern, MAX_LINE_LENGTH - 1);
            patterns[pattern_count].category = category;
            pattern_count++;
        }

        int current_state = 0;
        int pattern_len = strlen(pattern);

        for (int i = 0; i < pattern_len; i++) {
            unsigned char c = (unsigned char)pattern[i];

            if (c == '*') {
                int star_state = dfa_add_state(true);
                dfa_add_transition(current_state, star_state, c);
                dfa_add_transition(star_state, star_state, c);
                current_state = star_state;
            } else {
                if (dfa[current_state].next_state[c] < 0) {
                    int new_state = dfa_add_state(false);
                    dfa_add_transition(current_state, new_state, c);
                    current_state = new_state;
                } else {
                    current_state = dfa[current_state].next_state[c];
                }
            }
        }

        dfa[current_state].accepting = true;
    }

    fclose(file);
    fprintf(stderr, "Read %d patterns from %s\n", pattern_count, filename);
}

void write_binary(const char* filename) {
    FILE* out = fopen(filename, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot create %s\n", filename);
        return;
    }

    uint32_t magic = 0xDFA1DFA1;
    uint16_t version = 1;
    uint16_t state_count = (uint16_t)dfa_state_count;
    uint32_t initial_state = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t);
    uint32_t accepting_mask = 0;

    size_t header_size = sizeof(uint32_t) * 3 + sizeof(uint16_t) * 2;
    size_t state_header_size = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);

    uint32_t* state_offsets = malloc(dfa_state_count * sizeof(uint32_t));
    size_t current_offset = 0;

    for (int i = 0; i < dfa_state_count; i++) {
        state_offsets[i] = current_offset;
        current_offset += dfa[i].transition_count * 5;
    }

    fwrite(&magic, sizeof(magic), 1, out);
    fwrite(&version, sizeof(version), 1, out);
    fwrite(&state_count, sizeof(state_count), 1, out);
    fwrite(&initial_state, sizeof(initial_state), 1, out);
    fwrite(&accepting_mask, sizeof(accepting_mask), 1, out);

    size_t trans_start = header_size + dfa_state_count * state_header_size;

    for (int i = 0; i < dfa_state_count; i++) {
        uint32_t trans_offset = (uint32_t)state_offsets[i];
        uint16_t trans_count = (uint16_t)dfa[i].transition_count;
        uint16_t flags = dfa[i].accepting ? 1 : 0;

        fprintf(stderr, "State %d header: trans_offset=%u trans_count=%u flags=%u\n",
               i, trans_offset, trans_count, flags);
        fwrite(&trans_offset, sizeof(uint32_t), 1, out);
        fwrite(&trans_count, sizeof(uint16_t), 1, out);
        fwrite(&flags, sizeof(uint16_t), 1, out);
    }

    for (int i = 0; i < dfa_state_count; i++) {
        fprintf(stderr, "State %d: transitions_count=%d, accepting=%s\n",
               i, dfa[i].transition_count, dfa[i].accepting ? "YES" : "NO");
        for (int c = 1; c < 127; c++) {
            if (dfa[i].next_state[c] >= 0) {
                fprintf(stderr, "  '%c' (0x%02X) -> state %d\n", c >= 32 ? c : '?', c, dfa[i].next_state[c]);
            }
        }
    }

    fprintf(stderr, "\nWriting transitions to binary...\n");
    for (int i = 0; i < dfa_state_count; i++) {
        for (int c = 1; c < 127; c++) {
            if (dfa[i].next_state[c] >= 0) {
                uint8_t ch = (uint8_t)c;
                uint32_t target_state = dfa[i].next_state[c];
                uint32_t next_state_offset = header_size + target_state * 8;
                unsigned char buf[5] = { ch, (next_state_offset >> 0) & 0xFF, (next_state_offset >> 8) & 0xFF, (next_state_offset >> 16) & 0xFF, (next_state_offset >> 24) & 0xFF };
                fprintf(stderr, "WRITING BYTES: %02x %02x %02x %02x %02x = char='%c' next_state=%u offset=%u\n",
                       buf[0], buf[1], buf[2], buf[3], buf[4],
                       buf[0] >= 32 ? buf[0] : '?', target_state, next_state_offset);
                fwrite(buf, 1, 5, out);
            }
        }
    }

    free(state_offsets);
    fclose(out);
}

void write_c_array(const char* input_filename, const char* output_filename, const char* varname) {
    FILE* in = fopen(input_filename, "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: Cannot open %s\n", input_filename);
        return;
    }

    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    fseek(in, 0, SEEK_SET);

    if (size <= 0) {
        fclose(in);
        return;
    }

    unsigned char* data = malloc(size);
    size_t bytes = fread(data, 1, size, in);
    fclose(in);

    if (bytes != (size_t)size) {
        free(data);
        return;
    }

    FILE* out = fopen(output_filename, "w");
    if (out == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", output_filename);
        free(data);
        return;
    }

    fprintf(out, "#include \"dfa.h\"\n\n");
    fprintf(out, "const unsigned char %s_data[] = {\n", varname);
    for (size_t i = 0; i < bytes; i++) {
        if (i % 16 == 0) fprintf(out, "    ");
        fprintf(out, "0x%02X", data[i]);
        if (i < bytes - 1) fprintf(out, ",");
        if (i % 16 == 15) fprintf(out, "\n");
    }
    if (bytes % 16 != 0) fprintf(out, "\n");
    fprintf(out, "};\n\n");
    fprintf(out, "const size_t %s_size = %zu;\n", varname, bytes);

    fclose(out);
    free(data);

    printf("Generated %s (%zu bytes)\n", output_filename, bytes);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <spec_file> <output_dfa> <var_name> [c_output_file]\n", argv[0]);
        return 1;
    }

    const char* spec_file = argv[1];
    const char* output_file = argv[2];
    const char* var_name = argv[3];

    printf("DFA Generator (Trie-based)\n============================\n\n");

    read_spec_file(spec_file);

    printf("\nDFA states: %d\n", dfa_state_count);

    printf("\nWriting binary to %s...\n", output_file);
    write_binary(output_file);

    printf("\nGenerating C array...\n");
    char c_array_filename[1024];
    if (argc > 4) {
        snprintf(c_array_filename, sizeof(c_array_filename), "%s", argv[4]);
    } else {
        snprintf(c_array_filename, sizeof(c_array_filename), "%s.c", var_name);
    }
    write_c_array(output_file, c_array_filename, var_name);

    printf("\nDone!\n");
    return 0;
}
