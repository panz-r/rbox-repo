#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define DFA_MAGIC 0xDFA1DFA1

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <input.dfa> <output.c> <var_name>\n", argv[0]);
        return 1;
    }

    const char* input_file = argv[1];
    const char* output_file = argv[2];
    const char* var_name = argv[3];

    FILE* in = fopen(input_file, "rb");
    if (!in) {
        fprintf(stderr, "Cannot open %s\n", input_file);
        return 1;
    }

    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, in) != 1 || magic != DFA_MAGIC) {
        fprintf(stderr, "Invalid DFA file: wrong magic number\n");
        fclose(in);
        return 1;
    }

    uint16_t version;
    fread(&version, sizeof(version), 1, in);

    uint16_t state_count;
    fread(&state_count, sizeof(state_count), 1, in);

    uint32_t initial_state;
    fread(&initial_state, sizeof(initial_state), 1, in);

    uint32_t accepting_mask;
    fread(&accepting_mask, sizeof(accepting_mask), 1, in);

    uint16_t flags;
    fread(&flags, sizeof(flags), 1, in);

    uint8_t id_len = 0;
    char identifier[256] = "";
    size_t header_offset = 24; // 4 + 2 + 2 + 4 + 4 + 2 = 20, dfa_t has reserved but we skip it

    if (version >= 4) {
        fread(&id_len, sizeof(id_len), 1, in);
        if (id_len > 0 && id_len < 255) {
            fread(identifier, 1, id_len, in);
            identifier[id_len] = '\0';
        }
        header_offset = 25 + id_len; // 24 + id_length byte
    }

    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);

    if (header_offset >= (size_t)file_size) {
        fprintf(stderr, "Invalid DFA file: header exceeds file size\n");
        fclose(in);
        return 1;
    }

    fseek(in, header_offset, SEEK_SET);
    long dfa_size = file_size - header_offset;

    void* data = malloc(dfa_size);
    if (!data) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(in);
        return 1;
    }

    size_t bytes = fread(data, 1, dfa_size, in);
    fclose(in);

    if (bytes != (size_t)dfa_size) {
        fprintf(stderr, "Read error\n");
        free(data);
        return 1;
    }

    // Adjust initial_state if needed
    if (initial_state > header_offset) {
        ((uint32_t*)data)[1] = initial_state - id_len;
    }

    FILE* out = fopen(output_file, "w");
    if (!out) {
        fprintf(stderr, "Cannot create %s\n", output_file);
        free(data);
        return 1;
    }

    fprintf(out, "#include <stddef.h>\n\n");

    if (identifier[0]) {
        fprintf(out, "const char* %s_identifier = \"%s\";\n\n", var_name, identifier);
    } else {
        fprintf(out, "const char* %s_identifier = \"(none)\";\n\n", var_name);
    }

    fprintf(out, "const unsigned char %s_data[] = {\n", var_name);
    for (size_t i = 0; i < bytes; i++) {
        if (i % 16 == 0) fprintf(out, "    ");
        fprintf(out, "0x%02X", ((unsigned char*)data)[i]);
        if (i < bytes - 1) fprintf(out, ",");
        if (i % 16 == 15) fprintf(out, "\n");
    }
    if (bytes % 16 != 0) fprintf(out, "\n");
    fprintf(out, "};\n\n");
    fprintf(out, "const size_t %s_size = %zu;\n", var_name, bytes);

    fclose(out);
    free(data);

    if (identifier[0]) {
        printf("Generated %s (%zu bytes, identifier: %s)\n", output_file, bytes, identifier);
    } else {
        printf("Generated %s (%zu bytes)\n", output_file, bytes);
    }
    return 0;
}
