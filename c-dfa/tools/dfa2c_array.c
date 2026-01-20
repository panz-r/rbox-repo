#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    fseek(in, 0, SEEK_SET);

    uint8_t* data = malloc(size);
    size_t bytes = fread(data, 1, size, in);
    fclose(in);

    if (bytes != (size_t)size) {
        fprintf(stderr, "Read error\n");
        free(data);
        return 1;
    }

    FILE* out = fopen(output_file, "w");
    if (!out) {
        fprintf(stderr, "Cannot create %s\n", output_file);
        free(data);
        return 1;
    }

    fprintf(out, "#include <stddef.h>\n\n");
    fprintf(out, "const unsigned char %s_data[] = {\n", var_name);
    for (size_t i = 0; i < bytes; i++) {
        if (i % 16 == 0) fprintf(out, "    ");
        fprintf(out, "0x%02X", data[i]);
        if (i < bytes - 1) fprintf(out, ",");
        if (i % 16 == 15) fprintf(out, "\n");
    }
    if (bytes % 16 != 0) fprintf(out, "\n");
    fprintf(out, "};\n\n");
    fprintf(out, "const size_t %s_size = %zu;\n", var_name, bytes);

    fclose(out);
    free(data);

    printf("Generated %s (%zu bytes)\n", output_file, bytes);
    return 0;
}
