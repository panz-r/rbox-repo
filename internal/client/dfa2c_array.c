#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input.dfa> <output.c> <array_name>\n", argv[0]);
        return 1;
    }

    const char* input_path = argv[1];
    const char* output_path = argv[2];
    const char* array_name = argv[3];

    FILE* input = fopen(input_path, "rb");
    if (!input) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_path);
        return 1;
    }

    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    fseek(input, 0, SEEK_SET);

    if (file_size < 0) {
        fprintf(stderr, "Error: Cannot determine file size\n");
        fclose(input);
        return 1;
    }

    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if (!buffer) {
        fprintf(stderr, "Error: Cannot allocate memory\n");
        fclose(input);
        return 1;
    }

    if (fread(buffer, 1, file_size, input) != (size_t)file_size) {
        fprintf(stderr, "Error: Cannot read file\n");
        free(buffer);
        fclose(input);
        return 1;
    }
    fclose(input);

    FILE* output = fopen(output_path, "w");
    if (!output) {
        fprintf(stderr, "Error: Cannot open output file '%s'\n", output_path);
        free(buffer);
        return 1;
    }

    fprintf(output, "/* Auto-generated from %s */\n", input_path);
    fprintf(output, "/* Do not edit manually */\n\n");
    fprintf(output, "#include <stdint.h>\n");
    fprintf(output, "#include <stddef.h>\n\n");
    fprintf(output, "const size_t %s_size = %ld;\n\n", array_name, file_size);
    fprintf(output, "const uint8_t %s[%ld] = {\n", array_name, file_size);

    for (long i = 0; i < file_size; i++) {
        if (i % 16 == 0) {
            fprintf(output, "    ");
        }
        fprintf(output, "0x%02X", buffer[i]);
        if (i < file_size - 1) {
            fprintf(output, ", ");
        }
        if (i % 16 == 15) {
            fprintf(output, "\n");
        }
    }
    if (file_size % 16 != 0) {
        fprintf(output, "\n");
    }
    fprintf(output, "};\n");

    fclose(output);
    free(buffer);

    printf("Generated %s (%ld bytes)\n", output_path, file_size);
    return 0;
}
