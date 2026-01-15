#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simple DFA serializer (identity function for now)
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    const char* input_file = argv[1];
    const char* output_file = argv[2];

    // Load input file
    size_t size;
    void* data = load_dfa_from_file(input_file, &size);
    if (data == NULL) {
        printf("Failed to load input file %s\n", input_file);
        return 1;
    }

    // Save to output file
    if (!save_dfa_to_file(output_file, data, size)) {
        printf("Failed to save output file %s\n", output_file);
        free(data);
        return 1;
    }

    printf("Serialized DFA from %s to %s (%zu bytes)\n", input_file, output_file, size);

    free(data);
    return 0;
}