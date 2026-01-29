#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>

// Load DFA from file
void* load_dfa_from_file(const char* filename, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(file);
        return NULL;
    }

    // Allocate memory
    void* data = malloc(file_size);
    if (data == NULL) {
        fclose(file);
        return NULL;
    }

    // Read file
    size_t bytes_read = fread(data, 1, file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        free(data);
        return NULL;
    }

    if (size != NULL) {
        *size = bytes_read;
    }

    return data;
}

// Save DFA to file
bool save_dfa_to_file(const char* filename, const void* data, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        return false;
    }

    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);

    return bytes_written == size;
}