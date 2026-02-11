#include "../include/dfa_types.h"
#include "../include/dfa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_LINE_LENGTH 1024

// Get identifier from DFA file
const char* get_dfa_identifier(const char* filename) {
    static char identifier[256] = "";
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        return NULL;
    }

    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, file) == 1 && magic == DFA_MAGIC) {
        uint16_t version;
        if (fread(&version, sizeof(version), 1, file) != 1) {
            fclose(file);
            strcpy(identifier, "(none)");
            return identifier;
        }
        
        // Skip to identifier length: magic + version + state_count + initial_state + accepting_mask + flags + reserved
        fseek(file, 4 + 2 + 2 + 4 + 4 + 2 + 2, SEEK_CUR);
        
        uint8_t id_len = 0;
        if (version >= 4) {
            if (fread(&id_len, sizeof(id_len), 1, file) != 1) id_len = 0;
        }

        if (id_len > 0 && id_len < 255) {
            if (fread(identifier, 1, id_len, file) != id_len) id_len = 0;
            identifier[id_len] = '\0';
        } else {
            strcpy(identifier, "(none)");
        }
        fclose(file);
        return identifier;
    }

    // Fall back to text format
    rewind(file);
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "Identifier:", 11) == 0) {
            char* id_start = line + 11;
            while (*id_start == ' ') id_start++;
            id_start[strcspn(id_start, "\r\n")] = '\0';
            strncpy(identifier, id_start, sizeof(identifier) - 1);
            fclose(file);
            return identifier;
        }
    }

    fclose(file);
    strcpy(identifier, "(none)");
    return identifier;
}

// Load DFA from file - returns complete DFA binary including header
void* load_dfa_from_file(const char* filename, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        return NULL;
    }

    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, file) == 1 && magic == DFA_MAGIC) {
        uint16_t version;
        if (fread(&version, sizeof(version), 1, file) != 1) version = 0;

        uint16_t state_count;
        if (fread(&state_count, sizeof(state_count), 1, file) != 1) state_count = 0;

        uint32_t initial_state;
        if (fread(&initial_state, sizeof(initial_state), 1, file) != 1) initial_state = 0;

        uint32_t accepting_mask;
        if (fread(&accepting_mask, sizeof(accepting_mask), 1, file) != 1) accepting_mask = 0;

        uint16_t flags;
        if (fread(&flags, sizeof(flags), 1, file) != 1) flags = 0;

        uint8_t id_len = 0;
        size_t header_size = 19; // dfa_t base (magic through identifier_length)
        if (version >= 4) {
            if (fread(&id_len, sizeof(id_len), 1, file) != 1) id_len = 0;
            header_size = 19 + id_len;
            // Version 6+ has additional metadata_offset field
            if (version >= 6) {
                uint32_t metadata_offset;
                if (fread(&metadata_offset, sizeof(metadata_offset), 1, file) == 1) {
                    header_size = 23 + id_len; // 19 + id_len + 4 for metadata_offset
                }
            }
        }

        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);

        // Complete DFA size is the entire file
        long dfa_size = file_size;

        fseek(file, 0, SEEK_SET);

        void* dfa_data = malloc(dfa_size);
        if (dfa_data == NULL) {
            fclose(file);
            return NULL;
        }

        // Read entire file into buffer
        fprintf(stderr, "LOADING DFA: %s (%ld bytes)\n", filename, dfa_size);
        size_t bytes_read = fread(dfa_data, 1, dfa_size, file);
        fclose(file);

        if (bytes_read != (size_t)dfa_size) {
            free(dfa_data);
            return NULL;
        }

        if (size != NULL) {
            *size = dfa_size;
        }

        return dfa_data;
    }

    // Fall back to text format
    rewind(file);
    char line[MAX_LINE_LENGTH];
    long binary_start = 0;

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "BinaryDataStart", 14) == 0) {
            binary_start = ftell(file);
            break;
        }
    }

    if (binary_start == 0) {
        fclose(file);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    long binary_size = file_size - binary_start;

    fseek(file, binary_start, SEEK_SET);
    void* data = malloc(binary_size);
    size_t bytes_read = fread(data, 1, binary_size, file);
    fclose(file);

    if (bytes_read != (size_t)binary_size) {
        free(data);
        return NULL;
    }

    if (size != NULL) {
        *size = binary_size;
    }

    return data;
}

// Save DFA to file
bool save_dfa_to_file(const char* filename, const void* data, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        return false;
    }

    size_t written = fwrite(data, 1, size, file);
    fclose(file);

    return (written == size);
}
