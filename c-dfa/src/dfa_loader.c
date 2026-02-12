#include "../include/dfa_types.h"
#include "../include/dfa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_LINE_LENGTH 1024

// Compile-time struct validation
_Static_assert(sizeof(dfa_state_t) == 18, "dfa_state_t must be exactly 18 bytes (packed)");
_Static_assert(sizeof(dfa_t) == 23, "dfa_t must be exactly 23 bytes (packed)");
_Static_assert(sizeof(dfa_rule_t) == 12, "dfa_rule_t must be exactly 12 bytes (packed)");
_Static_assert(offsetof(dfa_state_t, transitions_offset) == 0, "transitions_offset must be at offset 0");
_Static_assert(offsetof(dfa_state_t, transition_count) == 4, "transition_count must be at offset 4");
_Static_assert(offsetof(dfa_state_t, flags) == 6, "flags must be at offset 6");
_Static_assert(offsetof(dfa_t, identifier) == 23, "identifier must be at offset 23 in dfa_t");

// Validation function to verify DFA structure integrity
static bool validate_dfa_structure(const dfa_t* dfa, size_t file_size) {
    // Validate header fields
    if (dfa->magic != DFA_MAGIC) {
        fprintf(stderr, "ERROR: Invalid magic number (expected 0x%08X, got 0x%08X)\n", DFA_MAGIC, dfa->magic);
        return false;
    }

    if (dfa->version < 5 || dfa->version > 6) {
        fprintf(stderr, "ERROR: Unsupported DFA version %u (expected 5 or 6)\n", dfa->version);
        return false;
    }

    if (dfa->state_count == 0) {
        fprintf(stderr, "ERROR: state_count is zero\n");
        return false;
    }

    // Note: DFA_MAX_STATES is 65535 (uint16_t max), so state_count > DFA_MAX_STATES
    // is always false. Validation is effectively covered by file size checks below.

    // Validate initial_state offset
    size_t min_state_offset = dfa->initial_state;
    if (min_state_offset < sizeof(dfa_t) + dfa->identifier_length) {
        fprintf(stderr, "ERROR: initial_state %u is before expected start of states\n", dfa->initial_state);
        return false;
    }

    // Validate that states fit in file
    size_t states_size = (size_t)dfa->state_count * sizeof(dfa_state_t);
    if (dfa->initial_state + states_size > file_size) {
        fprintf(stderr, "ERROR: States array extends beyond file size\n");
        return false;
    }

    // Validate accepting_mask only has bits for existing states
    if (dfa->accepting_mask != 0) {
        if (dfa->state_count < 32) {
            uint32_t max_valid_mask = (1u << dfa->state_count) - 1;
            if ((dfa->accepting_mask & ~max_valid_mask) != 0) {
                fprintf(stderr, "ERROR: accepting_mask 0x%08X has bits beyond state_count %u (max mask: 0x%08X)\n",
                        dfa->accepting_mask, dfa->state_count, max_valid_mask);
                return false;
            }
        } else {
            // For state_count >= 32, check each bit individually
            for (int i = 32; i < dfa->state_count; i++) {
                if ((dfa->accepting_mask & (1u << i)) != 0) {
                    fprintf(stderr, "ERROR: accepting_mask has bit %d set but state_count is only %u\n",
                            i, dfa->state_count);
                    return false;
                }
            }
        }
    }

    return true;
}

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
            identifier[sizeof(identifier) - 1] = '\0';
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
        if (version >= 4) {
            if (fread(&id_len, sizeof(id_len), 1, file) != 1) id_len = 0;
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

        // Validate DFA structure
        const dfa_t* dfa = (const dfa_t*)dfa_data;
        if (!validate_dfa_structure(dfa, (size_t)dfa_size)) {
            fprintf(stderr, "ERROR: DFA structure validation failed for %s\n", filename);
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

// Look up capture name by UID from the Name Table
const char* lookup_capture_name(const void* dfa_data, uint16_t uid) {
    if (!dfa_data || uid == 0) return NULL;

    const dfa_t* dfa = (const dfa_t*)dfa_data;
    if (dfa->version < 6 || dfa->metadata_offset == 0) return NULL;

    const uint32_t* name_table = (const uint32_t*)((const char*)dfa_data + dfa->metadata_offset);
    uint32_t entry_count = name_table[0];

    size_t byte_offset = 4; // start after entry_count
    for (uint32_t i = 0; i < entry_count && byte_offset < 10000; i++) {
        // Read UID at current position
        uint32_t entry_uid = *(const uint32_t*)((const char*)name_table + byte_offset);
        byte_offset += 4;

        // Read name length
        uint16_t name_len = *(const uint16_t*)((const char*)name_table + byte_offset);
        byte_offset += 2;

        // Check if this is the UID we're looking for
        if (entry_uid == uid) {
            static char name_buffer[64];
            if (name_len >= sizeof(name_buffer)) name_len = sizeof(name_buffer) - 1;
            memcpy(name_buffer, (const char*)name_table + byte_offset, name_len);
            name_buffer[name_len] = '\0';
            return name_buffer;
        }

        // Skip past name data
        byte_offset += name_len;
    }

    return NULL;
}
