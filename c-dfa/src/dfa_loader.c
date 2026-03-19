#define DFA_ERROR_PROGRAM "dfa_loader"
#include "dfa_errors.h"

#include "dfa_types.h"
#include "dfa_format.h"
#include "dfa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_LINE_LENGTH 1024

// Validation function to verify DFA structure integrity
static bool validate_dfa_structure(const uint8_t* d, size_t file_size) {
    if (dfa_fmt_magic(d) != DFA_MAGIC) {
        ERROR("Invalid magic number (expected 0x%08X, got 0x%08X)", DFA_MAGIC, dfa_fmt_magic(d));
        return false;
    }

    uint16_t ver = dfa_fmt_version(d);
    if (ver != DFA_VERSION) {
        ERROR("Unsupported DFA version %u (expected %u)", ver, DFA_VERSION);
        return false;
    }

    uint16_t sc = dfa_fmt_state_count(d);
    if (sc == 0) {
        ERROR("state_count is zero");
        return false;
    }

    int enc = dfa_fmt_encoding(d);
    uint8_t idl = dfa_fmt_id_len(d);
    size_t hs = DFA_HEADER_SIZE(enc, idl);
    uint32_t init = dfa_fmt_initial_state(d);

    if ((size_t)init < hs) {
        ERROR("initial_state %u is before header end %zu", init, hs);
        return false;
    }

    int ss = DFA_STATE_SIZE(enc);
    size_t states_size = (size_t)sc * ss;
    if ((size_t)init + states_size > file_size) {
        ERROR("States extend beyond file size");
        return false;
    }

    uint32_t meta = dfa_fmt_meta_offset(d);
    if (meta != 0 && meta > file_size) {
        ERROR("metadata_offset %u beyond file size %zu", meta, file_size);
        return false;
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
        if (!validate_dfa_structure((const uint8_t*)dfa_data, (size_t)dfa_size)) {
            ERROR("DFA structure validation failed for %s", filename);
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
static bool save_dfa_to_file(const char* filename, const void* data, size_t size) {
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

    // Use a reasonable upper bound: each entry has UID(4) + name_len(2) + name(N) bytes
    // Maximum 256 entries with 64-byte names = ~18KB, use 32KB as safe upper bound
    size_t max_metadata_size = 32768;
    size_t byte_offset = 4; // start after entry_count
    for (uint32_t i = 0; i < entry_count && byte_offset + 6 <= max_metadata_size; i++) {
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
