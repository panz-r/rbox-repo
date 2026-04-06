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

// MAX_LINE_LENGTH is defined in cdfa_defines.h

// Validation function to verify DFA structure integrity
static bool validate_dfa_structure(const uint8_t* d, size_t file_size) {
    if (file_size < DFA_HEADER_FIXED) {
        ERROR("File too small for DFA header (%zu < %d)", file_size, DFA_HEADER_FIXED);
        return false;
    }

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
    if (ss <= 0) {
        ERROR("Invalid state size %d", ss);
        return false;
    }
    if (sc > file_size / (size_t)ss) {
        ERROR("States size overflow (sc=%u, ss=%d, file_size=%zu)", sc, ss, file_size);
        return false;
    }
    size_t states_size = (size_t)sc * (size_t)ss;
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

// Load DFA from file - returns complete DFA binary including header
// Free DFA data loaded via load_dfa_from_file()
void unload_dfa(void* data) {
    free(data);
}

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
        if (file_size < 0) { fclose(file); return NULL; }

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
    if (fseek(file, 0, SEEK_SET) != 0) { fclose(file); return NULL; }
    char line[MAX_LINE_LENGTH];
    long binary_start = 0;

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "BinaryDataStart", 14) == 0) {
            binary_start = ftell(file);
            if (binary_start < 0) { fclose(file); return NULL; }
            break;
        }
    }

    if (binary_start == 0) {
        fclose(file);
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
    long file_size = ftell(file);
    if (file_size < 0) { fclose(file); return NULL; }
    long binary_size = file_size - binary_start;

    if (fseek(file, binary_start, SEEK_SET) != 0) { fclose(file); return NULL; }
    void* data = malloc(binary_size);
    if (!data) { fclose(file); return NULL; }
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

