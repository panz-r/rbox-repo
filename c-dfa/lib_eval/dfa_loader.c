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

    if (!dfa_fmt_verify_checksums(d, file_size, hs)) {
        ERROR("DFA checksum mismatch (corrupted header)");
        return false;
    }

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

    // Get file size
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
    long file_size = ftell(file);
    if (file_size < 0) { fclose(file); return NULL; }
    if (fseek(file, 0, SEEK_SET) != 0) { fclose(file); return NULL; }

    void* dfa_data = malloc((size_t)file_size);
    if (dfa_data == NULL) {
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(dfa_data, 1, (size_t)file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        free(dfa_data);
        return NULL;
    }

    // Validate DFA structure
    if (!validate_dfa_structure((const uint8_t*)dfa_data, (size_t)file_size)) {
        ERROR("DFA structure validation failed for %s", filename);
        free(dfa_data);
        return NULL;
    }

    if (size != NULL) {
        *size = (size_t)file_size;
    }

    return dfa_data;
}

