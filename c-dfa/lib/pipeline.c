/**
 * pipeline.c - Pipeline orchestration for ReadOnlyBox DFA library
 *
 * Wraps NFA builder, NFA→DFA conversion, minimization, compression,
 * and evaluation into a clean library API.
 */

#define _POSIX_C_SOURCE 200809L
#define DFA_ERROR_PROGRAM "pipeline"

#include "pipeline.h"
#include "dfa_internal.h"
#include "dfa_types.h"
#include "nfa.h"
#include "dfa_errors.h"

#include "../tools/nfa_builder.h"
#include "../tools/nfa2dfa_context.h"
#include "../tools/dfa_minimize.h"
#include "../tools/dfa_compress.h"
#include "../tools/dfa_layout.h"
#include "../tools/nfa_preminimize.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Forward declarations from nfa2dfa.c (compiled with NFA2DFA_BUILDING_LIB)
void init_hash_table(nfa2dfa_context_t* ctx);
void load_nfa_file(nfa2dfa_context_t* ctx, const char* filename);
void nfa_to_dfa(nfa2dfa_context_t* ctx);
void flatten_dfa(nfa2dfa_context_t* ctx);
void write_dfa_file(nfa2dfa_context_t* ctx, const char* filename);

// ============================================================================
// Pipeline struct
// ============================================================================

struct pipeline {
    pipeline_config_t config;
    nfa_builder_context_t* builder_ctx;
    nfa2dfa_context_t* nfa2dfa_ctx;
    uint8_t* binary_data;
    size_t binary_size;
    char last_error[256];
    pipeline_error_t last_error_code;
    char temp_nfa_file[256];
    char temp_dfa_file[256];
    bool nfa_built;
    bool dfa_built;
};

// ============================================================================
// DFA Evaluator struct
// ============================================================================

struct dfa_evaluator {
    void* data;
    size_t size;
    bool owns_data;
};

// ============================================================================
// Error strings
// ============================================================================

static const char* error_strings[] = {
    "Success",
    "General error",
    "Out of memory",
    "Parse error",
    "I/O error",
    "Invalid state",
    "Limit exceeded"
};

const char* pipeline_error_string(pipeline_error_t err) {
    if ((int)err < 0 || (int)err > PIPELINE_LIMIT_EXCEEDED) return "Unknown error";
    return error_strings[(int)err];
}

const char* pipeline_get_last_error(pipeline_t* p) {
    if (p->last_error_code == PIPELINE_OK) return NULL;
    return p->last_error;
}

static void set_error(pipeline_t* p, pipeline_error_t code, const char* msg) {
    p->last_error_code = code;
    snprintf(p->last_error, sizeof(p->last_error), "%s", msg);
}

// ============================================================================
// Pipeline lifecycle
// ============================================================================

pipeline_t* pipeline_create(const pipeline_config_t* config) {
    pipeline_t* p = calloc(1, sizeof(pipeline_t));
    if (!p) return NULL;

    if (config) {
        p->config = *config;
    } else {
        p->config.minimize_algo = PIPELINE_MIN_HOPCROFT;
        p->config.compress = true;
        p->config.optimize_layout = true;
    }

    // Create process-private temp directory using mkdtemp
    char temp_dir_template[] = "/tmp/readonlybox.XXXXXX";
    if (mkdtemp(temp_dir_template) == NULL) {
        free(p);
        return NULL;
    }
    
    // Create temp files inside the private directory
    snprintf(p->temp_nfa_file, sizeof(p->temp_nfa_file), "%s/nfa_XXXXXX", temp_dir_template);
    snprintf(p->temp_dfa_file, sizeof(p->temp_dfa_file), "%s/dfa_XXXXXX", temp_dir_template);
    int nfa_fd = mkstemp(p->temp_nfa_file);
    int dfa_fd = mkstemp(p->temp_dfa_file);
    if (nfa_fd < 0 || dfa_fd < 0) {
        // Close any successfully opened fd
        if (nfa_fd >= 0) close(nfa_fd);
        if (dfa_fd >= 0) close(dfa_fd);
        // Unlink any files that were successfully created
        if (nfa_fd >= 0) unlink(p->temp_nfa_file);
        if (dfa_fd >= 0) unlink(p->temp_dfa_file);
        unlink(temp_dir_template);
        free(p);
        return NULL;
    }
    close(nfa_fd);  // Close fd, path remains valid for later use
    close(dfa_fd);

    p->last_error_code = PIPELINE_OK;
    return p;
}

void pipeline_destroy(pipeline_t* p) {
    nfa_builder_context_destroy(p->builder_ctx);
    nfa2dfa_context_destroy(p->nfa2dfa_ctx);
    free(p->binary_data);
    // Clean up temp files and directory
    unlink(p->temp_nfa_file);
    unlink(p->temp_dfa_file);
    // Remove parent temp directory (extract dir from temp_nfa_file path)
    char temp_dir[256];
    snprintf(temp_dir, sizeof(temp_dir), "%s", p->temp_nfa_file);
    char* last_slash = strrchr(temp_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        rmdir(temp_dir);
    }
    free(p);
}

// ============================================================================
// Pipeline stages
// ============================================================================

pipeline_error_t pipeline_parse_patterns(pipeline_t* p, const char* filename) {
    p->builder_ctx = nfa_builder_context_create();
    if (!p->builder_ctx) {
        set_error(p, PIPELINE_OOM, "Failed to create builder context");
        return PIPELINE_OOM;
    }

    p->builder_ctx->flag_verbose = p->config.verbose;

    // Store filename for pipeline_build_nfa
    p->builder_ctx->current_input_file = filename;

    // Validate pattern file
    if (!nfa_validate_pattern_file(p->builder_ctx, filename, false)) {
        set_error(p, PIPELINE_PARSE_ERROR, "Pattern validation failed");
        return PIPELINE_PARSE_ERROR;
    }

    return PIPELINE_OK;
}

pipeline_error_t pipeline_build_nfa(pipeline_t* p) {
    if (!p->builder_ctx) return PIPELINE_INVALID_STATE;

    // Build alphabet before constructing NFA
    if (!nfa_alphabet_construct_from_patterns(p->builder_ctx, p->builder_ctx->current_input_file)) {
        return PIPELINE_PARSE_ERROR;
    }

    nfa_construct_init(p->builder_ctx);

    // Use nfa_parser to read spec file directly
    nfa_parser_read_spec_file(p->builder_ctx, p->builder_ctx->current_input_file);

    // Write NFA to temp file
    nfa_construct_write_file(p->builder_ctx, p->temp_nfa_file);

    p->nfa_built = true;
    return PIPELINE_OK;
}

pipeline_error_t pipeline_preminimize_nfa(pipeline_t* p) {
    if (!p->nfa2dfa_ctx) return PIPELINE_INVALID_STATE;

    nfa_premin_options_t opts = nfa_premin_default_options();
    opts.verbose = p->config.verbose;
    nfa_preminimize(p->nfa2dfa_ctx->nfa, &p->nfa2dfa_ctx->nfa_state_count, &opts);

    return PIPELINE_OK;
}

// Initialize NFA transitions to -1 (load_nfa_file skips nfa_init in library builds)
static void init_nfa_array(nfa2dfa_context_t* ctx) {
    for (int i = 0; i < ctx->nfa_state_count; i++) {
        for (int j = 0; j < BYTE_VALUE_MAX; j++) {  // BYTE_VALUE_MAX = 256 (byte values 0-255)
            ctx->nfa[i].transitions[j] = -1;
        }
    }
}

pipeline_error_t pipeline_convert_to_dfa(pipeline_t* p) {
    // Initialize nfa2dfa context if needed
    if (!p->nfa2dfa_ctx) {
        p->nfa2dfa_ctx = nfa2dfa_context_create();
        if (!p->nfa2dfa_ctx) {
            set_error(p, PIPELINE_OOM, "Failed to create nfa2dfa context");
            return PIPELINE_OOM;
        }
        p->nfa2dfa_ctx->flag_verbose = p->config.verbose;
    }

    // Initialize NFA transitions to -1 (load_nfa_file skips nfa_init in library builds)
    init_nfa_array(p->nfa2dfa_ctx);

    // Load NFA from temp file
    init_hash_table(p->nfa2dfa_ctx);
    load_nfa_file(p->nfa2dfa_ctx, p->temp_nfa_file);

    // Pre-minimize NFA
    pipeline_preminimize_nfa(p);

    // Convert to DFA
    nfa_to_dfa(p->nfa2dfa_ctx);

    flatten_dfa(p->nfa2dfa_ctx);

    p->dfa_built = true;
    return PIPELINE_OK;
}

pipeline_error_t pipeline_minimize_dfa(pipeline_t* p, int algo) {
    if (!p->nfa2dfa_ctx || !p->dfa_built) return PIPELINE_INVALID_STATE;

    p->nfa2dfa_ctx->dfa_state_count = dfa_minimize(
        p->nfa2dfa_ctx->dfa, p->nfa2dfa_ctx->dfa_state_count, (dfa_min_algo_t)algo);

    // Re-flatten after minimization (except Brzozowski)
    if (algo != PIPELINE_MIN_BRZOZOWSKI) {
        flatten_dfa(p->nfa2dfa_ctx);
    }

    return PIPELINE_OK;
}

pipeline_error_t pipeline_compress(pipeline_t* p) {
    if (!p->nfa2dfa_ctx || !p->dfa_built) return PIPELINE_INVALID_STATE;

    compress_options_t opts = get_default_compress_options();
    opts.verbose = p->config.verbose;
    dfa_compress(p->nfa2dfa_ctx->dfa, p->nfa2dfa_ctx->dfa_state_count, &opts);

    return PIPELINE_OK;
}

pipeline_error_t pipeline_optimize_layout(pipeline_t* p) {
    if (!p->nfa2dfa_ctx || !p->dfa_built) return PIPELINE_INVALID_STATE;

    layout_options_t layout_opts = get_default_layout_options();
    int* order = optimize_dfa_layout(p->nfa2dfa_ctx->dfa, p->nfa2dfa_ctx->dfa_state_count, &layout_opts);
    
    if (!order) {
        return PIPELINE_ERROR;
    }
    
    free(order);
    return PIPELINE_OK;
}

// ============================================================================
// Pipeline results
// ============================================================================

const uint8_t* pipeline_get_binary(pipeline_t* p, size_t* size) {
    if (!p->dfa_built) return NULL;
    if (size) *size = p->binary_size;
    return p->binary_data;
}

pipeline_error_t pipeline_save_binary(pipeline_t* p, const char* filename) {
    if (!p->nfa2dfa_ctx || !p->dfa_built) return PIPELINE_INVALID_STATE;

    write_dfa_file(p->nfa2dfa_ctx, filename);
    return PIPELINE_OK;
}

// ============================================================================
// Convenience functions
// ============================================================================

pipeline_error_t pipeline_run(pipeline_t* p, const char* pattern_file) {
    pipeline_error_t err;

    // 1. Parse patterns
    err = pipeline_parse_patterns(p, pattern_file);
    if (err != PIPELINE_OK) return err;

    // Set input file for builder
    p->builder_ctx->current_input_file = pattern_file;

    // 2. Build NFA
    err = pipeline_build_nfa(p);
    if (err != PIPELINE_OK) return err;

    // 3. Convert to DFA
    err = pipeline_convert_to_dfa(p);
    if (err != PIPELINE_OK) return err;

    // 4. Minimize
    err = pipeline_minimize_dfa(p, p->config.minimize_algo);
    if (err != PIPELINE_OK) return err;

    // 5. Compress (optional)
    if (p->config.compress) {
        err = pipeline_compress(p);
        if (err != PIPELINE_OK) return err;
    }

    // 6. Write output to temp file for binary retrieval
    write_dfa_file(p->nfa2dfa_ctx, p->temp_dfa_file);

    // Read binary into memory
    FILE* f = fopen(p->temp_dfa_file, "rb");
    if (!f) {
        ERROR("Failed to open temp DFA file '%s' for reading", p->temp_dfa_file);
        return PIPELINE_IO_ERROR;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); ERROR("fseek SEEK_END failed"); return PIPELINE_IO_ERROR; }
    long binary_size_long = ftell(f);
    if (binary_size_long < 0) { fclose(f); ERROR("ftell failed"); return PIPELINE_IO_ERROR; }
    if (binary_size_long == 0) { fclose(f); ERROR("Temp DFA file '%s' is empty", p->temp_dfa_file); return PIPELINE_IO_ERROR; }
    p->binary_size = (size_t)binary_size_long;
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); ERROR("fseek SEEK_SET failed"); return PIPELINE_IO_ERROR; }
    p->binary_data = malloc(p->binary_size);
    if (!p->binary_data) {
        fclose(f);
        ERROR("Failed to allocate %zu bytes for DFA binary", p->binary_size);
        return PIPELINE_OOM;
    }
    size_t bytes_read = fread(p->binary_data, 1, p->binary_size, f);
    fclose(f);
    if (bytes_read != p->binary_size) {
        ERROR("Failed to read DFA binary (got %zu of %zu bytes)", bytes_read, p->binary_size);
        free(p->binary_data);
        p->binary_data = NULL;
        p->binary_size = 0;
        return PIPELINE_IO_ERROR;
    }

    return PIPELINE_OK;
}

pipeline_error_t pipeline_build(const char* pattern_file,
                                const char* output_file,
                                const pipeline_config_t* config) {
    pipeline_t* p = pipeline_create(config);
    if (!p) return PIPELINE_OOM;

    pipeline_error_t err = pipeline_run(p, pattern_file);
    if (err == PIPELINE_OK) {
        err = pipeline_save_binary(p, output_file);
    }

    pipeline_destroy(p);
    return err;
}

// ============================================================================
// DFA Evaluation API
// ============================================================================

dfa_evaluator_t* dfa_eval_create(const uint8_t* binary_data, size_t size) {
    if (size == 0) return NULL;

    dfa_evaluator_t* e = calloc(1, sizeof(dfa_evaluator_t));
    if (!e) return NULL;

    e->data = malloc(size);
    if (!e->data) {
        free(e);
        return NULL;
    }
    memcpy(e->data, binary_data, size);
    e->size = size;
    e->owns_data = true;

    return e;
}

dfa_evaluator_t* dfa_eval_load(const char* filename) {
    size_t size = 0;
    void* data = load_dfa_from_file(filename, &size);
    if (!data) return NULL;

    dfa_evaluator_t* e = calloc(1, sizeof(dfa_evaluator_t));
    if (!e) {
        free(data);
        return NULL;
    }

    e->data = data;
    e->size = size;
    e->owns_data = true;

    return e;
}

void dfa_eval_destroy(dfa_evaluator_t* e) {
    if (e->owns_data) free(e->data);
    free(e);
}

dfa_result_t dfa_eval_evaluate(dfa_evaluator_t* e, const char* input) {
    dfa_result_t result = {0};

    result.matched = dfa_eval(e->data, e->size, input, strlen(input), &result);
    return result;
}

