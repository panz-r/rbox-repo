/**
 * pipeline.h - DFA Building Pipeline API
 *
 * FOR: Machine builders who need to compile patterns into binary DFAs.
 * NOT FOR: Eval-only users (see dfa.h for simple eval on pre-built DFAs).
 *
 * Provides:
 *   - Pattern set compilation (NFA → DFA → minimize → compress → binary)
 *   - Pipeline orchestration for building DFA binaries from pattern files
 *   - Evaluator wrapper for convenient evaluation of built DFAs
 *
 * Usage:
 *   pipeline_t* p = pipeline_create();
 *   pipeline_set_patterns_file(p, "patterns.txt");
 *   pipeline_run(p);  // builds binary DFA
 *   dfa_result_t result = pipeline_evaluate(p, "input");
 *   pipeline_destroy(p);
 *
 * For eval-only use on pre-built DFAs, see dfa.h.
 */

#ifndef PIPELINE_H
#define PIPELINE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "cdfa_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "dfa_types.h"

// ============================================================================
// Error Codes
// ============================================================================

typedef enum {
    PIPELINE_OK = 0,
    PIPELINE_ERROR,
    PIPELINE_OOM,
    PIPELINE_PARSE_ERROR,
    PIPELINE_IO_ERROR,
    PIPELINE_INVALID_STATE,
    PIPELINE_LIMIT_EXCEEDED
} pipeline_error_t;

// ============================================================================
// Minimization Algorithm Constants
// (Values match dfa_min_algo_t in tools/dfa_minimize.h)
// ============================================================================

#define PIPELINE_MIN_MOORE       0
#define PIPELINE_MIN_HOPCROFT    1
#define PIPELINE_MIN_BRZOZOWSKI  2

// ============================================================================
// Pipeline Configuration
// ============================================================================

typedef struct {
    int minimize_algo;          // PIPELINE_MIN_* constant
    bool verbose;
    bool preminimize;
    bool compress;
    bool optimize_layout;
    int max_states;      // 0 = use default
    int max_symbols;     // 0 = use default
} pipeline_config_t;

// ============================================================================
// Opaque Handles
// ============================================================================

typedef struct pipeline pipeline_t;
typedef struct dfa_evaluator dfa_evaluator_t;

// ============================================================================
// Pipeline Lifecycle
// ============================================================================

/**
 * Create a new pipeline with given configuration.
 * Returns NULL on allocation failure.
 */
pipeline_t* pipeline_create(const pipeline_config_t* config);

/**
 * Free all resources associated with the pipeline.
 */
void pipeline_destroy(pipeline_t* p) ATTR_NONNULL(1);

// ============================================================================
// Pipeline Stages (incremental API)
// ============================================================================

/**
 * Parse pattern file and load patterns into pipeline.
 */
pipeline_error_t pipeline_parse_patterns(pipeline_t* p, const char* filename) ATTR_NONNULL(1, 2);

/**
 * Build NFA from parsed patterns.
 */
pipeline_error_t pipeline_build_nfa(pipeline_t* p) ATTR_NONNULL(1);

/**
 * Pre-minimize NFA (optional optimization).
 */
pipeline_error_t pipeline_preminimize_nfa(pipeline_t* p) ATTR_NONNULL(1);

/**
 * Convert NFA to DFA via subset construction.
 */
pipeline_error_t pipeline_convert_to_dfa(pipeline_t* p) ATTR_NONNULL(1);

/**
 * Minimize DFA using specified algorithm.
 */
pipeline_error_t pipeline_minimize_dfa(pipeline_t* p, int algo) ATTR_NONNULL(1);

/**
 * Compress DFA transitions.
 */
pipeline_error_t pipeline_compress(pipeline_t* p) ATTR_NONNULL(1);

/**
 * Optimize DFA layout for cache performance.
 */
pipeline_error_t pipeline_optimize_layout(pipeline_t* p) ATTR_NONNULL(1);

// ============================================================================
// Pipeline Results
// ============================================================================

/**
 * Get pointer to internal binary data and its size.
 * Data is owned by the pipeline and valid until pipeline_destroy().
 * size pointer may be NULL if size is not needed.
 */
const uint8_t* pipeline_get_binary(pipeline_t* p, size_t* size) ATTR_NONNULL(1);

/**
 * Save binary DFA to file.
 */
pipeline_error_t pipeline_save_binary(pipeline_t* p, const char* filename) ATTR_NONNULL(1, 2);

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Run full pipeline: parse → NFA → DFA → minimize → output.
 */
pipeline_error_t pipeline_run(pipeline_t* p, const char* pattern_file) ATTR_NONNULL(1, 2);

/**
 * One-shot: build binary DFA from pattern file.
 * Combines create, run, save, and destroy.
 */
pipeline_error_t pipeline_build(const char* pattern_file,
                                const char* output_file,
                                const pipeline_config_t* config);

// ============================================================================
// DFA Evaluation API
// ============================================================================

/**
 * Create evaluator from in-memory binary data.
 * Copies the data internally.
 */
dfa_evaluator_t* dfa_eval_create(const uint8_t* binary_data, size_t size) ATTR_NONNULL(1);

/**
 * Load evaluator from binary DFA file.
 */
dfa_evaluator_t* dfa_eval_load(const char* filename) ATTR_NONNULL(1);

/**
 * Free evaluator resources.
 */
void dfa_eval_destroy(dfa_evaluator_t* e) ATTR_NONNULL(1);

/**
 * Evaluate input string against loaded DFA.
 */
dfa_result_t dfa_eval_evaluate(dfa_evaluator_t* e, const char* input) ATTR_NONNULL_ALL;

/**
 * Get human-readable category name.
 */
const char* dfa_eval_category_name(uint16_t category);

// ============================================================================
// Error Handling
// ============================================================================

/**
 * Get string description for error code.
 */
const char* pipeline_error_string(pipeline_error_t err);

/**
 * Get last error message from pipeline (if any).
 * Returns NULL if no error.
 */
const char* pipeline_get_last_error(pipeline_t* p) ATTR_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif // PIPELINE_H
