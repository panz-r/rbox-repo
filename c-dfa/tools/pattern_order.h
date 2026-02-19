/**
 * Pattern Ordering Optimization
 * 
 * Reorders patterns to minimize NFA/DFA states by grouping
 * patterns with common prefixes together.
 */

#ifndef PATTERN_ORDER_H
#define PATTERN_ORDER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Pattern entry from input file
 */
typedef struct {
    char* line;           // Original line (including category)
    char* pattern;        // Pattern part only
    char* category;       // Category part (or NULL)
    int original_index;   // Original position in file
} pattern_entry_t;

/**
 * Ordering statistics
 */
typedef struct {
    int original_count;      // Number of patterns
    int prefix_groups;       // Number of prefix groups found
    int patterns_reordered;  // Patterns that changed position
    double avg_prefix_len;   // Average prefix length shared
} pattern_order_stats_t;

/**
 * Options for pattern ordering
 */
typedef struct {
    bool group_by_category;  // Group by category first (default: true)
    bool wildcard_last;      // Place wildcard patterns last (default: true)
    bool verbose;            // Print progress
} pattern_order_options_t;

/**
 * Get default options
 */
pattern_order_options_t pattern_order_default_options(void);

/**
 * Order patterns for optimal NFA construction.
 * 
 * @param patterns Array of pattern entries
 * @param count Number of patterns
 * @param options Ordering options (NULL for defaults)
 * @return Number of patterns that changed position
 */
int pattern_order_optimize(pattern_entry_t* patterns, int count, 
                           const pattern_order_options_t* options);

/**
 * Get statistics from last ordering run
 */
void pattern_order_get_stats(pattern_order_stats_t* stats);

/**
 * Read patterns from file.
 * 
 * @param filename Input file path
 * @param patterns Output array (caller must free)
 * @return Number of patterns read, or -1 on error
 */
int pattern_order_read_file(const char* filename, pattern_entry_t** patterns);

/**
 * Write patterns to file in current order.
 * 
 * @param filename Output file path
 * @param patterns Array of pattern entries
 * @param count Number of patterns
 * @return 0 on success, -1 on error
 */
int pattern_order_write_file(const char* filename, const pattern_entry_t* patterns, int count);

/**
 * Free pattern array.
 */
void pattern_order_free(pattern_entry_t* patterns, int count);

#endif // PATTERN_ORDER_H
