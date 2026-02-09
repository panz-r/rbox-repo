/**
 * Dynamic Sparse Multi-Target Array
 *
 * A memory-efficient structure for storing NFA transition targets that only
 * allocates storage for symbols with 2+ targets. Single-target symbols use
 * the fast path (caller's transitions[] array).
 */

#ifndef MTA_H
#define MTA_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_SYMBOLS 256
#define INITIAL_TARGET_CAPACITY 8
#define TARGET_GROWTH_FACTOR 2
#define MAX_TARGETS 256
#define MAX_TARGET_BUFFER 4096

typedef struct {
    int symbol_id;
    int target_count;
    int target_capacity;
    int* targets;
    bool dirty;
    char* cached_csv;
} mta_entry_t;

typedef struct {
    mta_entry_t* symbol_map[MAX_SYMBOLS]; // O(1) lookup (Fix #1)
    mta_entry_t** active_entries;         // For iteration/printing
    int entry_count;
    int entry_capacity;
    int first_targets[MAX_SYMBOLS];
    bool has_first_target[MAX_SYMBOLS];
} multi_target_array_t;

void mta_init(multi_target_array_t* arr);

void mta_free(multi_target_array_t* arr);

bool mta_add_target(multi_target_array_t* arr, int symbol_id, int target_state);

bool mta_is_multi(multi_target_array_t* arr, int symbol_id);

const char* mta_get_targets(multi_target_array_t* arr, int symbol_id);

/**
 * Get direct access to the target array for a symbol. (Fix #5)
 * Returns pointer to internal array. Caller should not modify.
 */
int* mta_get_target_array(multi_target_array_t* arr, int symbol_id, int* out_count);

int mta_get_target_count(multi_target_array_t* arr, int symbol_id);

void mta_clear_symbol(multi_target_array_t* arr, int symbol_id);

void mta_print(multi_target_array_t* arr, const char* label);

int mta_get_entry_count(multi_target_array_t* arr);

#endif
