/**
 * Dynamic Sparse Multi-Target Array Implementation
 *
 * Optimized for O(1) symbol lookup and efficient multi-target management.
 */

#define DFA_ERROR_PROGRAM "multi_target_array"
#include "../include/dfa_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include "../include/multi_target_array.h"

/**
 * Checked allocation - returns NULL on failure
 */
static void* checked_malloc(size_t size) {
    if (size == 0) return NULL;
    if (size > SIZE_MAX) return NULL;
    void* ptr = malloc(size);
    return ptr;
}

static mta_entry_t* mta_create_entry(int symbol_id) {
    mta_entry_t* entry = checked_malloc(sizeof(mta_entry_t));
    if (entry == NULL) return NULL;

    entry->symbol_id = symbol_id;
    entry->target_count = 0;
    entry->target_capacity = INITIAL_TARGET_CAPACITY;
    entry->dirty = true;
    entry->cached_csv = NULL;
    entry->marker_count = 0;
    
    size_t targets_size = (size_t)INITIAL_TARGET_CAPACITY * sizeof(int);
    entry->targets = checked_malloc(targets_size);
    if (entry->targets == NULL) {
        free(entry);
        return NULL;
    }
    
    return entry;
}

static void mta_free_entry(mta_entry_t* entry) {
    if (entry != NULL) {
        free(entry->targets);
        free(entry->cached_csv);
        free(entry);
    }
}

static bool mta_grow_targets(mta_entry_t* entry) {
    if (entry->target_capacity > INT_MAX / TARGET_GROWTH_FACTOR) {
        return false;  // Overflow would happen
    }
    int new_capacity = entry->target_capacity * TARGET_GROWTH_FACTOR;
    size_t new_size = (size_t)new_capacity * sizeof(int);
    if (new_capacity > 0 && new_size > SIZE_MAX) {
        return false;  // Overflow
    }
    int* new_targets = realloc(entry->targets, new_size);
    if (new_targets == NULL) return false;

    entry->targets = new_targets;
    entry->target_capacity = new_capacity;
    return true;
}

void mta_init(multi_target_array_t* arr) {
    memset(arr->symbol_map, 0, sizeof(arr->symbol_map));
    arr->active_entries = NULL;
    arr->entry_count = 0;
    arr->entry_capacity = 0;
    for (int i = 0; i < MAX_SYMBOLS; i++) {
        arr->first_targets[i] = -1;
        arr->has_first_target[i] = false;
    }
}

void mta_free(multi_target_array_t* arr) {
    if (arr == NULL) return;
    
    if (arr->active_entries != NULL) {
        for (int i = 0; i < arr->entry_count; i++) {
            mta_free_entry(arr->active_entries[i]);
        }
        free(arr->active_entries);
    }
    
    // Zero out to prevent use-after-free
    memset(arr->symbol_map, 0, sizeof(arr->symbol_map));
    arr->active_entries = NULL;
    arr->entry_count = 0;
    arr->entry_capacity = 0;
}

bool mta_add_target(multi_target_array_t* arr, int symbol_id, int target_state) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) return false;

    // O(1) Lookup
    mta_entry_t* entry = arr->symbol_map[symbol_id];

    if (entry == NULL) {
        if (arr->has_first_target[symbol_id]) {
            // Already has one target, now adding a second -> upgrade to multi-target entry
            if (arr->first_targets[symbol_id] == target_state) return true;

            mta_entry_t* new_entry = mta_create_entry(symbol_id);
            if (new_entry == NULL) return false;

            new_entry->targets[0] = arr->first_targets[symbol_id];
            new_entry->targets[1] = target_state;
            new_entry->target_count = 2;
            
            // Register in lookup map
            arr->symbol_map[symbol_id] = new_entry;

            // Add to active list for iteration
            if (arr->entry_count >= arr->entry_capacity) {
                int new_cap = arr->entry_capacity == 0 ? 8 : arr->entry_capacity * 2;
                if (arr->entry_capacity > 0 && new_cap <= arr->entry_capacity) {
                    return false;  // Overflow
                }
                size_t new_size = (size_t)new_cap * sizeof(mta_entry_t*);
                if (new_size > SIZE_MAX) return false;
                mta_entry_t** next_active = realloc(arr->active_entries, new_size);
                if (next_active == NULL) {
                    mta_free_entry(new_entry);
                    return false;
                }
                arr->active_entries = next_active;
                arr->entry_capacity = new_cap;
            }
            arr->active_entries[arr->entry_count++] = new_entry;

            // Clear first-target optimization
            arr->first_targets[symbol_id] = -1;
            arr->has_first_target[symbol_id] = false;
            return true;
        }
        // First target for this symbol - use fast path
        arr->first_targets[symbol_id] = target_state;
        arr->has_first_target[symbol_id] = true;
        return true;
    }

    // Existing multi-target entry - check for duplicates
    for (int i = 0; i < entry->target_count; i++) {
        if (entry->targets[i] == target_state) return true;
    }

    // Add new target
    if (entry->target_count >= entry->target_capacity) {
        if (!mta_grow_targets(entry)) {
            return false;
        }
    }

    entry->targets[entry->target_count++] = target_state;
    entry->dirty = true;
    return true;
}

bool mta_is_multi(multi_target_array_t* arr, int symbol_id) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) return false;
    return arr->symbol_map[symbol_id] != NULL;
}

static void mta_update_cache(mta_entry_t* entry) {
    if (!entry->dirty && entry->cached_csv != NULL) return;

    if (entry->cached_csv == NULL) {
        entry->cached_csv = checked_malloc(MAX_TARGET_BUFFER);
        if (entry->cached_csv == NULL) return;  // Cache allocation failed, skip caching
    }

    char* p = entry->cached_csv;
    int remaining = MAX_TARGET_BUFFER - 1;

    for (int j = 0; j < entry->target_count; j++) {
        int len = snprintf(p, remaining, "%d", entry->targets[j]);
        if (len < 0 || len >= remaining) break; 
        p += len;
        remaining -= len;

        if (j < entry->target_count - 1 && remaining > 0) {
            *p++ = ',';
            remaining--;
        }
    }
    *p = '\0';
    entry->dirty = false;
}

const char* mta_get_targets(multi_target_array_t* arr, int symbol_id) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) return NULL;

    mta_entry_t* entry = arr->symbol_map[symbol_id];
    if (entry == NULL) return NULL;

    mta_update_cache(entry);
    return entry->cached_csv;
}

int* mta_get_target_array(multi_target_array_t* arr, int symbol_id, int* out_count) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) {
        if (out_count) *out_count = 0;
        return NULL;
    }

    mta_entry_t* entry = arr->symbol_map[symbol_id];
    if (entry) {
        if (out_count) *out_count = entry->target_count;
        return entry->targets;
    }

    if (arr->has_first_target[symbol_id]) {
        if (out_count) *out_count = 1;
        return &arr->first_targets[symbol_id];
    }

    if (out_count) *out_count = 0;
    return NULL;
}

int mta_get_target_count(multi_target_array_t* arr, int symbol_id) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) return 0; 
    
    mta_entry_t* entry = arr->symbol_map[symbol_id];
    if (entry != NULL) return entry->target_count;
    
    return arr->has_first_target[symbol_id] ? 1 : 0;
}

void mta_clear_symbol(multi_target_array_t* arr, int symbol_id) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) return;

    mta_entry_t* entry = arr->symbol_map[symbol_id];
    if (entry != NULL) {
        for (int i = 0; i < arr->entry_count; i++) {
            if (arr->active_entries[i] == entry) {
                arr->active_entries[i] = arr->active_entries[--arr->entry_count];
                break;
            }
        }
        mta_free_entry(entry);
        arr->symbol_map[symbol_id] = NULL;
    }

    arr->first_targets[symbol_id] = -1;
    arr->has_first_target[symbol_id] = false;
}

int mta_get_entry_count(multi_target_array_t* arr) {
    return arr->entry_count;
}

void mta_print(multi_target_array_t* arr, const char* label) {
    printf("=== Multi-Target Array: %s ===\n", label);
    printf("Active entries: %d\n", arr->entry_count);
    for (int i = 0; i < arr->entry_count; i++) {
        mta_entry_t* entry = arr->active_entries[i];
        printf("  Symbol %d: %d targets [", entry->symbol_id, entry->target_count);
        for (int j = 0; j < entry->target_count; j++) {
            printf("%d%s", entry->targets[j], (j < entry->target_count - 1) ? ", " : "");
        }
        printf("]\n");
        if (entry->marker_count > 0) {
            printf("    Markers: ");
            for (int j = 0; j < entry->marker_count; j++) {
                printf("[pat=%d uid=%u type=%d] ",
                       entry->markers[j].pattern_id,
                       entry->markers[j].uid,
                       entry->markers[j].type);
            }
            printf("\n");
        }
    }
    printf("==========================\n");
}

bool mta_add_marker(multi_target_array_t* arr, int symbol_id,
                   uint16_t pattern_id, uint32_t uid, uint8_t type) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) return false;
    if (type > 1) return false;  // Only START(0) or END(1) allowed

    // Get or create the multi-target entry
    mta_entry_t* entry = arr->symbol_map[symbol_id];

    if (entry == NULL && !arr->has_first_target[symbol_id]) {
        // No transition exists for this symbol, create a placeholder entry
        entry = mta_create_entry(symbol_id);
        if (entry == NULL) return false;
        
        int new_cap = arr->entry_capacity == 0 ? 8 : arr->entry_capacity * 2;
        if (arr->entry_capacity > 0 && new_cap <= arr->entry_capacity) {
            mta_free_entry(entry);
            return false;  // Overflow
        }
        size_t new_size = (size_t)new_cap * sizeof(mta_entry_t*);
        if (new_size > SIZE_MAX) {
            mta_free_entry(entry);
            return false;
        }
        mta_entry_t** next_active = realloc(arr->active_entries, new_size);
        if (next_active == NULL) {
            mta_free_entry(entry);
            return false;
        }
        arr->active_entries = next_active;
        arr->entry_capacity = new_cap;
        arr->active_entries[arr->entry_count++] = entry;
        arr->symbol_map[symbol_id] = entry;
    } else if (entry == NULL && arr->has_first_target[symbol_id]) {
        // Single-target transition exists, need to upgrade
        entry = mta_create_entry(symbol_id);
        if (entry == NULL) return false;
        
        entry->targets[0] = arr->first_targets[symbol_id];
        entry->target_count = 1;

        int new_cap = arr->entry_capacity == 0 ? 8 : arr->entry_capacity * 2;
        if (arr->entry_capacity > 0 && new_cap <= arr->entry_capacity) {
            mta_free_entry(entry);
            return false;  // Overflow
        }
        size_t new_size = (size_t)new_cap * sizeof(mta_entry_t*);
        if (new_size > SIZE_MAX) {
            mta_free_entry(entry);
            return false;
        }
        mta_entry_t** next_active = realloc(arr->active_entries, new_size);
        if (next_active == NULL) {
            mta_free_entry(entry);
            return false;
        }
        arr->active_entries = next_active;
        arr->entry_capacity = new_cap;
        arr->active_entries[arr->entry_count++] = entry;
        arr->symbol_map[symbol_id] = entry;

        arr->first_targets[symbol_id] = -1;
        arr->has_first_target[symbol_id] = false;
    }

    // Check for duplicate marker
    for (int i = 0; i < entry->marker_count; i++) {
        if (entry->markers[i].pattern_id == pattern_id &&
            entry->markers[i].uid == uid &&
            entry->markers[i].type == type) {
            return true;  // Already exists
        }
    }

    // Add new marker
    if (entry->marker_count >= MAX_MARKERS_PER_TRANSITION) {
        return false;  // Too many markers
    }

    entry->markers[entry->marker_count].pattern_id = pattern_id;
    entry->markers[entry->marker_count].uid = uid;
    entry->markers[entry->marker_count].type = type;
    entry->marker_count++;
    entry->dirty = true;

    return true;
}

transition_marker_t* mta_get_markers(multi_target_array_t* arr, int symbol_id, int* out_count) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) {
        if (out_count) *out_count = 0;
        return NULL;
    }

    mta_entry_t* entry = arr->symbol_map[symbol_id];
    if (entry == NULL) {
        // No multi-target entry, check first-target
        if (arr->has_first_target[symbol_id]) {
            // We need a way to return markers for single-target
            // For now, return NULL - single-target uses nfa.transitions
        }
        if (out_count) *out_count = 0;
        return NULL;
    }

    if (out_count) *out_count = entry->marker_count;
    return entry->markers;
}

void mta_clear_markers(multi_target_array_t* arr, int symbol_id) {
    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) return;

    mta_entry_t* entry = arr->symbol_map[symbol_id];
    if (entry != NULL) {
        entry->marker_count = 0;
        entry->dirty = true;
    }
}
