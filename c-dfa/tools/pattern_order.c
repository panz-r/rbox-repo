/**
 * Pattern Ordering Optimization Implementation
 * 
 * Uses prefix tree (trie) to group patterns with common prefixes,
 * minimizing NFA/DFA states.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "pattern_order.h"

// Statistics from last run
static pattern_order_stats_t last_stats = {0};
static bool order_verbose = false;

#define VERBOSE_PRINT(...) do { \
    if (order_verbose) fprintf(stderr, "[PATTERN_ORDER] " __VA_ARGS__); \
} while(0)

// Prefix tree node
typedef struct trie_node {
    char ch;                    // Character at this node
    int pattern_idx;            // Pattern index (-1 if not terminal)
    int depth;                  // Depth in tree
    struct trie_node* child;    // First child
    struct trie_node* sibling;  // Next sibling
} trie_node_t;

// Get default options
pattern_order_options_t pattern_order_default_options(void) {
    pattern_order_options_t opts = {
        .group_by_category = true,
        .wildcard_last = true,
        .verbose = false
    };
    return opts;
}

// Get statistics
void pattern_order_get_stats(pattern_order_stats_t* stats) {
    if (stats) *stats = last_stats;
}

/**
 * Create a new trie node
 */
static trie_node_t* trie_create_node(char ch, int depth) {
    trie_node_t* node = malloc(sizeof(trie_node_t));
    node->ch = ch;
    node->pattern_idx = -1;
    node->depth = depth;
    node->child = NULL;
    node->sibling = NULL;
    return node;
}

/**
 * Find or create child node for character
 */
static trie_node_t* trie_get_child(trie_node_t* parent, char ch) {
    // Search existing children
    trie_node_t* prev = NULL;
    trie_node_t* node = parent->child;
    
    while (node) {
        if (node->ch == ch) return node;
        if (node->ch > ch) break;  // Insert point (sorted)
        prev = node;
        node = node->sibling;
    }
    
    // Create new node
    trie_node_t* new_node = trie_create_node(ch, parent->depth + 1);
    
    // Insert in sorted order
    if (prev == NULL) {
        new_node->sibling = parent->child;
        parent->child = new_node;
    } else {
        new_node->sibling = prev->sibling;
        prev->sibling = new_node;
    }
    
    return new_node;
}

/**
 * Insert pattern into trie
 */
static void trie_insert(trie_node_t* root, const char* pattern, int pattern_idx) {
    trie_node_t* node = root;
    
    for (const char* p = pattern; *p; p++) {
        node = trie_get_child(node, *p);
    }
    
    // Mark as terminal with pattern index
    node->pattern_idx = pattern_idx;
}

/**
 * Extract patterns in depth-first order
 */
static void trie_extract_order(trie_node_t* node, int* order, int* count) {
    if (node->pattern_idx >= 0) {
        order[(*count)++] = node->pattern_idx;
    }
    
    // Traverse children in order
    for (trie_node_t* child = node->child; child; child = child->sibling) {
        trie_extract_order(child, order, count);
    }
}

/**
 * Free trie memory
 */
static void trie_free(trie_node_t* node) {
    if (!node) return;
    
    trie_free(node->child);
    trie_free(node->sibling);
    free(node);
}

/**
 * Count nodes in trie (for statistics)
 */
static int trie_count_nodes(trie_node_t* node) {
    if (!node) return 0;
    return 1 + trie_count_nodes(node->child) + trie_count_nodes(node->sibling);
}

/**
 * Compare patterns for qsort (by pattern string)
 */
static int compare_patterns(const void* a, const void* b) {
    const pattern_entry_t* pa = (const pattern_entry_t*)a;
    const pattern_entry_t* pb = (const pattern_entry_t*)b;
    return strcmp(pa->pattern, pb->pattern);
}

/**
 * Check if pattern contains wildcards
 */
static bool has_wildcards(const char* pattern) {
    return strchr(pattern, '*') != NULL ||
           strchr(pattern, '+') != NULL ||
           strchr(pattern, '?') != NULL;
}

/**
 * Order patterns for optimal NFA construction
 */
int pattern_order_optimize(pattern_entry_t* patterns, int count, 
                           const pattern_order_options_t* options) {
    pattern_order_options_t opts = options ? *options : pattern_order_default_options();
    order_verbose = opts.verbose;
    
    memset(&last_stats, 0, sizeof(last_stats));
    last_stats.original_count = count;
    
    if (count <= 1) return 0;
    
    VERBOSE_PRINT("Ordering %d patterns\n", count);
    
    // Build tries for each category (if grouping by category)
    int* new_order = malloc(count * sizeof(int));
    int new_count = 0;
    
    // Find unique categories
    char** categories = NULL;
    int cat_count = 0;
    int cat_capacity = 16;
    categories = malloc(cat_capacity * sizeof(char*));
    
    for (int i = 0; i < count; i++) {
        if (patterns[i].category) {
            // Check if category already seen
            bool found = false;
            for (int j = 0; j < cat_count; j++) {
                if (strcmp(categories[j], patterns[i].category) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (cat_count >= cat_capacity) {
                    cat_capacity *= 2;
                    categories = realloc(categories, cat_capacity * sizeof(char*));
                }
                categories[cat_count++] = patterns[i].category;
            }
        }
    }
    
    VERBOSE_PRINT("Found %d categories\n", cat_count);
    
    // Process each category
    for (int cat = -1; cat < cat_count; cat++) {
        const char* cat_name = (cat < 0) ? NULL : categories[cat];
        
        // Build trie for patterns in this category
        trie_node_t* root = trie_create_node('\0', 0);
        int* cat_indices = malloc(count * sizeof(int));
        int cat_pattern_count = 0;
        
        // Separate wildcard and non-wildcard patterns
        int* wildcard_indices = malloc(count * sizeof(int));
        int wildcard_count = 0;
        
        for (int i = 0; i < count; i++) {
            // Check if pattern belongs to this category
            bool match = (cat_name == NULL && patterns[i].category == NULL) ||
                         (cat_name != NULL && patterns[i].category != NULL &&
                          strcmp(cat_name, patterns[i].category) == 0);
            
            if (match) {
                if (opts.wildcard_last && has_wildcards(patterns[i].pattern)) {
                    wildcard_indices[wildcard_count++] = i;
                } else {
                    cat_indices[cat_pattern_count++] = i;
                }
            }
        }
        
        // Insert non-wildcard patterns into trie
        for (int i = 0; i < cat_pattern_count; i++) {
            trie_insert(root, patterns[cat_indices[i]].pattern, cat_indices[i]);
        }
        
        // Extract order from trie
        int* cat_order = malloc(cat_pattern_count * sizeof(int));
        int cat_order_count = 0;
        trie_extract_order(root, cat_order, &cat_order_count);
        
        // Add to new order
        for (int i = 0; i < cat_order_count; i++) {
            new_order[new_count++] = cat_order[i];
        }
        
        // Add wildcard patterns at the end
        for (int i = 0; i < wildcard_count; i++) {
            new_order[new_count++] = wildcard_indices[i];
        }
        
        last_stats.prefix_groups += trie_count_nodes(root) > 1 ? 1 : 0;
        
        trie_free(root);
        free(cat_indices);
        free(wildcard_indices);
        free(cat_order);
    }
    
    free(categories);
    
    // Count how many patterns changed position
    int reordered = 0;
    for (int i = 0; i < count; i++) {
        if (new_order[i] != i) reordered++;
    }
    last_stats.patterns_reordered = reordered;
    
    // Reorder patterns array
    pattern_entry_t* temp = malloc(count * sizeof(pattern_entry_t));
    memcpy(temp, patterns, count * sizeof(pattern_entry_t));
    for (int i = 0; i < count; i++) {
        patterns[i] = temp[new_order[i]];
    }
    free(temp);
    
    free(new_order);
    
    VERBOSE_PRINT("Reordered %d/%d patterns\n", reordered, count);
    
    return reordered;
}

/**
 * Read patterns from file
 */
int pattern_order_read_file(const char* filename, pattern_entry_t** patterns_out) {
    FILE* f = fopen(filename, "r");
    if (!f) return -1;
    
    int capacity = 256;
    pattern_entry_t* patterns = malloc(capacity * sizeof(pattern_entry_t));
    int count = 0;
    
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }
        
        // Skip empty lines and comments
        if (len == 0 || line[0] == '#') continue;
        
        // Grow array if needed
        if (count >= capacity) {
            capacity *= 2;
            patterns = realloc(patterns, capacity * sizeof(pattern_entry_t));
        }
        
        // Parse line
        pattern_entry_t* pe = &patterns[count];
        pe->line = strdup(line);
        pe->original_index = count;
        
        // Extract category [category] if present
        if (line[0] == '[') {
            char* end = strchr(line, ']');
            if (end) {
                pe->category = strndup(line + 1, end - line - 1);
                pe->pattern = strdup(end + 1);
                // Trim leading whitespace from pattern
                while (pe->pattern[0] && isspace(pe->pattern[0])) {
                    memmove(pe->pattern, pe->pattern + 1, strlen(pe->pattern));
                }
            } else {
                pe->category = NULL;
                pe->pattern = strdup(line);
            }
        } else {
            pe->category = NULL;
            pe->pattern = strdup(line);
        }
        
        count++;
    }
    
    fclose(f);
    *patterns_out = patterns;
    return count;
}

/**
 * Write patterns to file
 */
int pattern_order_write_file(const char* filename, const pattern_entry_t* patterns, int count) {
    FILE* f = fopen(filename, "w");
    if (!f) return -1;
    
    for (int i = 0; i < count; i++) {
        fprintf(f, "%s\n", patterns[i].line);
    }
    
    fclose(f);
    return 0;
}

/**
 * Free pattern array
 */
void pattern_order_free(pattern_entry_t* patterns, int count) {
    for (int i = 0; i < count; i++) {
        free(patterns[i].line);
        free(patterns[i].pattern);
        free(patterns[i].category);
    }
    free(patterns);
}
