/**
 * Pattern Ordering Optimization Implementation
 * 
 * Uses prefix tree (trie) to group patterns with common prefixes,
 * minimizing NFA/DFA states.
 * 
 * Also performs validation:
 * - Duplicate detection (warns and removes)
 * - Fragment reference validation (errors if missing)
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "pattern_order.h"

// Statistics from last run
static pattern_order_stats_t last_stats = {
    .original_count = 0,
    .prefix_groups = 0,
    .patterns_reordered = 0,
    .duplicates_found = 0,
    .fragment_errors = 0,
    .avg_prefix_len = 0.0
};
static bool order_verbose = false;

#define VERBOSE_PRINT(...) do { \
    if (order_verbose) fprintf(stderr, "[PATTERN_ORDER] " __VA_ARGS__); \
} while(0)

// Prefix tree node for duplicate detection (uses full line)
typedef struct trie_node {
    char ch;                    // Character at this node
    int pattern_idx;            // Pattern index (-1 if not terminal)
    int depth;                  // Depth in tree
    struct trie_node* child;    // First child
    struct trie_node* sibling;  // Next sibling
} trie_node_t;

// Fragment table for validation
#define MAX_FRAGMENTS 256
typedef struct {
    char* names[MAX_FRAGMENTS];
    int count;
} fragment_table_t;

static fragment_table_t fragment_table = {
    .names = {NULL},
    .count = 0
};

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
 * Insert pattern into trie - returns true if duplicate detected
 * Uses the FULL line (including category) for duplicate detection
 */
static bool trie_insert_detect_dup(trie_node_t* root, const char* full_line, int pattern_idx) {
    trie_node_t* node = root;
    
    for (const char* p = full_line; *p; p++) {
        node = trie_get_child(node, *p);
    }
    
    // Check if this is a duplicate
    if (node->pattern_idx >= 0) {
        return true;  // Duplicate detected
    }
    
    // Mark as terminal with pattern index
    node->pattern_idx = pattern_idx;
    return false;
}

/**
 * Insert pattern into trie (for ordering, no duplicate detection)
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
 * Register a fragment definition
 */
static void register_fragment(const char* name) {
    if (fragment_table.count >= MAX_FRAGMENTS) {
        fprintf(stderr, "Warning: Too many fragments (max %d)\n", MAX_FRAGMENTS);
        return;
    }
    
    // Check if already registered
    for (int i = 0; i < fragment_table.count; i++) {
        if (strcmp(fragment_table.names[i], name) == 0) {
            return;  // Already exists
        }
    }
    
    fragment_table.names[fragment_table.count++] = strdup(name);
}

/**
 * Check if a fragment exists (with optional namespace)
 * If name contains "::", look it up directly
 * If name has no "::", look up in the given namespace, then fall back to unqualified
 */
static bool fragment_exists_in_ns(const char* name, const char* namespace) {
    // If name already has namespace qualifier, look it up directly
    if (strstr(name, "::") != NULL) {
        for (int i = 0; i < fragment_table.count; i++) {
            if (strcmp(fragment_table.names[i], name) == 0) {
                return true;
            }
        }
        return false;
    }
    
    // First, try to look up in the given namespace
    if (namespace && namespace[0] != '\0') {
        char full_name[4096];
        snprintf(full_name, sizeof(full_name), "%s::%s", namespace, name);
        
        for (int i = 0; i < fragment_table.count; i++) {
            if (strcmp(fragment_table.names[i], full_name) == 0) {
                return true;
            }
        }
    }
    
    // Fall back to unqualified name (for backward compatibility)
    for (int i = 0; i < fragment_table.count; i++) {
        if (strcmp(fragment_table.names[i], name) == 0) {
            return true;
        }
    }
    
    return false;
}

/**
 * Check if a string is a valid fragment name (alphanumeric, underscores, hyphens, double-colons)
 */
static bool is_valid_fragment_name(const char* s, int len) {
    if (len <= 0 || len >= 64) return false;
    
    for (int i = 0; i < len; i++) {
        char c = s[i];
        if (isalnum((unsigned char)c) || c == '_' || c == '-' || c == ':') {
            continue;
        }
        return false;  // Invalid character (e.g., |, (, ), space, etc.)
    }
    return true;
}

/**
 * Extract fragment references from a pattern
 * Looks for ((name)) or ((namespace::name)) patterns
 * Only extracts valid fragment names (no alternations, nested parens, etc.)
 */
static void extract_fragment_refs(const char* pattern, 
                                   char (*refs)[64], int* ref_count, int max_refs) {
    *ref_count = 0;
    const char* p = pattern;
    
    while (*p && *ref_count < max_refs) {
        // Look for ((...))
        if (p[0] == '(' && p[1] == '(') {
            const char* start = p + 2;
            const char* end = strstr(start, "))");
            
            if (end) {
                // Extract the fragment name
                int len = end - start;
                if (is_valid_fragment_name(start, len)) {
                    strncpy(refs[*ref_count], start, len);
                    refs[*ref_count][len] = '\0';
                    (*ref_count)++;
                }
                p = end + 2;
            } else {
                p++;
            }
        } else {
            p++;
        }
    }
}

/**
 * Check if line is a fragment definition [fragment:name]
 */
static bool is_fragment_definition(const char* line, char* frag_name, int max_len) {
    if (strncmp(line, "[fragment:", 10) != 0) {
        return false;
    }
    
    const char* name_start = line + 10;
    const char* bracket = strchr(name_start, ']');
    
    if (!bracket) {
        return false;
    }
    
    int len = bracket - name_start;
    if (len >= max_len) {
        len = max_len - 1;
    }
    
    strncpy(frag_name, name_start, len);
    frag_name[len] = '\0';
    return true;
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
 * Check if pattern contains wildcards
 */
static bool has_wildcards(const char* pattern) {
    return strchr(pattern, '*') != NULL ||
           strchr(pattern, '+') != NULL ||
           strchr(pattern, '?') != NULL;
}

/**
 * Order patterns for optimal NFA construction
 * 
 * Also performs validation:
 * - Duplicate detection (warns and marks for removal)
 * - Fragment reference validation (returns -1 on error)
 */
int pattern_order_optimize(pattern_entry_t* patterns, int count, 
                           const pattern_order_options_t* options) {
    pattern_order_options_t opts = options ? *options : pattern_order_default_options();
    order_verbose = opts.verbose;
    
    last_stats = (pattern_order_stats_t){
        .original_count = count,
        .prefix_groups = 0,
        .patterns_reordered = 0,
        .duplicates_found = 0,
        .fragment_errors = 0,
        .avg_prefix_len = 0.0
    };
    
    if (count <= 1) return 0;
    
    VERBOSE_PRINT("Ordering %d patterns\n", count);
    
    // === PHASE 1: Collect fragment definitions ===
    fragment_table.count = 0;  // Reset fragment table
    for (int i = 0; i < count; i++) {
        char frag_name[64];
        if (is_fragment_definition(patterns[i].line, frag_name, sizeof(frag_name))) {
            register_fragment(frag_name);
            VERBOSE_PRINT("  Found fragment: %s\n", frag_name);
        }
    }
    
    // === PHASE 2: Validate fragment references ===
    for (int i = 0; i < count; i++) {
        char refs[32][64];
        int ref_count = 0;
        extract_fragment_refs(patterns[i].pattern, refs, &ref_count, 32);
        
        // Get namespace from pattern's category (e.g., "safe" from "[safe]")
        const char* namespace = patterns[i].category;
        
        for (int r = 0; r < ref_count; r++) {
            const char* frag_ref = refs[r];
            
            // Check if fragment exists:
            // - ((ns::name)) looks for "ns::name" directly
            // - ((name)) looks for "category::name" in the pattern's namespace
            if (!fragment_exists_in_ns(frag_ref, namespace ? namespace : "")) {
                fprintf(stderr, "ERROR: Pattern references undefined fragment '%s'", frag_ref);
                if (namespace && strstr(frag_ref, "::") == NULL) {
                    fprintf(stderr, " (looked for %s::%s)", namespace, frag_ref);
                }
                fprintf(stderr, ": %s\n", patterns[i].line);
                patterns[i].has_error = true;
                last_stats.fragment_errors++;
            }
        }
    }
    
    // If there are fragment errors, return -1
    if (last_stats.fragment_errors > 0) {
        return -1;
    }
    
    // === PHASE 3: Detect duplicates using full line ===
    trie_node_t* dup_trie = trie_create_node('\0', 0);
    int duplicates = 0;
    
    for (int i = 0; i < count; i++) {
        if (patterns[i].has_error) continue;
        
        // Use full line for duplicate detection (includes category)
        if (trie_insert_detect_dup(dup_trie, patterns[i].line, i)) {
            fprintf(stderr, "WARNING: Duplicate pattern detected:\n");
            fprintf(stderr, "  Duplicate: %s\n", patterns[i].line);
            fprintf(stderr, "  (duplicate will be removed)\n");
            
            patterns[i].is_duplicate = true;
            duplicates++;
        }
    }
    
    trie_free(dup_trie);
    last_stats.duplicates_found = duplicates;
    
    // === PHASE 4: Build ordering tries for each category ===
    int* new_order = malloc(count * sizeof(int));
    int new_count = 0;
    
    // Find unique categories
    char** categories = NULL;
    int cat_count = 0;
    int cat_capacity = 16;
    categories = malloc(cat_capacity * sizeof(char*));
    
    for (int i = 0; i < count; i++) {
        if (patterns[i].category && !patterns[i].is_duplicate && !patterns[i].has_error) {
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
            // Skip duplicates and errors
            if (patterns[i].is_duplicate || patterns[i].has_error) continue;
            
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
        
        // Insert non-wildcard patterns into trie (for ordering)
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
    for (int i = 0; i < new_count; i++) {
        if (new_order[i] != i) reordered++;
    }
    last_stats.patterns_reordered = reordered;
    
    // Reorder patterns array (excluding duplicates and errors)
    // We need to be careful about memory management to avoid double-free.
    // Strategy: Mark which source indices have been used, then do a single pass.
    bool* used = calloc(count, sizeof(bool));
    pattern_entry_t* temp = malloc(new_count * sizeof(pattern_entry_t));
    
    // Copy entries to temp
    for (int i = 0; i < new_count; i++) {
        temp[i] = patterns[new_order[i]];
        used[new_order[i]] = true;
    }
    
    // Free entries that are NOT in the new order (duplicates, errors, or dropped)
    for (int i = 0; i < count; i++) {
        if (!used[i]) {
            free(patterns[i].line);
            free(patterns[i].pattern);
            free(patterns[i].category);
            patterns[i].line = NULL;
            patterns[i].pattern = NULL;
            patterns[i].category = NULL;
        }
    }
    
    // Copy back
    for (int i = 0; i < new_count; i++) {
        patterns[i] = temp[i];
    }
    
    free(used);
    free(temp);
    free(new_order);
    
    VERBOSE_PRINT("Reordered %d/%d patterns (%d duplicates removed)\n", 
                  reordered, new_count, duplicates);
    
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
        
        // Skip empty lines
        if (len == 0) continue;
        
        // Check for directive lines (no leading #)
        const char* trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        
        // Skip pure comment lines (lines starting with #)
        if (trimmed[0] == '#') {
            continue;
        }
        
        // Skip section header lines (lines that are just [SECTION_NAME])
        if (trimmed[0] == '[' && strchr(trimmed, ']') == trimmed + strlen(trimmed) - 1) {
            // It's a section header like [fragment:...] - let it through
        }
        
        // Grow array if needed
        if (count >= capacity) {
            capacity *= 2;
            patterns = realloc(patterns, capacity * sizeof(pattern_entry_t));
        }
        
        // Parse line
        pattern_entry_t* pe = &patterns[count];
        pe->line = strdup(line);
        pe->original_index = count;
        pe->is_duplicate = false;
        pe->has_error = false;
        
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
        // Handle NULL pointers (from reordering)
        if (patterns[i].line) free(patterns[i].line);
        if (patterns[i].pattern) free(patterns[i].pattern);
        if (patterns[i].category) free(patterns[i].category);
    }
    free(patterns);
}
