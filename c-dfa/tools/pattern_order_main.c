/**
 * Pattern Ordering Tool
 * 
 * Reorders patterns in a file to minimize NFA/DFA states.
 * 
 * Usage: pattern_order input.txt output.txt [--verbose]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pattern_order.h"

int main(int argc, char* argv[]) {
    bool verbose = false;
    const char* input_file = NULL;
    const char* output_file = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        } else if (input_file == NULL) {
            input_file = argv[i];
        } else if (output_file == NULL) {
            output_file = argv[i];
        }
    }
    
    if (input_file == NULL) {
        fprintf(stderr, "Usage: %s input.txt [output.txt] [--verbose]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Reorders patterns to minimize NFA/DFA states.\n");
        fprintf(stderr, "If output file is not specified, prints to stdout.\n");
        return 1;
    }
    
    // Read patterns
    pattern_entry_t* patterns = NULL;
    int count = pattern_order_read_file(input_file, &patterns);
    if (count < 0) {
        fprintf(stderr, "Error reading %s\n", input_file);
        return 1;
    }
    
    fprintf(stderr, "Read %d patterns from %s\n", count, input_file);
    
    // Order patterns
    pattern_order_options_t opts = pattern_order_default_options();
    opts.verbose = verbose;
    
    int reordered = pattern_order_optimize(patterns, count, &opts);
    
    // Get statistics
    pattern_order_stats_t stats;
    pattern_order_get_stats(&stats);
    
    fprintf(stderr, "Reordered %d/%d patterns\n", stats.patterns_reordered, count);
    fprintf(stderr, "Found %d prefix groups\n", stats.prefix_groups);
    
    // Write output
    if (output_file) {
        if (pattern_order_write_file(output_file, patterns, count) < 0) {
            fprintf(stderr, "Error writing %s\n", output_file);
            pattern_order_free(patterns, count);
            return 1;
        }
        fprintf(stderr, "Wrote %s\n", output_file);
    } else {
        // Print to stdout
        for (int i = 0; i < count; i++) {
            printf("%s\n", patterns[i].line);
        }
    }
    
    pattern_order_free(patterns, count);
    return 0;
}
