#define _POSIX_C_SOURCE 200809L

#define DFA_ERROR_PROGRAM "nfa_builder"
#include "../include/dfa_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#include "nfa_builder.h"
#include "pattern_order.h"

// ============================================================================
// CLI code (main binary only)
// Context lifecycle and find_symbol_id are in nfa_builder_lib.c
// ============================================================================

#ifndef NFABUILDER_NO_MAIN

static bool flag_validate_only = false;
static bool flag_verbose_alphabet = false;
static bool flag_verbose_validation = false;
static const char* external_alphabet_file = NULL;

// ============================================================================
// Usage and argument parsing
// ============================================================================

static void print_usage(const char* progname) {
    fprintf(stderr, "Usage: %s [options] <spec_file> [output.nfa]\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Advanced NFA Builder with Integrated Validation and Alphabet Construction\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --validate-only       Only validate pattern file, don't build NFA\n");
    fprintf(stderr, "  --verbose              Enable verbose output\n");
    fprintf(stderr, "  --verbose-alphabet     Show alphabet construction details\n");
    fprintf(stderr, "  --verbose-validation   Show validation details\n");
    fprintf(stderr, "  --verbose-nfa          Show NFA building details\n");
    fprintf(stderr, "  --alphabet FILE        Use external alphabet file (optional)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If no external alphabet is provided, the builder constructs one automatically\n");
    fprintf(stderr, "from the pattern file.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s patterns_safe_commands.txt readonlybox.nfa\n", progname);
    fprintf(stderr, "  %s --validate-only patterns_safe_commands.txt\n", progname);
    fprintf(stderr, "  %s --verbose patterns_safe_commands.txt\n", progname);
}

static void parse_arguments(int argc, char* argv[], nfa_builder_context_t* ctx,
                            const char** spec_file, const char** output_file) {
    const char* progname = argv[0];

    flag_validate_only = false;
    flag_verbose_alphabet = false;
    flag_verbose_validation = false;
    external_alphabet_file = NULL;
    ctx->flag_verbose = false;
    ctx->flag_verbose_nfa = false;

    argc--;
    argv++;

    while (argc > 0) {
        if (strcmp(argv[0], "--validate-only") == 0) {
            flag_validate_only = true;
        } else if (strcmp(argv[0], "--verbose") == 0) {
            ctx->flag_verbose = true;
        } else if (strcmp(argv[0], "--verbose-alphabet") == 0) {
            flag_verbose_alphabet = true;
        } else if (strcmp(argv[0], "--verbose-validation") == 0) {
            flag_verbose_validation = true;
        } else if (strcmp(argv[0], "--verbose-nfa") == 0) {
            ctx->flag_verbose_nfa = true;
        } else if (strcmp(argv[0], "--alphabet") == 0) {
            if (argc < 2) {
                ERROR("--alphabet requires a filename");
                exit(EXIT_FAILURE);
            }
            external_alphabet_file = argv[1];
            argc--;
            argv++;
        } else if (argv[0][0] == '-') {
            ERROR("Unknown option '%s'", argv[0]);
            print_usage(progname);
            exit(EXIT_FAILURE);
        } else {
            break;
        }
        argc--;
        argv++;
    }

    if (argc < 1) {
        ERROR("No spec file provided");
        print_usage(progname);
        exit(EXIT_FAILURE);
    }

    *spec_file = argv[0];
    *output_file = argc > 1 ? argv[1] : "readonlybox.nfa";
}

// ============================================================================
// main() — orchestration
// ============================================================================

int main(int argc, char* argv[]) {
    const char* spec_file = NULL;
    const char* output_file = NULL;

    nfa_builder_context_t* ctx = nfa_builder_context_create();
    if (!ctx) {
        fprintf(stderr, "Failed to allocate builder context\n");
        return 1;
    }

    parse_arguments(argc, argv, ctx, &spec_file, &output_file);

    if (ctx->flag_verbose) {
        fprintf(stderr, "Advanced NFA Builder with Integrated Validation and Alphabet Construction\n");
        fprintf(stderr, "================================================================================\n\n");
    }

    // Validate-only mode
    if (flag_validate_only) {
        bool valid = nfa_validate_pattern_file(ctx, spec_file, flag_verbose_validation);
        nfa_builder_context_destroy(ctx);
        if (!valid) {
            fprintf(stderr, "Validation failed\n");
            return 1;
        }
        fprintf(stderr, "Validation passed\n");
        return 0;
    }

    // Always validate first
    if (!nfa_validate_pattern_file(ctx, spec_file, flag_verbose_validation)) {
        fprintf(stderr, "Pattern validation failed\n");
        nfa_builder_context_destroy(ctx);
        return 1;
    }

    // Read patterns into memory for ordering
    pattern_entry_t* ordered_patterns = NULL;
    int pattern_count = pattern_order_read_file(spec_file, &ordered_patterns);
    if (pattern_count < 0) {
        fprintf(stderr, "Failed to read patterns for ordering\n");
        nfa_builder_context_destroy(ctx);
        return 1;
    }

    // Apply pattern ordering optimization
    if (pattern_count > 1) {
        pattern_order_options_t order_opts = pattern_order_default_options();
        order_opts.verbose = ctx->flag_verbose;
        int reordered = pattern_order_optimize(ordered_patterns, pattern_count, &order_opts);

        if (reordered < 0) {
            fprintf(stderr, "Pattern validation failed (see errors above)\n");
            pattern_order_free(ordered_patterns, pattern_count);
            nfa_builder_context_destroy(ctx);
            return 1;
        }

        if (ctx->flag_verbose && reordered > 0) {
            fprintf(stderr, "Pattern ordering: reordered %d/%d patterns\n", reordered, pattern_count);
        }

        pattern_order_stats_t stats;
        pattern_order_get_stats(&stats);
        pattern_count = stats.original_count - stats.duplicates_found;
    }

    // Build alphabet (CLI: use external alphabet file if provided, otherwise use library function)
    if (external_alphabet_file) {
        nfa_alphabet_load(ctx, external_alphabet_file);
    } else {
        nfa_alphabet_construct_from_patterns(ctx, spec_file);
    }

    // Initialize NFA
    nfa_construct_init(ctx);
    ctx->current_input_file = spec_file;

    // Build NFA from reordered patterns
    int patterns_added = 0;
    for (int i = 0; i < pattern_count; i++) {
        if (!ordered_patterns[i].is_duplicate && !ordered_patterns[i].has_error) {
            nfa_parser_parse_pattern(ctx, ordered_patterns[i].line);
            patterns_added++;
        }
    }

    if (ctx->flag_verbose) {
        fprintf(stderr, "Read %d patterns from %s (%d duplicates removed)\n",
                patterns_added, spec_file, pattern_count - patterns_added);
    }

    // Write NFA output
    nfa_construct_write_file(ctx, output_file);

    // Cleanup
    nfa_construct_cleanup(ctx);
    pattern_order_free(ordered_patterns, pattern_count);

    if (ctx->flag_verbose) {
        fprintf(stderr, "\nDone!\n");
        fprintf(stderr, "Next step: Run nfa2dfa_with_alphabet to convert NFA to DFA\n");
        fprintf(stderr, "  nfa2dfa_with_alphabet %s readonlybox.dfa\n", output_file);
    }

    nfa_builder_context_destroy(ctx);
    return 0;
}

#endif // NFABUILDER_NO_MAIN
