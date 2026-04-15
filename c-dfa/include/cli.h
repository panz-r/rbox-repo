/**
 * cli.h - Unified DFA CLI Tool
 *
 * Single command-line tool for all DFA operations:
 *   validate <pattern-file>
 *   compile [options] input -o output
 *   embedd <dfa-file> -o <output.c>
 *   eval <dfa-file> [-i <input>]
 */

#ifndef CLI_H
#define CLI_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Command Types
// ============================================================================

typedef enum {
    CMD_VALIDATE,
    CMD_COMPILE,
    CMD_EMBEDD,
    CMD_VERIFY,
    CMD_EVAL,
    CMD_HELP,
    CMD_NONE
} cli_cmd_t;

// ============================================================================
// Output Types
// ============================================================================

typedef enum {
    OUTPUT_AUTO,   // Infer from file extension
    OUTPUT_DFA,
    OUTPUT_C
} output_type_t;

// ============================================================================
// CLI Arguments
// ============================================================================

typedef struct {
    cli_cmd_t cmd;

    // Global options
    int verbosity;
    bool quiet;           // -q, --quiet - suppress stderr
    bool json_output;     // -j, --json - JSON output
    bool force;           // -f, --force - overwrite output file
    bool stats;           // --stats - show statistics

    // validate command
    const char* validate_pattern;

    // compile command
    const char* compile_input;
    const char* compile_output;
    output_type_t output_type;
    bool output_type_set;         // true if -t was explicitly used
    const char* minimize_algo;    // "hopcroft" (default), "moore", "brzozowski"
    bool minimize;
    bool no_minimize;
    bool preminimize;
    bool no_preminimize;
    bool compress;
    bool no_compress;
    bool compress_sat;
    bool preminimize_sat;
    bool sat_optimal;
    const char* alphabet_file;
    bool validate_only;

    // embedd command
    const char* embedd_input;
    const char* embedd_output;

    // verify command
    const char* verify_dfa;

    // eval command
    const char* eval_dfa;
    const char* eval_input;      // NULL means stdin
    bool eval_category;
    bool eval_capture;
} cli_args_t;

// ============================================================================
// CLI Functions
// ============================================================================

/**
 * Parse command-line arguments.
 * Returns true on success, false on error.
 * On error, prints usage to stderr.
 */
bool cli_parse_args(int argc, char* argv[], cli_args_t* args);

/**
 * Execute the command specified in args.
 * Returns exit code (0 = success, 1 = error, 2 = usage error).
 */
int cli_run(const cli_args_t* args);

/**
 * Print global usage help.
 */
void cli_usage(const char* progname);

/**
 * Print help for a specific command.
 */
void cli_help_for(const char* progname, cli_cmd_t cmd);

/**
 * Get version string.
 */
const char* cli_version(void);

#ifdef __cplusplus
}
#endif

#endif // CLI_H