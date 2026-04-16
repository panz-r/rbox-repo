/**
 * dfa_cli.c - Unified DFA CLI Tool
 *
 * Single command-line tool for all DFA operations:
 *   validate <pattern-file>
 *   compile [options] input -o output
 *   embedd <dfa-file> -o <output.c>
 *   eval <dfa-file> [-i <input>]
 */

#define _POSIX_C_SOURCE 200809L
#define DFA_ERROR_PROGRAM "cdfatool"

#include "cli.h"
#include "dfa_errors.h"
#include "../include/pipeline.h"
#include "../include/dfa.h"
#include "../include/dfa_types.h"
#include "../include/dfa_format.h"
#include "../include/cdfa_defines.h"
#include "../include/nfa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

// ============================================================================
// Version
// ============================================================================

static const char* cli_version_str = "1.0.0";

const char* cli_version(void) {
    return cli_version_str;
}

// ============================================================================
// Usage Help
// ============================================================================

static void print_version(void) {
    fprintf(stderr, "cdfatool version %s\n", cli_version());
}

static void print_global_usage(const char* progname) {
    fprintf(stderr, "Usage: %s <command> [options]\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  validate <pattern-file>     Validate pattern file syntax\n");
    fprintf(stderr, "  compile [options] input -o output  Compile patterns to DFA binary\n");
    fprintf(stderr, "  embedd <dfa-file> -o <output.c>  Embed DFA binary as C array\n");
    fprintf(stderr, "  verify <dfa-file>             Verify DFA binary integrity\n");
    fprintf(stderr, "  eval <dfa-file> [-i <input>]  Evaluate input against DFA\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Global options:\n");
    fprintf(stderr, "  -h, --help        Show help\n");
    fprintf(stderr, "  --version         Show version information\n");
    fprintf(stderr, "  -v                Enable verbose output\n");
    fprintf(stderr, "  -vv               Enable very verbose debug output\n");
    fprintf(stderr, "  -q, --quiet       Suppress stderr output\n");
    fprintf(stderr, "  -j, --json        JSON output\n");
    fprintf(stderr, "  -f, --force       Overwrite output file if it exists\n");
    fprintf(stderr, "  --stats           Show statistics (CSV format, or JSON if -j)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Run '%s help <command>' for command-specific help.\n", progname);
}

void cli_usage(const char* progname) {
    print_global_usage(progname);
}

static void print_validate_help(const char* progname) {
    fprintf(stderr, "\nUsage: %s validate <pattern-file>\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Validate pattern file syntax.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  pattern-file              Pattern file to validate (required)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Exit codes:\n");
    fprintf(stderr, "  0 = valid\n");
    fprintf(stderr, "  1 = invalid\n");
    fprintf(stderr, "  2 = usage error\n");
}

static void print_compile_help(const char* progname) {
    fprintf(stderr, "\nUsage: %s compile [options] input -o output\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Compile pattern file to DFA binary.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  input                     Input pattern file (required)\n");
    fprintf(stderr, "  -o, --output <file>      Output file (required)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --minimize=<algo>        Minimization algorithm\n");
    fprintf(stderr, "                           Values: hopcroft (default), moore, brzozowski\n");
    fprintf(stderr, "  --no-minimize            Skip minimization\n");
    fprintf(stderr, "  --preminimize            Enable pre-minimization (default: on)\n");
    fprintf(stderr, "  --no-preminimize         Disable pre-minimization\n");
    fprintf(stderr, "  --compress                Enable compression (default: on)\n");
    fprintf(stderr, "  --no-compress            Skip compression\n");
    fprintf(stderr, "  --compress-sat           Use SAT solver for compression\n");
    fprintf(stderr, "  --preminimize-sat        Use SAT solver for pre-minimization\n");
    fprintf(stderr, "  --sat-optimal            Use SAT-based optimal pre-minimization\n");
    fprintf(stderr, "  --alphabet=<file>        Use external alphabet file\n");
    fprintf(stderr, "  --validate-only          Only validate patterns (don't compile)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Exit codes:\n");
    fprintf(stderr, "  0 = success\n");
    fprintf(stderr, "  1 = error\n");
    fprintf(stderr, "  2 = usage error\n");
}

static void print_embedd_help(const char* progname) {
    fprintf(stderr, "\nUsage: %s embedd <dfa-file> -o <output.c>\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Embed DFA binary file as a C array in a header file.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  dfa-file                     DFA binary file (required)\n");
    fprintf(stderr, "  -o, --output <file>        Output C file (required)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -v                          Verbose output\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Exit codes:\n");
    fprintf(stderr, "  0 = success\n");
    fprintf(stderr, "  1 = error\n");
    fprintf(stderr, "  2 = usage error\n");
}

static void print_verify_help(const char* progname) {
    fprintf(stderr, "\nUsage: %s verify <dfa-file>\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Verify the integrity of a DFA binary file.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  dfa-file                     DFA binary file (required)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Checks performed:\n");
    fprintf(stderr, "  - Magic number validation\n");
    fprintf(stderr, "  - Version validation\n");
    fprintf(stderr, "  - CRC32-C checksum verification\n");
    fprintf(stderr, "  - FNV-1a checksum verification\n");
    fprintf(stderr, "  - Header structure validation\n");
    fprintf(stderr, "  - State count and offset validation\n");
    fprintf(stderr, "  - Section offset validation\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Exit codes:\n");
    fprintf(stderr, "  0 = valid\n");
    fprintf(stderr, "  1 = invalid or corrupted\n");
    fprintf(stderr, "  2 = usage error\n");
}

static void print_eval_help(const char* progname) {
    fprintf(stderr, "\nUsage: %s eval <dfa-file> [-i <input>]\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Evaluate input strings against a compiled DFA.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  dfa-file                     Compiled DFA file (required)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i, --input <file>          Input file (default: stdin, one string per line)\n");
    fprintf(stderr, "  -c, --category              Show category for each match\n");
    fprintf(stderr, "  --capture                   Show capture groups\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Output format (per input line):\n");
    fprintf(stderr, "  matched=<0|1> category=<N> (<name>) category_mask=0x<MM> [captures]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Exit codes:\n");
    fprintf(stderr, "  0 = success\n");
    fprintf(stderr, "  1 = error\n");
    fprintf(stderr, "  2 = usage error\n");
}

void cli_help_for(const char* progname, cli_cmd_t cmd) {
    switch (cmd) {
        case CMD_VALIDATE:
            print_validate_help(progname);
            break;
        case CMD_COMPILE:
            print_compile_help(progname);
            break;
        case CMD_EMBEDD:
            print_embedd_help(progname);
            break;
        case CMD_VERIFY:
            print_verify_help(progname);
            break;
        case CMD_EVAL:
            print_eval_help(progname);
            break;
        case CMD_HELP:
            print_global_usage(progname);
            fprintf(stderr, "\nRun '%s help <command>' for command-specific help.\n", progname);
            break;
        default:
            print_global_usage(progname);
            break;
    }
}

// ============================================================================
// Input/Output Type Inference
// ============================================================================

static bool is_pattern_file(const char* filename) {
    if (!filename) return false;
    size_t len = strlen(filename);
    if (len > 4) {
        const char* ext = filename + len - 4;
        if (strcmp(ext, ".txt") == 0) return true;
        if (strcmp(ext, ".cap") == 0) return true;
        if (strcmp(ext, ".spec") == 0) return true;
        if (strcmp(ext, ".pat") == 0) return true;
    }
    return false;
}

// ============================================================================
// JSON Output Helpers (no external dependencies)
// ============================================================================

static void json_escape_string(FILE* out, const char* str) {
    fputc('"', out);
    for (const char* p = str; *p; p++) {
        if (*p == '"') fprintf(out, "\\\"");
        else if (*p == '\\') fprintf(out, "\\\\");
        else if (*p == '\n') fprintf(out, "\\n");
        else if (*p == '\r') fprintf(out, "\\r");
        else if (*p == '\t') fprintf(out, "\\t");
        else fputc(*p, out);
    }
    fputc('"', out);
}

static void json_start_object(FILE* out) {
    fputc('{', out);
}

static void json_end_object(FILE* out) {
    fputc('}', out);
}

static void json_start_array(FILE* out) {
    fputc('[', out);
}

static void json_end_array(FILE* out) {
    fputc(']', out);
}

static void json_comma(FILE* out) {
    fputc(',', out);
}

static void json_key_value_int(FILE* out, const char* key, long long value) {
    fprintf(out, "\"%s\":%lld", key, value);
}

static void json_key_value_uint(FILE* out, const char* key, unsigned long long value) {
    fprintf(out, "\"%s\":%llu", key, value);
}

static void json_key_value_bool(FILE* out, const char* key, bool value) {
    fprintf(out, "\"%s\":%s", key, value ? "true" : "false");
}

static void json_key_value_str(FILE* out, const char* key, const char* value) {
    fprintf(out, "\"%s\":", key);
    json_escape_string(out, value);
}

// CSV stats output
static void csv_stats_header(FILE* out) {
    fprintf(out, "command,status,input,output,size,states,premin_removed,min_removed,min_iterations,time_ms\n");
}

static void csv_stats_row(FILE* out, const char* cmd, const char* status, 
                          const char* input, const char* output,
                          size_t size, int states, int premin_removed, 
                          int min_removed, int min_iterations, long time_ms) {
    fprintf(out, "%s,%s,%s,%s,%zu,%d,%d,%d,%d,%ld\n", 
            cmd, status, input, output, size, states, 
            premin_removed, min_removed, min_iterations, time_ms);
}

// CPU time tracking helper
#include <sys/resource.h>

typedef struct {
    long user_ms;
    long sys_ms;
} cpu_time_t;

static void get_cpu_time(cpu_time_t* t) {
    struct rusage u;
    if (getrusage(RUSAGE_SELF, &u) == 0) {
        t->user_ms = u.ru_utime.tv_sec * 1000 + u.ru_utime.tv_usec / 1000;
        t->sys_ms = u.ru_stime.tv_sec * 1000 + u.ru_stime.tv_usec / 1000;
    } else {
        t->user_ms = 0;
        t->sys_ms = 0;
    }
}

static long time_diff_ms(cpu_time_t* start, cpu_time_t* end) {
    return (end->user_ms + end->sys_ms) - (start->user_ms + start->sys_ms);
}

// ============================================================================
// Argument Parsing - Option Detection
// ============================================================================

static bool is_option(const char* arg) {
    if (arg[0] != '-') return false;
    if (arg[1] == '-') return true;  // long option
    if (arg[1] >= 'a' && arg[1] <= 'z') return true;  // short option
    return false;
}

static bool is_flag_with_value(const char* arg) {
    return strcmp(arg, "-t") == 0 || strcmp(arg, "--type") == 0 ||
           strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0 ||
           strcmp(arg, "-i") == 0 || strcmp(arg, "--input") == 0;
}

// ============================================================================
// Argument Parsing
// ============================================================================

static void init_args(cli_args_t* args) {
    memset(args, 0, sizeof(*args));
    args->cmd = CMD_NONE;
    args->minimize = true;
    args->preminimize = true;
    args->compress = true;
    args->minimize_algo = "hopcroft";
    args->output_type = OUTPUT_DFA;
    args->quiet = false;
    args->json_output = false;
    args->force = false;
    args->stats = false;
}

static void init_compile_args(cli_args_t* args) {
    args->minimize = true;
    args->preminimize = true;
    args->compress = true;
    args->minimize_algo = "hopcroft";
}

bool cli_parse_args(int argc, char* argv[], cli_args_t* args) {
    init_args(args);

    if (argc < 2) {
        print_global_usage(argv[0]);
        return false;
    }

    const char* progname = argv[0];
    int i = 1;

    // Parse global options first
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            args->cmd = CMD_HELP;
            return true;
        } else if (strcmp(argv[i], "--version") == 0) {
            print_version();
            return false;  // Exit immediately
        } else if (strcmp(argv[i], "-v") == 0) {
            args->verbosity = 1;
            i++;
        } else if (strcmp(argv[i], "-vv") == 0) {
            args->verbosity = 2;
            i++;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            args->quiet = true;
            i++;
        } else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            args->json_output = true;
            i++;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            args->force = true;
            i++;
        } else if (strcmp(argv[i], "--stats") == 0) {
            args->stats = true;
            i++;
        } else if (strcmp(argv[i], "help") == 0) {
            args->cmd = CMD_HELP;
            return true;
        } else {
            break;  // Not a global option, must be command
        }
    }

    // Parse command
    if (i >= argc) {
        print_global_usage(progname);
        return false;
    }

    if (strcmp(argv[i], "help") == 0) {
        args->cmd = CMD_HELP;
        return true;
    }

    if (strcmp(argv[i], "validate") == 0) {
        args->cmd = CMD_VALIDATE;
        i++;

        // Parse options before pattern file
        while (i < argc && argv[i][0] == '-') {
            const char* arg = argv[i];

            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_validate_help(progname);
                return false;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                i++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                i++;
                continue;
            }

            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                args->quiet = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0) {
                args->json_output = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
                args->force = true;
                i++;
                continue;
            }

            if (strcmp(arg, "--stats") == 0) {
                args->stats = true;
                i++;
                continue;
            }

            // If it's not a known option, it must be the pattern file
            break;
        }

        if (i >= argc) {
            fprintf(stderr, "Error: 'validate' requires a pattern file argument\n");
            print_validate_help(progname);
            return false;
        }
        if (!is_pattern_file(argv[i])) {
            fprintf(stderr, "Error: '%s' does not look like a pattern file\n", argv[i]);
            return false;
        }
        args->validate_pattern = argv[i];
        i++;

        // Parse options after pattern file
        while (i < argc && argv[i][0] == '-') {
            const char* arg = argv[i];

            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_validate_help(progname);
                return false;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                i++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                i++;
                continue;
            }

            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                args->quiet = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0) {
                args->json_output = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
                args->force = true;
                i++;
                continue;
            }

            if (strcmp(arg, "--stats") == 0) {
                args->stats = true;
                i++;
                continue;
            }

            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            print_validate_help(progname);
            return false;
        }

        return true;
    }

    if (strcmp(argv[i], "compile") == 0) {
        args->cmd = CMD_COMPILE;
        init_compile_args(args);
        i++;

        // First pass: find the input file (first non-option positional)
        int first_positional = -1;
        int j = i;
        while (j < argc) {
            const char* arg = argv[j];
            
            // Check for help flags anywhere - print command-specific help and exit
            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_compile_help(progname);
                return false;  // Return false to indicate help was shown
            }
            
            if (is_option(arg)) {
                if (is_flag_with_value(arg)) {
                    j += 2;
                } else {
                    j++;
                }
            } else {
                first_positional = j;
                break;
            }
        }

        if (first_positional == -1) {
            fprintf(stderr, "Error: 'compile' requires an input file\n");
            print_compile_help(progname);
            return false;
        }
        
        args->compile_input = argv[first_positional];

        if (!is_pattern_file(args->compile_input)) {
            fprintf(stderr, "Error: '%s' is not a pattern file (must be .txt, .cap, .spec, or .pat)\n", 
                    args->compile_input);
            return false;
        }

        // Parse options before input
        for (int k = i; k < first_positional; ) {
            const char* arg = argv[k];

            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_compile_help(progname);
                return false;  // Exit after showing help
            }

            if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
                if (k + 1 >= argc || is_option(argv[k + 1])) {
                    fprintf(stderr, "Error: %s requires an argument\n", arg);
                    return false;
                }
                args->compile_output = argv[k + 1];
                k += 2;
                continue;
            }

            if (strncmp(arg, "--minimize=", 11) == 0) {
                args->minimize = true;
                args->no_minimize = false;
                const char* algo = arg + 11;
                if (strcmp(algo, "hopcroft") == 0) {
                    args->minimize_algo = "hopcroft";
                } else if (strcmp(algo, "moore") == 0) {
                    args->minimize_algo = "moore";
                } else if (strcmp(algo, "brzozowski") == 0) {
                    args->minimize_algo = "brzozowski";
                } else {
                    fprintf(stderr, "Error: --minimize must be: hopcroft, moore, or brzozowski\n");
                    return false;
                }
                k++;
                continue;
            }

            if (strcmp(arg, "--no-minimize") == 0) {
                args->minimize = false;
                args->no_minimize = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--preminimize") == 0) {
                args->preminimize = true;
                args->no_preminimize = false;
                k++;
                continue;
            }

            if (strcmp(arg, "--no-preminimize") == 0) {
                args->preminimize = false;
                args->no_preminimize = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--compress") == 0) {
                args->compress = true;
                args->no_compress = false;
                k++;
                continue;
            }

            if (strcmp(arg, "--no-compress") == 0) {
                args->compress = false;
                args->no_compress = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--compress-sat") == 0) {
                args->compress_sat = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--preminimize-sat") == 0) {
                args->preminimize_sat = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--sat-optimal") == 0) {
                args->sat_optimal = true;
                k++;
                continue;
            }

            if (strncmp(arg, "--alphabet=", 12) == 0) {
                args->alphabet_file = arg + 12;
                k++;
                continue;
            }

            if (strcmp(arg, "--validate-only") == 0) {
                args->validate_only = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                k++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                k++;
                continue;
            }

            if (strcmp(arg, "-t") == 0 || strcmp(arg, "--type") == 0) {
                fprintf(stderr, "Error: -t/--type option is no longer supported\n");
                k += 2;
                continue;
            }

            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            print_compile_help(progname);
            return false;
        }

        // Parse options after input
        for (int k = first_positional + 1; k < argc; ) {
            const char* arg = argv[k];

            if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
                if (k + 1 >= argc || is_option(argv[k + 1])) {
                    fprintf(stderr, "Error: %s requires an argument\n", arg);
                    return false;
                }
                args->compile_output = argv[k + 1];
                k += 2;
                continue;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                k++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                k++;
                continue;
            }

            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                args->quiet = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0) {
                args->json_output = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
                args->force = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--stats") == 0) {
                args->stats = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-t") == 0 || strcmp(arg, "--type") == 0) {
                fprintf(stderr, "Error: -t/--type option is no longer supported\n");
                k += 2;
                continue;
            }

            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            print_compile_help(progname);
            return false;
        }

        if (!args->compile_output) {
            fprintf(stderr, "Error: 'compile' requires -o output\n");
            print_compile_help(progname);
            return false;
        }

        return true;
    }

    if (strcmp(argv[i], "embedd") == 0) {
        args->cmd = CMD_EMBEDD;
        i++;

        // Parse options before positional
        while (i < argc && argv[i][0] == '-') {
            const char* arg = argv[i];

            if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Error: %s requires an argument\n", arg);
                    print_embedd_help(progname);
                    return false;
                }
                i++;
                args->embedd_output = argv[i];
                i++;
                continue;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                i++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                i++;
                continue;
            }

            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                args->quiet = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0) {
                args->json_output = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
                args->force = true;
                i++;
                continue;
            }

            if (strcmp(arg, "--stats") == 0) {
                args->stats = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_eval_help(progname);
                return false;
            }

            if (strcmp(arg, "-i") == 0 || strcmp(arg, "--input") == 0) {
                fprintf(stderr, "Error: embedd does not use -i for input file\n");
                return false;
            }

            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            print_embedd_help(progname);
            return false;
        }

        // Remaining positional is the DFA file
        if (i >= argc) {
            fprintf(stderr, "Error: 'embedd' requires a DFA file\n");
            print_embedd_help(progname);
            return false;
        }
        args->embedd_input = argv[i];
        i++;

        // Parse remaining options (should be none, but handle -o if not already set)
        while (i < argc) {
            const char* arg = argv[i];

            if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "Error: %s requires an argument\n", arg);
                    return false;
                }
                i++;
                args->embedd_output = argv[i];
                i++;
                continue;
            }

            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_embedd_help(progname);
                return false;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                i++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                i++;
                continue;
            }

            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                args->quiet = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0) {
                args->json_output = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
                args->force = true;
                i++;
                continue;
            }

            if (strcmp(arg, "--stats") == 0) {
                args->stats = true;
                i++;
                continue;
            }

            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            print_embedd_help(progname);
            return false;
        }

        if (!args->embedd_output) {
            fprintf(stderr, "Error: 'embedd' requires -o output\n");
            print_embedd_help(progname);
            return false;
        }

        return true;
    }

    if (strcmp(argv[i], "verify") == 0) {
        args->cmd = CMD_VERIFY;
        i++;

        // Parse options
        while (i < argc && argv[i][0] == '-') {
            const char* arg = argv[i];

            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_verify_help(progname);
                return false;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                i++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                i++;
                continue;
            }

            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                args->quiet = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0) {
                args->json_output = true;
                i++;
                continue;
            }

            if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
                args->force = true;
                i++;
                continue;
            }

            if (strcmp(arg, "--stats") == 0) {
                args->stats = true;
                i++;
                continue;
            }

            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            print_verify_help(progname);
            return false;
        }

        // Remaining positional is the DFA file
        if (i >= argc) {
            fprintf(stderr, "Error: 'verify' requires a DFA file\n");
            print_verify_help(progname);
            return false;
        }
        args->verify_dfa = argv[i];

        return true;
    }

    if (strcmp(argv[i], "eval") == 0) {
        args->cmd = CMD_EVAL;
        i++;

        // Collect all arguments
        int first_positional = -1;
        int j = i;
        while (j < argc) {
            const char* arg = argv[j];

            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_eval_help(progname);
                return false;
            }

            if (is_option(arg)) {
                if (is_flag_with_value(arg)) {
                    j += 2;
                } else {
                    j++;
                }
            } else {
                first_positional = j;
                break;
            }
        }

        if (first_positional == -1 || first_positional >= argc) {
            fprintf(stderr, "Error: 'eval' requires a DFA file\n");
            print_eval_help(progname);
            return false;
        }
        args->eval_dfa = argv[first_positional];

        // Parse options before dfa file
        for (int k = i; k < first_positional; ) {
            const char* arg = argv[k];

            if (strcmp(arg, "-i") == 0 || strcmp(arg, "--input") == 0) {
                if (k + 1 >= argc || is_option(argv[k + 1])) {
                    fprintf(stderr, "Error: %s requires an argument\n", arg);
                    return false;
                }
                args->eval_input = argv[k + 1];
                k += 2;
                continue;
            }

            if (strcmp(arg, "-c") == 0 || strcmp(arg, "--category") == 0) {
                args->eval_category = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--capture") == 0) {
                args->eval_capture = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                k++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                k++;
                continue;
            }

            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                args->quiet = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0) {
                args->json_output = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
                args->force = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--stats") == 0) {
                args->stats = true;
                k++;
                continue;
            }

            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            print_eval_help(progname);
            return false;
        }

        // Parse options after dfa file
        for (int k = first_positional + 1; k < argc; ) {
            const char* arg = argv[k];

            if (strcmp(arg, "-i") == 0 || strcmp(arg, "--input") == 0) {
                if (k + 1 >= argc || is_option(argv[k + 1])) {
                    fprintf(stderr, "Error: %s requires an argument\n", arg);
                    return false;
                }
                args->eval_input = argv[k + 1];
                k += 2;
                continue;
            }

            if (strcmp(arg, "-c") == 0 || strcmp(arg, "--category") == 0) {
                args->eval_category = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--capture") == 0) {
                args->eval_capture = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-v") == 0) {
                args->verbosity = 1;
                k++;
                continue;
            }

            if (strcmp(arg, "-vv") == 0) {
                args->verbosity = 2;
                k++;
                continue;
            }

            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                args->quiet = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0) {
                args->json_output = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
                args->force = true;
                k++;
                continue;
            }

            if (strcmp(arg, "--stats") == 0) {
                args->stats = true;
                k++;
                continue;
            }

            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                print_eval_help(progname);
                return false;
            }

            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            print_eval_help(progname);
            return false;
        }

        return true;
    }

    fprintf(stderr, "Error: unknown command '%s'\n", argv[i]);
    print_global_usage(progname);
    return false;
}

// ============================================================================
// Validate Command
// ============================================================================

int cli_validate(const cli_args_t* args) {
    if (!args->validate_pattern) {
        fprintf(stderr, "Error: no pattern file specified\n");
        return 2;
    }

    if (!args->quiet && args->verbosity > 0) {
        fprintf(stderr, "Validating pattern file: %s\n", args->validate_pattern);
    }

    cpu_time_t start = {0, 0}, end = {0, 0};
    get_cpu_time(&start);

    pipeline_config_t config = {
        .verbose = false,
    };

    pipeline_t* p = pipeline_create(&config);
    if (!p) {
        get_cpu_time(&end);
        long elapsed = time_diff_ms(&start, &end);
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "validate");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "failed to create pipeline");
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->validate_pattern);
            json_comma(stdout);
            json_key_value_int(stdout, "time_ms", elapsed);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else {
            fprintf(stderr, "Error: failed to create pipeline\n");
        }
        return 1;
    }

    pipeline_error_t err = pipeline_parse_patterns(p, args->validate_pattern);
    get_cpu_time(&end);
    long elapsed = time_diff_ms(&start, &end);

    if (err != PIPELINE_OK) {
        const char* err_msg = pipeline_get_last_error(p);
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "validate");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", err_msg ? err_msg : pipeline_error_string(err));
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->validate_pattern);
            json_comma(stdout);
            json_key_value_int(stdout, "time_ms", elapsed);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            if (args->verbosity > 0) {
                fprintf(stderr, "Validation failed: %s\n", err_msg ? err_msg : pipeline_error_string(err));
            } else {
                fprintf(stderr, "Error: pattern file is invalid\n");
            }
        }
        pipeline_destroy(p);
        return 1;
    }

    pipeline_destroy(p);

    if (args->json_output) {
        json_start_object(stdout);
        json_key_value_str(stdout, "command", "validate");
        json_comma(stdout);
        json_key_value_bool(stdout, "success", true);
        json_comma(stdout);
        json_key_value_str(stdout, "input", args->validate_pattern);
        json_comma(stdout);
        json_key_value_int(stdout, "time_ms", elapsed);
        json_end_object(stdout);
        fputc('\n', stdout);
        fflush(stdout);
    } else if (!args->quiet && args->verbosity > 0) {
        fprintf(stderr, "Pattern file is valid\n");
    }

    return 0;
}

// ============================================================================
// Compile Command
// ============================================================================

static int get_minimize_algo(const char* name) {
    if (strcmp(name, "moore") == 0) return PIPELINE_MIN_MOORE;
    if (strcmp(name, "brzozowski") == 0) return PIPELINE_MIN_BRZOZOWSKI;
    return PIPELINE_MIN_HOPCROFT;
}

static bool check_output_exists(const char* output) {
    if (!output) return false;
    FILE* f = fopen(output, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

int cli_compile(const cli_args_t* args) {
    if (!args->compile_input) {
        fprintf(stderr, "Error: no input file specified\n");
        return 2;
    }

    if (!args->compile_output) {
        fprintf(stderr, "Error: no output file specified\n");
        return 2;
    }

    if (!args->quiet) {
        if (args->verbosity > 0) {
            fprintf(stderr, "Compiling: %s → %s\n", args->compile_input, args->compile_output);
            fprintf(stderr, "  Minimization: %s\n", args->no_minimize ? "off" : args->minimize_algo);
            fprintf(stderr, "  Pre-minimization: %s\n", args->no_preminimize ? "off" : (args->preminimize_sat ? "SAT" : "on"));
            fprintf(stderr, "  Compression: %s\n", args->no_compress ? "off" : (args->compress_sat ? "SAT" : "on"));
        }
    }

    if (!args->force && check_output_exists(args->compile_output)) {
        fprintf(stderr, "Error: output file '%s' already exists (will not overwrite)\n", 
                args->compile_output);
        return 1;
    }

    cpu_time_t start = {0, 0}, end = {0, 0};
    long elapsed = 0;
    get_cpu_time(&start);

    pipeline_config_t config = {
        .verbose = !args->quiet && args->verbosity > 0,
        .preminimize = args->preminimize && !args->no_preminimize,
        .use_sat_compress = args->compress_sat,
        .enable_sat_optimal_premin = args->sat_optimal,
    };

    if (args->minimize && !args->no_minimize) {
        config.minimize_algo = get_minimize_algo(args->minimize_algo);
        config.optimize_layout = true;
    } else {
        config.minimize_algo = 0;
        config.optimize_layout = false;
    }

    if (args->compress && !args->no_compress) {
        config.compress = true;
    } else {
        config.compress = false;
    }

    pipeline_t* p = pipeline_create(&config);
    if (!p) {
        get_cpu_time(&end);
        elapsed = time_diff_ms(&start, &end);
        fprintf(stderr, "Error: failed to create pipeline\n");
        return 1;
    }

    pipeline_error_t err = pipeline_run(p, args->compile_input);
    if (err != PIPELINE_OK) {
        get_cpu_time(&end);
        elapsed = time_diff_ms(&start, &end);
        const char* err_msg = pipeline_get_last_error(p);
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "compile");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", err_msg ? err_msg : pipeline_error_string(err));
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->compile_input);
            json_comma(stdout);
            json_key_value_str(stdout, "output", args->compile_output);
            json_comma(stdout);
            json_key_value_int(stdout, "time_ms", elapsed);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: compilation failed: %s\n",
                    err_msg ? err_msg : pipeline_error_string(err));
        }
        pipeline_destroy(p);
        return 1;
    }

    if (args->validate_only) {
        get_cpu_time(&end);
        elapsed = time_diff_ms(&start, &end);
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "compile");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", true);
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->compile_input);
            json_comma(stdout);
            json_key_value_str(stdout, "output", args->compile_output);
            json_comma(stdout);
            json_key_value_bool(stdout, "validated_only", true);
            json_comma(stdout);
            json_key_value_int(stdout, "time_ms", elapsed);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet && args->verbosity > 0) {
            fprintf(stderr, "Validation successful\n");
        }
        pipeline_destroy(p);
        return 0;
    }

    // Save binary
    err = pipeline_save_binary(p, args->compile_output);
    if (err != PIPELINE_OK) {
        get_cpu_time(&end);
        elapsed = time_diff_ms(&start, &end);
        const char* err_msg = pipeline_get_last_error(p);
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "compile");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", err_msg ? err_msg : pipeline_error_string(err));
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->compile_input);
            json_comma(stdout);
            json_key_value_str(stdout, "output", args->compile_output);
            json_comma(stdout);
            json_key_value_int(stdout, "time_ms", elapsed);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: failed to save DFA: %s\n",
                    err_msg ? err_msg : pipeline_error_string(err));
        }
        pipeline_destroy(p);
        return 1;
    }

    size_t binary_size = pipeline_get_binary_size(p);
    int state_count = pipeline_get_dfa_state_count(p);

    // Get minimize and pre-minimize stats
    pipeline_minimize_stats_t min_stats = {0};
    pipeline_premin_stats_t premin_stats = {0};
    pipeline_get_minimize_stats(p, &min_stats);
    pipeline_get_premin_stats(p, &premin_stats);

    get_cpu_time(&end);
    elapsed = time_diff_ms(&start, &end);

    if (args->stats) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "compile");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", true);
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->compile_input);
            json_comma(stdout);
            json_key_value_str(stdout, "output", args->compile_output);
            json_comma(stdout);
            json_key_value_uint(stdout, "size", (unsigned long long)binary_size);
            json_comma(stdout);
            json_key_value_int(stdout, "states", state_count);
            json_comma(stdout);
            json_key_value_int(stdout, "premin_removed", premin_stats.states_removed);
            json_comma(stdout);
            json_key_value_int(stdout, "min_removed", min_stats.states_removed);
            json_comma(stdout);
            json_key_value_int(stdout, "min_iterations", min_stats.iterations);
            json_comma(stdout);
            json_key_value_int(stdout, "time_ms", elapsed);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else {
            csv_stats_header(stdout);
            csv_stats_row(stdout, "compile", "success", args->compile_input, 
                         args->compile_output, binary_size, state_count, 
                         premin_stats.states_removed, min_stats.states_removed, 
                         min_stats.iterations, elapsed);
        }
    } else if (!args->quiet && args->verbosity > 0) {
        fprintf(stderr, "  Wrote %zu bytes (%d states) to %s\n", 
                binary_size, state_count, args->compile_output);
    }

    pipeline_destroy(p);
    return 0;
}

// ============================================================================
// Embedd Command
// ============================================================================

static int embedd_validate_dfa(const uint8_t* dfa_data, long file_size, bool quiet, bool json_output) {
    // Check 1: File size
    if (file_size < 16) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "file too small");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: File too small (%ld bytes)\n", file_size);
        }
        return 1;
    }

    // Check 2: Magic number
    uint32_t magic = dfa_fmt_magic(dfa_data);
    if (magic != DFA_MAGIC) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "invalid magic number");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: Invalid magic number (expected 0x%08X, got 0x%08X)\n",
                    DFA_MAGIC, magic);
        }
        return 1;
    }

    // Check 3: Version
    uint16_t version = dfa_fmt_version(dfa_data);
    if (version != DFA_VERSION) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "unsupported version");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: Unsupported version (expected %u, got %u)\n",
                    DFA_VERSION, version);
        }
        return 1;
    }

    // Check 4: Encoding
    int enc = dfa_fmt_encoding(dfa_data);
    if (enc < 0 || enc > 3) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "invalid encoding");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: Invalid encoding %d\n", enc);
        }
        return 1;
    }

    // Check 5: State count
    uint16_t state_count = dfa_fmt_state_count(dfa_data);
    if (state_count == 0) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "state count is zero");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: State count is zero\n");
        }
        return 1;
    }

    // Check 6: Header size and ID length
    uint8_t id_len = dfa_fmt_id_len(dfa_data);
    size_t header_size = DFA_HEADER_SIZE(enc, id_len);

    if (file_size < (long)header_size + 8) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "file too small for header");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: File too small for header and checksums\n");
        }
        return 1;
    }

    // Check 7: Checksums
    uint32_t stored_crc = dfa_fmt_checksum_crc32(dfa_data);
    uint32_t stored_fnv = dfa_fmt_checksum_fnv32(dfa_data);
    uint8_t hdr_copy[header_size + 8];
    memcpy(hdr_copy, dfa_data, header_size);
    memset(hdr_copy + header_size, 0, 8);
    uint32_t computed_crc = crc32c(hdr_copy, header_size);
    uint32_t computed_fnv = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < header_size; i++) {
        computed_fnv ^= hdr_copy[i];
        computed_fnv *= FNV_PRIME;
    }

    if (stored_crc != computed_crc) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "CRC32 checksum mismatch");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: CRC32 checksum mismatch (stored 0x%08X, computed 0x%08X)\n",
                    stored_crc, computed_crc);
        }
        return 1;
    }

    if (stored_fnv != computed_fnv) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "FNV-1a checksum mismatch");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: FNV-1a checksum mismatch (stored 0x%08X, computed 0x%08X)\n",
                    stored_fnv, computed_fnv);
        }
        return 1;
    }

    // Check 8: Initial state offset
    uint32_t init_state = dfa_fmt_initial_state(dfa_data);
    int state_size = DFA_STATE_SIZE(enc);
    if (state_size <= 0) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "invalid state size");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: Invalid state size %d\n", state_size);
        }
        return 1;
    } else if ((size_t)init_state < header_size) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "initial state offset before header");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: Initial state offset before header end\n");
        }
        return 1;
    } else if ((size_t)init_state + (size_t)state_count * (size_t)state_size > (size_t)file_size) {
        if (json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "states extend beyond file");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!quiet) {
            fprintf(stderr, "FAIL: States extend beyond file size\n");
        }
        return 1;
    }

    return 0;  // Valid
}

int cli_embedd(const cli_args_t* args) {
    cpu_time_t start = {0, 0}, end = {0, 0};
    long elapsed = 0;
    get_cpu_time(&start);

    if (!args->embedd_input) {
        fprintf(stderr, "Error: no DFA file specified\n");
        return 2;
    }

    if (!args->embedd_output) {
        fprintf(stderr, "Error: no output file specified\n");
        return 2;
    }

    if (!args->quiet && args->verbosity > 0) {
        fprintf(stderr, "Embedding: %s → %s\n", args->embedd_input, args->embedd_output);
    }

    if (!args->force && check_output_exists(args->embedd_output)) {
        get_cpu_time(&end);
        elapsed = time_diff_ms(&start, &end);
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "output file exists");
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->embedd_input);
            json_comma(stdout);
            json_key_value_str(stdout, "output", args->embedd_output);
            json_comma(stdout);
            json_key_value_int(stdout, "time_ms", elapsed);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else {
            fprintf(stderr, "Error: output file '%s' already exists (will not overwrite)\n", 
                    args->embedd_output);
        }
        return 1;
    }

    // Read DFA binary
    FILE* dfaf = fopen(args->embedd_input, "rb");
    if (!dfaf) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "cannot open DFA file");
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->embedd_input);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: cannot open DFA file '%s': %s\n",
                    args->embedd_input, strerror(errno));
        }
        return 1;
    }

    fseek(dfaf, 0, SEEK_END);
    long dfa_size = ftell(dfaf);
    fseek(dfaf, 0, SEEK_SET);

    uint8_t* dfa_data = malloc(dfa_size);
    if (!dfa_data) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "memory allocation failed");
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->embedd_input);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: failed to allocate memory for DFA\n");
        }
        fclose(dfaf);
        return 1;
    }

    if (fread(dfa_data, 1, dfa_size, dfaf) != (size_t)dfa_size) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "failed to read DFA file");
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->embedd_input);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: failed to read DFA file\n");
        }
        free(dfa_data);
        fclose(dfaf);
        return 1;
    }
    fclose(dfaf);

    // Validate DFA before embedding
    int valid = embedd_validate_dfa(dfa_data, dfa_size, args->quiet, args->json_output);
    if (valid != 0) {
        free(dfa_data);
        return 1;
    }

    // Derive array name from output filename
    const char* output = args->embedd_output;
    const char* basename = output;
    for (const char* p = output; *p; p++) {
        if (*p == '/' || *p == '\\') basename = p + 1;
    }
    // Remove .c extension if present
    size_t baselen = strlen(basename);
    char array_name[256];
    if (baselen > 2 && strcmp(basename + baselen - 2, ".c") == 0) {
        baselen -= 2;
    }
    if (baselen >= sizeof(array_name)) baselen = sizeof(array_name) - 1;
    memcpy(array_name, basename, baselen);
    array_name[baselen] = '\0';
    // Replace non-alphanumeric with underscore
    for (char* p = array_name; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_')) {
            *p = '_';
        }
    }

    // Write C file
    FILE* out = fopen(args->embedd_output, "w");
    if (!out) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "cannot open output file");
            json_comma(stdout);
            json_key_value_str(stdout, "output", args->embedd_output);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: cannot open '%s' for writing: %s\n",
                    args->embedd_output, strerror(errno));
        }
        free(dfa_data);
        return 1;
    }

    fprintf(out, "/* Generated by cdfatool version %s */\n", cli_version());
    fprintf(out, "/* Do not edit manually */\n\n");
    fprintf(out, "#include <stdint.h>\n");
    fprintf(out, "#include <stddef.h>\n\n");
    fprintf(out, "const uint8_t %s[] = {\n", array_name);

    for (long i = 0; i < dfa_size; i++) {
        if ((i % 16) == 0) fprintf(out, "    ");
        fprintf(out, "0x%02x", dfa_data[i]);
        if (i < dfa_size - 1) fprintf(out, ", ");
        if ((i % 16) == 15 || i == dfa_size - 1) fprintf(out, "\n");
    }

    fprintf(out, "};\n\n");
    fprintf(out, "const size_t %s_size = %zu;\n", array_name, (size_t)dfa_size);

    fclose(out);

    if (args->stats) {
        uint16_t state_count = dfa_fmt_state_count(dfa_data);
        int enc = dfa_fmt_encoding(dfa_data);
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "embedd");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", true);
            json_comma(stdout);
            json_key_value_str(stdout, "input", args->embedd_input);
            json_comma(stdout);
            json_key_value_str(stdout, "output", args->embedd_output);
            json_comma(stdout);
            json_key_value_uint(stdout, "size", (unsigned long long)dfa_size);
            json_comma(stdout);
            json_key_value_int(stdout, "states", state_count);
            json_comma(stdout);
            json_key_value_int(stdout, "encoding", enc);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else {
            csv_stats_header(stdout);
            csv_stats_row(stdout, "embedd", "success", args->embedd_input, 
                         args->embedd_output, (size_t)dfa_size, state_count, 
                         0, 0, 0, 0);
        }
    } else if (!args->quiet && args->verbosity > 0) {
        fprintf(stderr, "  Wrote %zu bytes to %s\n", (size_t)dfa_size, args->embedd_output);
    }

    free(dfa_data);
    return 0;
}

// ============================================================================
// Verify Command
// ============================================================================

int cli_verify(const cli_args_t* args) {
    if (!args->verify_dfa) {
        fprintf(stderr, "Error: no DFA file specified\n");
        return 2;
    }

    if (!args->quiet && args->verbosity > 0) {
        fprintf(stderr, "Verifying: %s\n", args->verify_dfa);
    }

    // Read DFA binary
    FILE* dfaf = fopen(args->verify_dfa, "rb");
    if (!dfaf) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "verify");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "cannot open DFA file");
            json_comma(stdout);
            json_key_value_str(stdout, "file", args->verify_dfa);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: cannot open DFA file '%s': %s\n",
                    args->verify_dfa, strerror(errno));
        }
        return 1;
    }

    fseek(dfaf, 0, SEEK_END);
    long file_size = ftell(dfaf);
    fseek(dfaf, 0, SEEK_SET);

    uint8_t* dfa_data = malloc(file_size);
    if (!dfa_data) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "verify");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "memory allocation failed");
            json_comma(stdout);
            json_key_value_str(stdout, "file", args->verify_dfa);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: failed to allocate memory for DFA\n");
        }
        fclose(dfaf);
        return 1;
    }

    if (fread(dfa_data, 1, file_size, dfaf) != (size_t)file_size) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "verify");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "failed to read DFA file");
            json_comma(stdout);
            json_key_value_str(stdout, "file", args->verify_dfa);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "Error: failed to read DFA file\n");
        }
        free(dfa_data);
        fclose(dfaf);
        return 1;
    }
    fclose(dfaf);

    // Perform validation checks
    bool valid = true;
    int exit_code = 0;

    // Check 1: File size
    if (file_size < 16) {
        if (!args->quiet) fprintf(stderr, "FAIL: File too small (%zu bytes)\n", (size_t)file_size);
        valid = false;
    }

    // Check 2: Magic number
    uint32_t magic = dfa_fmt_magic(dfa_data);
    if (magic != DFA_MAGIC) {
        if (!args->quiet) fprintf(stderr, "FAIL: Invalid magic number (expected 0x%08X, got 0x%08X)\n",
                DFA_MAGIC, magic);
        valid = false;
    }

    // Check 3: Version
    uint16_t version = dfa_fmt_version(dfa_data);
    if (version != DFA_VERSION) {
        if (!args->quiet) fprintf(stderr, "FAIL: Unsupported version (expected %u, got %u)\n",
                DFA_VERSION, version);
        valid = false;
    }

    // Check 4: Encoding
    int enc = dfa_fmt_encoding(dfa_data);
    if (enc < 0 || enc > 3) {
        if (!args->quiet) fprintf(stderr, "FAIL: Invalid encoding %d\n", enc);
        valid = false;
    }

    // Check 5: State count
    uint16_t state_count = dfa_fmt_state_count(dfa_data);
    if (state_count == 0) {
        if (!args->quiet) fprintf(stderr, "FAIL: State count is zero\n");
        valid = false;
    }

    // Check 6: Header size and ID length
    uint8_t id_len = dfa_fmt_id_len(dfa_data);
    size_t header_size = DFA_HEADER_SIZE(enc, id_len);

    if (file_size < (long)header_size + 8) {
        if (!args->quiet) fprintf(stderr, "FAIL: File too small for header and checksums\n");
        valid = false;
    }

    // Check 7: Checksums
    uint32_t stored_crc = dfa_fmt_checksum_crc32(dfa_data);
    uint32_t stored_fnv = dfa_fmt_checksum_fnv32(dfa_data);
    uint8_t hdr_copy[header_size + 8];
    memcpy(hdr_copy, dfa_data, header_size);
    memset(hdr_copy + header_size, 0, 8);
    uint32_t computed_crc = crc32c(hdr_copy, header_size);
    uint32_t computed_fnv = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < header_size; i++) {
        computed_fnv ^= hdr_copy[i];
        computed_fnv *= FNV_PRIME;
    }

    if (stored_crc != computed_crc) {
        if (!args->quiet) fprintf(stderr, "FAIL: CRC32 checksum mismatch (stored 0x%08X, computed 0x%08X)\n",
                stored_crc, computed_crc);
        valid = false;
    }
    if (stored_fnv != computed_fnv) {
        if (!args->quiet) fprintf(stderr, "FAIL: FNV-1a checksum mismatch (stored 0x%08X, computed 0x%08X)\n",
                stored_fnv, computed_fnv);
        valid = false;
    }

    // Check 8: Initial state offset
    uint32_t init_state = dfa_fmt_initial_state(dfa_data);
    int state_size = DFA_STATE_SIZE(enc);
    if (state_size <= 0) {
        if (!args->quiet) fprintf(stderr, "FAIL: Invalid state size %d\n", state_size);
        valid = false;
    } else if ((size_t)init_state < header_size) {
        if (!args->quiet) fprintf(stderr, "FAIL: Initial state offset before header end\n");
        valid = false;
    } else if ((size_t)init_state + (size_t)state_count * (size_t)state_size > (size_t)file_size) {
        if (!args->quiet) fprintf(stderr, "FAIL: States extend beyond file size\n");
        valid = false;
    }

    // Check 9: Meta offset
    uint32_t meta_off = dfa_fmt_meta_offset(dfa_data);
    if (meta_off != 0 && meta_off > (size_t)file_size) {
        if (!args->quiet) fprintf(stderr, "FAIL: Metadata offset beyond file size\n");
        valid = false;
    }

    // Check 10: EOS offset
    uint32_t eos_off = dfa_fmt_eos_offset(dfa_data);
    if (eos_off > (size_t)file_size) {
        if (!args->quiet) fprintf(stderr, "FAIL: EOS offset beyond file size\n");
        valid = false;
    }

    // Check 11: PID offset
    uint32_t pid_off = dfa_fmt_pid_offset(dfa_data);
    if (pid_off > (size_t)file_size) {
        if (!args->quiet) fprintf(stderr, "FAIL: Pattern ID offset beyond file size\n");
        valid = false;
    }

    free(dfa_data);

    if (valid) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "verify");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", true);
            json_comma(stdout);
            json_key_value_str(stdout, "file", args->verify_dfa);
            json_comma(stdout);
            json_key_value_uint(stdout, "size", (unsigned long long)file_size);
            json_comma(stdout);
            json_key_value_int(stdout, "states", state_count);
            json_comma(stdout);
            json_key_value_int(stdout, "encoding", enc);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (args->stats) {
            csv_stats_header(stdout);
            csv_stats_row(stdout, "verify", "valid", args->verify_dfa, "", (size_t)file_size, state_count, 0, 0, 0, 0);
        } else if (!args->quiet) {
            if (args->verbosity > 0) {
                fprintf(stderr, "PASS: DFA is valid (%u states, encoding %d, %zu bytes)\n",
                        state_count, enc, (size_t)file_size);
            } else {
                fprintf(stderr, "PASS: DFA is valid\n");
            }
        }
        exit_code = 0;
    } else {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "verify");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "validation failed");
            json_comma(stdout);
            json_key_value_str(stdout, "file", args->verify_dfa);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else if (!args->quiet) {
            fprintf(stderr, "FAIL: DFA is invalid or corrupted\n");
        }
        exit_code = 1;
    }

    return exit_code;
}

// ============================================================================
// Eval Command
// ============================================================================

int cli_eval(const cli_args_t* args) {
    if (!args->eval_dfa) {
        fprintf(stderr, "Error: no DFA file specified\n");
        return 2;
    }

    if (!args->quiet && args->verbosity > 0) {
        fprintf(stderr, "Evaluating with DFA: %s\n", args->eval_dfa);
        if (args->eval_input) {
            fprintf(stderr, "  Input file: %s\n", args->eval_input);
        } else {
            fprintf(stderr, "  Input: stdin\n");
        }
    }

    FILE* dfaf = fopen(args->eval_dfa, "rb");
    if (!dfaf) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "eval");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "cannot open DFA file");
            json_comma(stdout);
            json_key_value_str(stdout, "file", args->eval_dfa);
            json_end_object(stdout);
            fputc('\n', stdout);
        } else {
            fprintf(stderr, "Error: cannot open DFA file '%s': %s\n",
                    args->eval_dfa, strerror(errno));
        }
        return 1;
    }

    fseek(dfaf, 0, SEEK_END);
    long dfa_size = ftell(dfaf);
    fseek(dfaf, 0, SEEK_SET);

    uint8_t* dfa_data = malloc(dfa_size);
    if (!dfa_data) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "eval");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "memory allocation failed");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else {
            fprintf(stderr, "Error: failed to allocate memory for DFA\n");
        }
        fclose(dfaf);
        return 1;
    }

    if (fread(dfa_data, 1, dfa_size, dfaf) != (size_t)dfa_size) {
        if (args->json_output) {
            json_start_object(stdout);
            json_key_value_str(stdout, "command", "eval");
            json_comma(stdout);
            json_key_value_bool(stdout, "success", false);
            json_comma(stdout);
            json_key_value_str(stdout, "error", "failed to read DFA file");
            json_end_object(stdout);
            fputc('\n', stdout);
        } else {
            fprintf(stderr, "Error: failed to read DFA file\n");
        }
        free(dfa_data);
        fclose(dfaf);
        return 1;
    }
    fclose(dfaf);

    FILE* input = stdin;
    if (args->eval_input) {
        input = fopen(args->eval_input, "r");
        if (!input) {
            if (args->json_output) {
                json_start_object(stdout);
                json_key_value_str(stdout, "command", "eval");
                json_comma(stdout);
                json_key_value_bool(stdout, "success", false);
                json_comma(stdout);
                json_key_value_str(stdout, "error", "cannot open input file");
                json_end_object(stdout);
                fputc('\n', stdout);
            } else {
                fprintf(stderr, "Error: cannot open input file '%s': %s\n",
                        args->eval_input, strerror(errno));
            }
            free(dfa_data);
            return 1;
        }
    }

    if (args->json_output) {
        json_start_array(stdout);
        bool first = true;
        char line[4096];
        while (fgets(line, sizeof(line), input)) {
            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
                len--;
            }
            if (len == 0) continue;

            dfa_result_t result;
            bool ok = dfa_eval(dfa_data, dfa_size, line, len, &result);

            if (!first) json_comma(stdout);
            first = false;

            json_start_object(stdout);
            json_key_value_str(stdout, "input", line);
            json_comma(stdout);
            json_key_value_bool(stdout, "matched", ok && result.matched);
            if (ok && result.matched) {
                json_comma(stdout);
                json_key_value_int(stdout, "category", result.category);
                json_comma(stdout);
                json_key_value_str(stdout, "category_name", dfa_category_string(result.category));
                json_comma(stdout);
                fprintf(stdout, "\"category_mask\":\"0x%02x\"", result.category_mask);
                if (args->eval_capture && result.capture_count > 0) {
                    json_comma(stdout);
                    json_key_value_int(stdout, "captures", result.capture_count);
                }
            }
            json_end_object(stdout);
        }
        json_end_array(stdout);
        fputc('\n', stdout);
    } else {
        char line[4096];
        while (fgets(line, sizeof(line), input)) {
            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
                len--;
            }
            if (len == 0) continue;

            dfa_result_t result;
            bool ok = dfa_eval(dfa_data, dfa_size, line, len, &result);

            if (ok && result.matched) {
                printf("matched=1 category=%d (%s) category_mask=0x%02x",
                       result.category,
                       dfa_category_string(result.category),
                       result.category_mask);

                if (args->eval_capture && result.capture_count > 0) {
                    printf(" captures=%d", result.capture_count);
                    for (int c = 0; c < result.capture_count; c++) {
                        size_t start = result.captures[c].start;
                        size_t end = result.captures[c].end;
                        if (start < len && end <= len && start < end) {
                            printf(" capture[%d]=%zu-%zu=\"%.*s\"",
                                   c, start, end, (int)(end - start), line + start);
                        }
                    }
                }
                printf("\n");
            } else {
                printf("matched=0 category=0 (Unknown)\n");
            }
        }
    }

    if (args->eval_input && input != stdin) {
        fclose(input);
    }
    free(dfa_data);

    return 0;
}

// ============================================================================
// Main
// ============================================================================

int cli_run(const cli_args_t* args) {
    switch (args->cmd) {
        case CMD_VALIDATE:
            return cli_validate(args);
        case CMD_COMPILE:
            return cli_compile(args);
        case CMD_EMBEDD:
            return cli_embedd(args);
        case CMD_VERIFY:
            return cli_verify(args);
        case CMD_EVAL:
            return cli_eval(args);
        case CMD_HELP:
            cli_help_for("cdfatool", CMD_HELP);
            return 0;
        default:
            fprintf(stderr, "Error: no command specified\n");
            cli_usage("cdfatool");
            return 2;
    }
}

// ============================================================================
// Standalone Main
// ============================================================================

#ifndef NFABUILDER_NO_MAIN

int main(int argc, char* argv[]) {
    cli_args_t args;

    if (!cli_parse_args(argc, argv, &args)) {
        if (argc >= 2 && strcmp(argv[1], "help") == 0) {
            return 0;
        }
        if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
            return 0;
        }
        return 2;
    }

    return cli_run(&args);
}

#endif // NFABUILDER_NO_MAIN