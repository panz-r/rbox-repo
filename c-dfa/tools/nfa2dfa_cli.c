#define DFA_ERROR_PROGRAM "nfa2dfa"
#include "../include/dfa_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/dfa_minimize.h"
#include "../include/dfa_types.h"
#include "../include/pipeline.h"

static void print_usage(const char* progname) {
    fprintf(stderr, "Usage: %s [options] <input.nfa> [output.dfa]\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Convert NFA to minimized DFA binary.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help           Show this help message\n");
    fprintf(stderr, "  --version            Show version information\n");
    fprintf(stderr, "  -v                   Enable verbose output\n");
    fprintf(stderr, "  -vv                  Enable very verbose debug output\n");
    fprintf(stderr, "  --no-minimize        Skip DFA minimization\n");
    fprintf(stderr, "  --no-compress        Skip DFA compression\n");
    fprintf(stderr, "  --minimize-hopcroft  Use Hopcroft minimization (default)\n");
    fprintf(stderr, "  --minimize-moore     Use Moore minimization\n");
    fprintf(stderr, "  --minimize-brzozowski Use Brzozowski minimization\n");
    fprintf(stderr, "  --minimize-sat       Use SAT-based minimization\n");
    fprintf(stderr, "  --compress-sat       Use SAT-based compression\n");
    fprintf(stderr, "  --sat-optimal        Use SAT-based optimal pre-minimization\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  input.nfa            Input NFA file (required)\n");
    fprintf(stderr, "  output.dfa           Output DFA file (default: out.dfa)\n");
}

int main(int argc, char* argv[]) {
    bool minimize = true;
    bool compress = true;
    bool verbose = false;
    int verbosity = 0;
    bool compress_sat = false;
    bool sat_optimal = false;
    const char* input_file = NULL;
    const char* output_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            pipeline_print_version("nfa2dfa_advanced");
            return 0;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
            verbosity = 1;
        } else if (strcmp(argv[i], "-vv") == 0) {
            verbose = true;
            verbosity = 2;
        } else if (strcmp(argv[i], "--no-minimize") == 0) {
            minimize = false;
        } else if (strcmp(argv[i], "--no-compress") == 0) {
            compress = false;
        } else if (strcmp(argv[i], "--minimize-hopcroft") == 0) {
            dfa_minimize_set_algorithm(DFA_MIN_HOPCROFT);
        } else if (strcmp(argv[i], "--minimize-moore") == 0) {
            dfa_minimize_set_algorithm(DFA_MIN_MOORE);
        } else if (strcmp(argv[i], "--minimize-brzozowski") == 0) {
            dfa_minimize_set_algorithm(DFA_MIN_BRZOZOWSKI);
        } else if (strcmp(argv[i], "--minimize-sat") == 0) {
            dfa_minimize_set_algorithm(DFA_MIN_SAT);
        } else if (strcmp(argv[i], "--compress-sat") == 0) {
            compress_sat = true;
        } else if (strcmp(argv[i], "--sat-optimal") == 0) {
            sat_optimal = true;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Error: unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        } else {
            if (input_file == NULL) {
                input_file = argv[i];
            } else if (output_file == NULL) {
                output_file = argv[i];
            }
        }
    }

    if (input_file == NULL) {
        fprintf(stderr, "Error: no input file specified\n");
        print_usage(argv[0]);
        return 2;
    }

    if (output_file == NULL) {
        output_file = "out.dfa";
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa_advanced: input='%s' output='%s' minimize=%d compress=%d\n",
                input_file, output_file, minimize, compress);
    }

    pipeline_config_t config = {
        .minimize_algo = dfa_minimize_get_algorithm(),
        .compress = compress,
        .optimize_layout = minimize,
        .verbose = verbose,
        .use_sat_compress = compress_sat,
        .enable_sat_optimal_premin = sat_optimal,
    };

    pipeline_t* p = pipeline_create(&config);
    if (!p) {
        fprintf(stderr, "Error: failed to create pipeline\n");
        return 1;
    }

    pipeline_error_t err = pipeline_load_nfa(p, input_file);
    if (err != PIPELINE_OK) {
        const char* err_msg = pipeline_get_last_error(p);
        fprintf(stderr, "Error: failed to load NFA from '%s': %s\n",
                input_file, err_msg ? err_msg : pipeline_error_string(err));
        pipeline_destroy(p);
        return 1;
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: loaded NFA with %d states\n", pipeline_get_nfa_state_count(p));
    }

    err = pipeline_convert_to_dfa(p);
    if (err != PIPELINE_OK) {
        const char* err_msg = pipeline_get_last_error(p);
        fprintf(stderr, "Error: NFA to DFA conversion failed: %s\n",
                err_msg ? err_msg : pipeline_error_string(err));
        pipeline_destroy(p);
        return 1;
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: converted to DFA with %d states\n", pipeline_get_dfa_state_count(p));
    }

    if (minimize) {
        dfa_minimize_algo_t algo = config.minimize_algo;
        if (verbosity > 0) {
            fprintf(stderr, "nfa2dfa: before minimize, state_count=%d, algo=%d\n",
                    pipeline_get_dfa_state_count(p), algo);
        }
        err = pipeline_minimize_dfa(p, algo);
        if (err != PIPELINE_OK) {
            fprintf(stderr, "Error: minimization failed: %s\n", pipeline_error_string(err));
            pipeline_destroy(p);
            return 1;
        }
        if (verbosity > 0) {
            fprintf(stderr, "nfa2dfa: after minimize, state_count=%d\n",
                    pipeline_get_dfa_state_count(p));
        }
        if (config.optimize_layout) {
            if (verbosity > 0) {
                fprintf(stderr, "nfa2dfa: before layout, state_count=%d\n",
                        pipeline_get_dfa_state_count(p));
            }
            err = pipeline_optimize_layout(p);
            if (err != PIPELINE_OK) {
                fprintf(stderr, "Error: layout optimization failed: %s\n",
                        pipeline_error_string(err));
                pipeline_destroy(p);
                return 1;
            }
            if (verbosity > 0) {
                fprintf(stderr, "nfa2dfa: after layout\n");
            }
        }
    }

    if (compress) {
        if (verbosity > 0) {
            fprintf(stderr, "nfa2dfa: before compress, state_count=%d\n",
                    pipeline_get_dfa_state_count(p));
        }
        err = pipeline_compress(p);
        if (err != PIPELINE_OK) {
            fprintf(stderr, "Error: compression failed: %s\n", pipeline_error_string(err));
            pipeline_destroy(p);
            return 1;
        }
        if (verbosity > 0) {
            fprintf(stderr, "nfa2dfa: after compress\n");
        }
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: before write_dfa_file, state_count=%d\n",
                pipeline_get_dfa_state_count(p));
    }
    err = pipeline_save_binary(p, output_file);
    if (err != PIPELINE_OK) {
        const char* err_msg = pipeline_get_last_error(p);
        fprintf(stderr, "Error: failed to save DFA to '%s': %s\n",
                output_file, err_msg ? err_msg : pipeline_error_string(err));
        pipeline_destroy(p);
        return 1;
    }
    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: after write_dfa_file\n");
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: done, output='%s' size=%zu bytes\n",
                output_file, pipeline_get_binary_size(p));
    }

    pipeline_destroy(p);
    return 0;
}
