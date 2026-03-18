/**
 * dfa2c_array.c - Convert binary DFA to C array
 *
 * Reads a binary DFA file and outputs a C source file containing
 * the data as a static byte array, suitable for embedding in programs.
 *
 * Usage:
 *   dfa2c_array [options] <input.dfa> <output.c> <array_name>
 *
 * Options:
 *   --header FILE     Generate companion header with declarations
 *   --type TYPE       Array element type: uint8_t (default) or unsigned char
 *   --no-const        Omit const qualifier from array
 *   --static          Use static linkage (single translation unit)
 *   --array-only      Emit only the byte array, skip size variable
 *   --size-only       Emit only the size variable, skip byte array
 *   --guard NAME      Header guard name (default: <ARRAY_NAME>_H)
 *   --include FILE    Extra #include directive in generated code
 *   --help            Show this help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define DFA_ERROR_PROGRAM "dfa2c_array"
#include "dfa_errors.h"

static void usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] <input.dfa> <output.c> <array_name>\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --header FILE     Generate companion header with declarations\n");
    fprintf(stderr, "  --type TYPE       Array element type: uint8_t (default) or unsigned char\n");
    fprintf(stderr, "  --no-const        Omit const qualifier from array\n");
    fprintf(stderr, "  --static          Use static linkage (single translation unit)\n");
    fprintf(stderr, "  --array-only      Emit only the byte array, skip size variable\n");
    fprintf(stderr, "  --size-only       Emit only the size variable, skip byte array\n");
    fprintf(stderr, "  --guard NAME      Header guard name (default: <ARRAY_NAME>_H)\n");
    fprintf(stderr, "  --include FILE    Extra #include directive in generated code\n");
    fprintf(stderr, "  --help            Show this help\n");
}

typedef struct {
    const char* input_path;
    const char* output_path;
    const char* array_name;
    const char* header_path;
    const char* type;           // "uint8_t" or "unsigned char"
    const char* guard;          // header guard name
    const char* extra_include;  // extra #include
    bool no_const;
    bool static_linkage;
    bool array_only;
    bool size_only;
} config_t;

static bool parse_args(int argc, char* argv[], config_t* cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->type = "uint8_t";

    int positional = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            exit(0);
        }
        else if (strcmp(argv[i], "--header") == 0) {
            if (++i >= argc) { ERROR("--header requires an argument"); return false; }
            cfg->header_path = argv[i];
        }
        else if (strcmp(argv[i], "--type") == 0) {
            if (++i >= argc) { ERROR("--type requires an argument"); return false; }
            if (strcmp(argv[i], "uint8_t") != 0 && strcmp(argv[i], "unsigned char") != 0) {
                ERROR("--type must be 'uint8_t' or 'unsigned char', got '%s'", argv[i]);
                return false;
            }
            cfg->type = argv[i];
        }
        else if (strcmp(argv[i], "--no-const") == 0) {
            cfg->no_const = true;
        }
        else if (strcmp(argv[i], "--static") == 0) {
            cfg->static_linkage = true;
        }
        else if (strcmp(argv[i], "--array-only") == 0) {
            cfg->array_only = true;
        }
        else if (strcmp(argv[i], "--size-only") == 0) {
            cfg->size_only = true;
        }
        else if (strcmp(argv[i], "--guard") == 0) {
            if (++i >= argc) { ERROR("--guard requires an argument"); return false; }
            cfg->guard = argv[i];
        }
        else if (strcmp(argv[i], "--include") == 0) {
            if (++i >= argc) { ERROR("--include requires an argument"); return false; }
            cfg->extra_include = argv[i];
        }
        else if (argv[i][0] == '-') {
            ERROR("Unknown option: %s", argv[i]);
            return false;
        }
        else {
            // Positional argument
            switch (positional) {
                case 0: cfg->input_path = argv[i]; break;
                case 1: cfg->output_path = argv[i]; break;
                case 2: cfg->array_name = argv[i]; break;
                default:
                    ERROR("Unexpected argument: %s", argv[i]);
                    return false;
            }
            positional++;
        }
    }

    if (positional != 3) {
        ERROR("Expected 3 positional arguments (input.dfa output.c array_name), got %d", positional);
        return false;
    }

    if (cfg->array_only && cfg->size_only) {
        ERROR("Cannot use --array-only and --size-only together");
        return false;
    }

    // Build default guard name from array_name
    if (!cfg->guard) {
        static char guard_buf[256];
        snprintf(guard_buf, sizeof(guard_buf), "%s_H", cfg->array_name);
        // Uppercase it
        for (char* p = guard_buf; *p; p++) {
            if (*p >= 'a' && *p <= 'z') *p = *p - 'a' + 'A';
        }
        cfg->guard = guard_buf;
    }

    return true;
}

static unsigned char* read_file(const char* path, long* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        ERROR_SYS("Cannot open '%s'", path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0) {
        ERROR("Cannot determine size of '%s'", path);
        fclose(f);
        return NULL;
    }

    unsigned char* buf = malloc(size);
    if (!buf) {
        ERROR("Cannot allocate %ld bytes", size);
        fclose(f);
        return NULL;
    }

    if ((long)fread(buf, 1, size, f) != size) {
        ERROR("Short read on '%s'", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);

    *out_size = size;
    return buf;
}

static bool write_source(const config_t* cfg, const unsigned char* data, long size) {
    FILE* f = fopen(cfg->output_path, "w");
    if (!f) {
        ERROR_SYS("Cannot open '%s' for writing", cfg->output_path);
        return false;
    }

    const char* qualifier = cfg->no_const ? "" : "const";
    const char* linkage = cfg->static_linkage ? "static" : "";

    // Build prefix: "static const " or "const " or "static " or ""
    char prefix[32] = "";
    if (linkage[0]) strcat(prefix, linkage);
    if (linkage[0] && qualifier[0]) strcat(prefix, " ");
    if (qualifier[0]) strcat(prefix, qualifier);
    if (prefix[0]) strcat(prefix, " ");

    fprintf(f, "/* Auto-generated from %s by dfa2c_array */\n", cfg->input_path);
    fprintf(f, "/* Do not edit manually */\n\n");

    if (cfg->extra_include) {
        fprintf(f, "#include \"%s\"\n", cfg->extra_include);
    }
    if (!cfg->size_only) {
        fprintf(f, "#include <stdint.h>\n");
    }
    fprintf(f, "#include <stddef.h>\n\n");

    // Size variable
    if (!cfg->array_only) {
        fprintf(f, "%ssize_t %s_size = %ld;\n\n", prefix, cfg->array_name, size);
    }

    // Array
    if (!cfg->size_only) {
        fprintf(f, "%s%s %s[%ld] = {\n",
                prefix, cfg->type, cfg->array_name, size);

        for (long i = 0; i < size; i++) {
            if (i % 16 == 0) {
                fprintf(f, "    ");
            }
            fprintf(f, "0x%02X", data[i]);
            if (i < size - 1) {
                fprintf(f, ", ");
            }
            if (i % 16 == 15) {
                fprintf(f, "\n");
            }
        }
        if (size % 16 != 0) {
            fprintf(f, "\n");
        }
        fprintf(f, "};\n");
    }

    fclose(f);
    return true;
}

static bool write_header(const config_t* cfg, long size) {
    (void)size;
    FILE* f = fopen(cfg->header_path, "w");
    if (!f) {
        ERROR_SYS("Cannot open '%s' for writing", cfg->header_path);
        return false;
    }

    const char* qualifier = cfg->no_const ? "" : "const";

    fprintf(f, "/* Auto-generated by dfa2c_array - do not edit */\n");
    fprintf(f, "#ifndef %s\n", cfg->guard);
    fprintf(f, "#define %s\n\n", cfg->guard);

    fprintf(f, "#include <stdint.h>\n");
    fprintf(f, "#include <stddef.h>\n\n");

    if (cfg->extra_include) {
        fprintf(f, "#include \"%s\"\n\n", cfg->extra_include);
    }

    if (!cfg->array_only) {
        fprintf(f, "extern const size_t %s_size;\n", cfg->array_name);
    }
    if (!cfg->size_only) {
        fprintf(f, "extern %s%s%s %s[];\n",
                qualifier, qualifier[0] ? " " : "", cfg->type, cfg->array_name);
    }

    fprintf(f, "\n#endif /* %s */\n", cfg->guard);

    fclose(f);
    return true;
}

int main(int argc, char* argv[]) {
    config_t cfg;
    if (!parse_args(argc, argv, &cfg)) {
        return 1;
    }

    // Read input
    long size;
    unsigned char* data = read_file(cfg.input_path, &size);
    if (!data) return 1;

    // Write source
    if (!write_source(&cfg, data, size)) {
        free(data);
        return 1;
    }

    // Write header if requested
    if (cfg.header_path) {
        if (!write_header(&cfg, size)) {
            free(data);
            return 1;
        }
    }

    free(data);

    fprintf(stderr, "Generated %s (%ld bytes)", cfg.output_path, size);
    if (cfg.header_path) {
        fprintf(stderr, " + %s", cfg.header_path);
    }
    fprintf(stderr, "\n");

    return 0;
}
