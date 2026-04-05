#!/usr/bin/env python3
"""
Transform nfa2dfa.c to use context struct instead of globals.
Completed: Context struct refactoring.
"""

import re
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def transform():
    with open(os.path.join(SCRIPT_DIR, "nfa2dfa.c"), "r") as f:
        lines = f.readlines()

    output = []
    i = 0
    while i < len(lines):
        line = lines[i]

        # 1. Add nfa2dfa_context.h include
        if line.strip() == '#include "nfa_preminimize.h"':
            output.append(line)
            output.append('#include "nfa2dfa_context.h"\n')
            i += 1
            continue

        # 2. Replace forward declarations
        if line.strip() == "void nfa_init(void);":
            i += 1
            continue

        # 3. Replace global variable declarations with nothing (they're in context now)
        if line.startswith("static char pattern_identifier"):
            i += 1
            continue
        if line.startswith("static bool flag_verbose"):
            i += 1
            continue
        if (
            line.strip()
            == "#define DEBUG_PRINT(...) do { if (flag_verbose) fprintf(stderr, __VA_ARGS__); } while (0)"
        ):
            output.append(
                "#define DEBUG_PRINT(...) do { if (ctx->flag_verbose) fprintf(stderr, __VA_ARGS__); } while (0)\n"
            )
            i += 1
            continue

        # 4. Skip the alphabet_entry_t typedef (moved to header)
        if (
            line.startswith("typedef struct {")
            and i + 4 < len(lines)
            and "alphabet_entry_t" in lines[i + 4]
        ):
            while i < len(lines) and "alphabet_entry_t" not in lines[i]:
                i += 1
            i += 1  # skip the } alphabet_entry_t; line
            continue

        # 5. Skip all global variable declarations
        if line.startswith("static nfa_state_t nfa["):
            i += 1
            continue
        if line.startswith("static build_dfa_state_t dfa["):
            i += 1
            continue
        if line.startswith("static alphabet_entry_t alphabet["):
            i += 1
            continue
        if line.startswith("static int nfa_state_count"):
            i += 1
            continue
        if line.startswith("static int dfa_state_count"):
            i += 1
            continue
        if line.startswith("static int alphabet_size"):
            i += 1
            continue
        if line.startswith("static int max_states"):
            i += 1
            continue

        # 6. Skip the state documentation comment block
        if "NFA-TO-DFA CONVERTER STATE DOCUMENTATION" in line:
            while i < len(lines) and "globals are acceptable" not in lines[i]:
                i += 1
            i += 1
            continue

        # 7. Replace DFA hash table globals
        if line.startswith("static int dfa_hash_table["):
            i += 1
            continue
        if line.startswith("static int dfa_next_in_bucket["):
            i += 1
            continue

        # 8. Replace init_hash_table function
        if line.strip() == "static void init_hash_table(void) {":
            output.append("static void init_hash_table(nfa2dfa_context_t* ctx) {\n")
            i += 1
            continue
        if "memset(dfa_hash_table, -1, sizeof(dfa_hash_table));" in line:
            output.append(
                "    memset(ctx->dfa_hash_table, -1, sizeof(int) * DFA_HASH_SIZE);\n"
            )
            i += 1
            continue
        if "memset(dfa_next_in_bucket, -1, sizeof(dfa_next_in_bucket));" in line:
            output.append(
                "    memset(ctx->dfa_next_in_bucket, -1, sizeof(int) * ctx->max_states);\n"
            )
            i += 1
            continue

        # 9. Skip marker list globals
        if line.startswith("static MarkerList* dfa_marker_lists"):
            i += 1
            continue
        if line.startswith("static int marker_list_count"):
            i += 1
            continue

        # 10. Replace init_marker_lists function
        if (
            "Failed to allocate marker lists" in line
            and "init_marker_lists" not in line
        ):
            # This is inside the old init_marker_lists, skip it and replace
            pass
        if line.strip() == "static void init_marker_lists(void) {":
            output.append("static void init_marker_lists(nfa2dfa_context_t* ctx) {\n")
            output.append(
                "    memset(ctx->dfa_marker_lists, 0, sizeof(MarkerList) * MAX_DFA_MARKER_LISTS);\n"
            )
            output.append("    ctx->marker_list_count = 0;\n")
            output.append("}\n")
            # Skip until closing brace
            while i < len(lines) and lines[i].strip() != "}":
                i += 1
            i += 1  # skip the }
            continue

        # Skip the old body of init_marker_lists
        if i > 0 and "dfa_marker_lists = alloc_or_abort" in line:
            i += 1
            continue
        if "memset(dfa_marker_lists, 0, sizeof(MarkerList)" in line:
            i += 1
            continue

        # 11. After all the header changes, now process function signatures and bodies
        # We need to track whether we're inside a function that needs ctx

        # Skip the "Note: No free_marker_lists()" comment
        if "No free_marker_lists" in line:
            i += 1
            continue

        output.append(line)
        i += 1

    # Now do a second pass to fix function signatures and bodies
    content = "".join(output)

    # Add context create/destroy functions after alloc_or_abort
    create_destroy = """
// ============================================================================
// Context lifecycle
// ============================================================================

nfa2dfa_context_t* nfa2dfa_context_create(void) {
    nfa2dfa_context_t* ctx = calloc(1, sizeof(nfa2dfa_context_t));
    if (!ctx) return NULL;

    ctx->max_states = MAX_STATES;
    ctx->nfa = calloc(MAX_STATES, sizeof(nfa_state_t));
    ctx->dfa = calloc(MAX_STATES, sizeof(build_dfa_state_t));
    ctx->alphabet = calloc(MAX_SYMBOLS, sizeof(alphabet_entry_t));
    ctx->dfa_hash_table = calloc(DFA_HASH_SIZE, sizeof(int));
    ctx->dfa_next_in_bucket = calloc(MAX_STATES, sizeof(int));
    ctx->dfa_marker_lists = calloc(MAX_DFA_MARKER_LISTS, sizeof(MarkerList));

    if (!ctx->nfa || !ctx->dfa || !ctx->alphabet ||
        !ctx->dfa_hash_table || !ctx->dfa_next_in_bucket ||
        !ctx->dfa_marker_lists) {
        nfa2dfa_context_destroy(ctx);
        return NULL;
    }

    return ctx;
}

void nfa2dfa_context_destroy(nfa2dfa_context_t* ctx) {
    if (!ctx) return;
    free(ctx->nfa);
    free(ctx->dfa);
    free(ctx->alphabet);
    free(ctx->dfa_hash_table);
    free(ctx->dfa_next_in_bucket);
    free(ctx->dfa_marker_lists);
    free(ctx);
}

"""
    content = content.replace(
        "    return ptr;\n}\n\n// Get unique marker list",
        "    return ptr;\n}\n" + create_destroy + "\n// Get unique marker list",
    )

    # Now fix function signatures - add ctx parameter
    sig_fixes = [
        (
            "static uint32_t store_marker_list(const uint32_t* markers, int count)",
            "static uint32_t store_marker_list(nfa2dfa_context_t* ctx, const uint32_t* markers, int count)",
        ),
        (
            "static void collect_markers_from_states(const int* states, int state_count,",
            "static void collect_markers_from_states(nfa2dfa_context_t* ctx, const int* states, int state_count,",
        ),
        (
            "static int find_dfa_state_hashed(uint32_t hash, const int* sorted_states, int count, uint8_t mask, uint16_t first_accepting_pattern)",
            "static int find_dfa_state_hashed(nfa2dfa_context_t* ctx, uint32_t hash, const int* sorted_states, int count, uint8_t mask, uint16_t first_accepting_pattern)",
        ),
        ("void nfa_init(void)", "static void nfa_init(nfa2dfa_context_t* ctx)"),
        ("void dfa_init(void)", "static void dfa_init(nfa2dfa_context_t* ctx)"),
        (
            "void epsilon_closure_with_markers(int* states, int* count, int max_states,",
            "static void epsilon_closure_with_markers(nfa2dfa_context_t* ctx, int* states, int* count, int max_states,",
        ),
        (
            "void epsilon_closure(int* states, int* count, int max_states)",
            "static void epsilon_closure(nfa2dfa_context_t* ctx, int* states, int* count, int max_states)",
        ),
        (
            "static uint8_t collect_fork_categories(int* states, int count, bool is_initial_state)",
            "static uint8_t collect_fork_categories(nfa2dfa_context_t* ctx, int* states, int count, bool is_initial_state)",
        ),
        (
            "int dfa_add_state(uint8_t category_mask, int* nfa_states, int nfa_count, uint16_t accepting_pattern_id, uint16_t first_accepting_pattern)",
            "static int dfa_add_state(nfa2dfa_context_t* ctx, uint8_t category_mask, int* nfa_states, int nfa_count, uint16_t accepting_pattern_id, uint16_t first_accepting_pattern)",
        ),
        (
            "void nfa_move(int* states, int* count, int sid, int max_states)",
            "static void nfa_move(nfa2dfa_context_t* ctx, int* states, int* count, int sid, int max_states)",
        ),
        (
            "static void collect_transition_markers(int source_count, int* source_states, int sid,",
            "static void collect_transition_markers(nfa2dfa_context_t* ctx, int source_count, int* source_states, int sid,",
        ),
        ("void nfa_to_dfa(void)", "static void nfa_to_dfa(nfa2dfa_context_t* ctx)"),
        ("void flatten_dfa(void)", "static void flatten_dfa(nfa2dfa_context_t* ctx)"),
        (
            "void write_dfa_file(const char* filename)",
            "static void write_dfa_file(nfa2dfa_context_t* ctx, const char* filename)",
        ),
        (
            "void load_nfa_file(const char* filename)",
            "static void load_nfa_file(nfa2dfa_context_t* ctx, const char* filename)",
        ),
    ]

    for old, new in sig_fixes:
        content = content.replace(old, new)

    # Remove NFABUILDER_EXCLUDE_NFA_INIT guards
    content = content.replace("#ifndef NFABUILDER_EXCLUDE_NFA_INIT\n\n", "")
    content = content.replace("\n#endif  // NFABUILDER_EXCLUDE_NFA_INIT\n", "\n")

    # Now replace global accesses in function BODIES ONLY (not in signatures)
    # We process line by line, skipping function signature lines

    lines = content.split("\n")
    new_lines = []
    in_sig = False
    paren_depth = 0

    for line in lines:
        stripped = line.strip()

        # Detect function signature lines (contain 'static' or return type and '(' but not '{' on same line typically)
        # Function signatures span from the function name to the opening brace
        is_sig_start = False
        if (
            "static void " in line
            or "static int " in line
            or "static uint" in line
            or "void " in line
            or "int " in line
            or "uint" in line
        ) and "(" in line:
            # Check if this looks like a function definition (not a function call or for loop)
            if (
                not stripped.startswith("for")
                and not stripped.startswith("if")
                and not stripped.startswith("while")
            ):
                if "{" not in line:
                    is_sig_start = True
                    in_sig = True
                    paren_depth = line.count("(") - line.count(")")

        if in_sig:
            paren_depth += line.count("(") - line.count(")")
            if "{" in line or paren_depth <= 0:
                in_sig = False
            new_lines.append(line)
            continue

        # Not in a signature - do replacements on the body
        new_line = line

        # Replace global accesses with ctx->
        # Pattern: identifier NOT preceded by '.', '->', or part of a type/declaration

        # For array accesses
        new_line = re.sub(r"(?<!\.)(?<!->)\bnfa\[", "ctx->nfa[", new_line)
        new_line = re.sub(r"(?<!\.)(?<!->)\bdfa\[", "ctx->dfa[", new_line)
        new_line = re.sub(r"(?<!\.)(?<!->)\balphabet\[", "ctx->alphabet[", new_line)
        new_line = re.sub(
            r"(?<!\.)(?<!->)\bdfa_hash_table\[", "ctx->dfa_hash_table[", new_line
        )
        new_line = re.sub(
            r"(?<!\.)(?<!->)\bdfa_next_in_bucket\[",
            "ctx->dfa_next_in_bucket[",
            new_line,
        )

        # For marker lists - but only when used as a pointer, not as a type
        if "MarkerList*" not in new_line and "sizeof(MarkerList)" not in new_line:
            new_line = re.sub(
                r"(?<!\.)(?<!->)\bdfa_marker_lists\b", "ctx->dfa_marker_lists", new_line
            )

        # For scalar globals - use word boundary
        new_line = re.sub(
            r"(?<!\.)(?<!->)\bnfa_state_count\b", "ctx->nfa_state_count", new_line
        )
        new_line = re.sub(
            r"(?<!\.)(?<!->)\bdfa_state_count\b", "ctx->dfa_state_count", new_line
        )
        new_line = re.sub(
            r"(?<!\.)(?<!->)\balphabet_size\b", "ctx->alphabet_size", new_line
        )
        new_line = re.sub(
            r"(?<!\.)(?<!->)\bmarker_list_count\b", "ctx->marker_list_count", new_line
        )
        new_line = re.sub(
            r"(?<!\.)(?<!->)\bpattern_identifier\b", "ctx->pattern_identifier", new_line
        )
        new_line = re.sub(
            r"(?<!\.)(?<!->)\bflag_verbose\b", "ctx->flag_verbose", new_line
        )

        # max_states - careful, this is also a parameter name in some functions
        # Only replace when NOT a parameter (i.e., not in a function signature)
        # Actually, in function bodies, max_states always refers to ctx->max_states
        # The parameter 'max_states' in epsilon_closure etc is a DIFFERENT variable (function param)
        # So we should NOT replace 'max_states' in function bodies because it might be a parameter
        # Actually wait - the parameter 'max_states' in epsilon_closure_with_markers is the parameter max_states
        # NOT ctx->max_states. So we should NOT replace max_states at all in function bodies.
        # The ctx->max_states is only used in init_hash_table and dfa_init.
        # Let's be selective: only replace in dfa_init and init_hash_table
        if "dfa_init" in new_line or "init_hash_table" in new_line:
            new_line = re.sub(
                r"(?<!\.)(?<!->)\bmax_states\b", "ctx->max_states", new_line
            )

        # Fix function calls to add ctx parameter
        new_line = new_line.replace("init_hash_table()", "init_hash_table(ctx)")
        new_line = new_line.replace("init_marker_lists()", "init_marker_lists(ctx)")
        new_line = new_line.replace("dfa_init()", "dfa_init(ctx)")
        new_line = new_line.replace("nfa_init()", "nfa_init(ctx)")
        new_line = new_line.replace("nfa_to_dfa()", "nfa_to_dfa(ctx)")
        new_line = new_line.replace("flatten_dfa()", "flatten_dfa(ctx)")

        # store_marker_list( -> store_marker_list(ctx,
        if (
            "store_marker_list(" in new_line
            and "store_marker_list(ctx," not in new_line
        ):
            new_line = new_line.replace("store_marker_list(", "store_marker_list(ctx, ")

        # collect_markers_from_states( -> collect_markers_from_states(ctx,
        if (
            "collect_markers_from_states(" in new_line
            and "collect_markers_from_states(ctx," not in new_line
        ):
            new_line = new_line.replace(
                "collect_markers_from_states(", "collect_markers_from_states(ctx, "
            )

        # find_dfa_state_hashed( -> find_dfa_state_hashed(ctx,
        if (
            "find_dfa_state_hashed(" in new_line
            and "find_dfa_state_hashed(ctx," not in new_line
        ):
            new_line = new_line.replace(
                "find_dfa_state_hashed(", "find_dfa_state_hashed(ctx, "
            )

        # epsilon_closure_with_markers( -> epsilon_closure_with_markers(ctx,
        if (
            "epsilon_closure_with_markers(" in new_line
            and "epsilon_closure_with_markers(ctx," not in new_line
        ):
            new_line = new_line.replace(
                "epsilon_closure_with_markers(", "epsilon_closure_with_markers(ctx, "
            )

        # epsilon_closure( -> epsilon_closure(ctx,
        if (
            "epsilon_closure(" in new_line
            and "epsilon_closure(ctx," not in new_line
            and "epsilon_closure_with" not in new_line
        ):
            new_line = new_line.replace("epsilon_closure(", "epsilon_closure(ctx, ")

        # collect_fork_categories( -> collect_fork_categories(ctx,
        if (
            "collect_fork_categories(" in new_line
            and "collect_fork_categories(ctx," not in new_line
        ):
            new_line = new_line.replace(
                "collect_fork_categories(", "collect_fork_categories(ctx, "
            )

        # dfa_add_state( -> dfa_add_state(ctx,
        if "dfa_add_state(" in new_line and "dfa_add_state(ctx," not in new_line:
            new_line = new_line.replace("dfa_add_state(", "dfa_add_state(ctx, ")

        # nfa_move( -> nfa_move(ctx,
        if "nfa_move(" in new_line and "nfa_move(ctx," not in new_line:
            new_line = new_line.replace("nfa_move(", "nfa_move(ctx, ")

        # collect_transition_markers( -> collect_transition_markers(ctx,
        if (
            "collect_transition_markers(" in new_line
            and "collect_transition_markers(ctx," not in new_line
        ):
            new_line = new_line.replace(
                "collect_transition_markers(", "collect_transition_markers(ctx, "
            )

        # write_dfa_file( -> write_dfa_file(ctx,
        if "write_dfa_file(" in new_line and "write_dfa_file(ctx," not in new_line:
            new_line = new_line.replace("write_dfa_file(", "write_dfa_file(ctx, ")

        # load_nfa_file( -> load_nfa_file(ctx,
        if "load_nfa_file(" in new_line and "load_nfa_file(ctx," not in new_line:
            new_line = new_line.replace("load_nfa_file(", "load_nfa_file(ctx, ")

        new_lines.append(new_line)

    content = "\n".join(new_lines)

    # Fix nfa_preminimize call - it takes (nfa, &nfa_state_count, &opts)
    # After our replacements, it should be (ctx->nfa, &ctx->nfa_state_count, &opts)
    # The regex should have handled this already

    # Fix dfa_minimize call
    # Should be dfa_minimize(ctx->dfa, ctx->dfa_state_count)

    # Fix dfa_compress call
    # Should be dfa_compress(ctx->dfa, ctx->dfa_state_count, &opts)

    # Update main function
    content = content.replace(
        "int main(int argc, char* argv[]) {",
        """int main(int argc, char* argv[]) {
    nfa2dfa_context_t* ctx = nfa2dfa_context_create();
    if (!ctx) { FATAL("Failed to create context"); return 1; }""",
    )

    # Add context destroy before the final return 0 in main
    # Find the last 'return 0;' and add destroy before it
    last_return = content.rfind("    return 0;")
    if last_return != -1:
        content = (
            content[:last_return]
            + "    nfa2dfa_context_destroy(ctx);\n    return 0;\n"
            + content[last_return + len("    return 0;") :]
        )

    # Fix any remaining double ctx->ctx->
    content = content.replace("ctx->ctx->", "ctx->")

    # Fix specific issues:
    # The nfa_preminimize function signature takes (nfa_state_t* nfa, int* state_count, ...)
    # After replacement it might be: nfa_preminimize(ctx->nfa, &ctx->nfa_state_count, &premin_opts)
    # This should be correct

    # The dfa_minimize takes (build_dfa_state_t* dfa, int state_count)
    # After replacement: dfa_minimize(ctx->dfa, ctx->dfa_state_count)
    # This should be correct

    # The dfa_compress takes (build_dfa_state_t* dfa, int state_count, compress_options_t* opts)
    # After replacement: dfa_compress(ctx->dfa, ctx->dfa_state_count, &opts)
    # This should be correct

    with open(os.path.join(SCRIPT_DIR, "nfa2dfa.c"), "w") as f:
        f.write(content)

    print("Transformation complete!")


if __name__ == "__main__":
    transform()
