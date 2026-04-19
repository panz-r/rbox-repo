# CLI tools - standalone executables that link against the libraries
# ============================================================================

# cdfatool - unified CLI for all DFA operations
add_executable(cdfatool dfa_cli.c)
target_link_libraries(cdfatool PRIVATE
    readonlybox_dfa
    readonlybox_dfa_eval
    cadical
    readonlybox_dfa_headers
)
target_compile_definitions(cdfatool PRIVATE
    USE_CADICAL
)

# nfa_builder - CLI tool for building NFAs from patterns
add_executable(nfa_builder nfa_builder.c)
target_link_libraries(nfa_builder PRIVATE
    readonlybox_dfa
    readonlybox_dfa_headers
)

# nfa2dfa_cli - CLI tool for NFA to DFA conversion
# Note: nfa2dfa_cli.c contains the CLI main() function
# The library code is in lib/nfa2dfa.c (compiled with NFABUILDER_NO_MAIN)
add_executable(nfa2dfa_cli nfa2dfa_cli.c)
target_link_libraries(nfa2dfa_cli PRIVATE
    readonlybox_dfa
    readonlybox_dfa_headers
)

# dfa2c_array - conversion tool
add_executable(dfa2c_array dfa2c_array.c)
target_link_libraries(dfa2c_array PRIVATE
    readonlybox_dfa
    readonlybox_dfa_headers
)

# dfa_eval_wrapper - used for fuzzing (eval-only)
add_executable(dfa_eval_wrapper dfa_eval_wrapper.c)
target_link_libraries(dfa_eval_wrapper PRIVATE
    readonlybox_dfa_eval
    readonlybox_dfa_headers
)
target_compile_definitions(dfa_eval_wrapper PRIVATE
    NFABUILDER_EXCLUDE_NFA_INIT
    USE_CADICAL
)

# ============================================================================
# Build Summary
# ============================================================================
add_custom_target(tools ALL DEPENDS
    readonlybox_dfa
    readonlybox_dfa_shared
    cdfatool
    nfa_builder
    nfa2dfa_cli
    dfa2c_array
    dfa_eval_wrapper
)
