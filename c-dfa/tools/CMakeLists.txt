# Tools and NFA/DFA processing modules
# ============================================================================

# All C sources for the library
set(LIB_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/dfa_eval.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/dfa_loader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/dfa_machine.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pipeline.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/build_dfa_state.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/nfa2dfa_context.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_builder_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_construct.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_capture.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_categories.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_validate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_alphabet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa2dfa.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_minimize.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_minimize_brzozowski.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_layout.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_compress.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_preminimize.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pattern_order.c
    ${CMAKE_CURRENT_SOURCE_DIR}/multi_target_array.c
)

# Note: nfa2dfa.c contains utility functions (init_hash_table, load_nfa_file, etc.)
# that are used by the pipeline. It is compiled with NFABUILDER_NO_MAIN to exclude
# its main() function from the library build.

# SAT C++ modules
set(SAT_CXX_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_minimize_sat.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_layout_sat.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_compress_sat.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_preminimize_sat.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_preminimize_windowed.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa_preminimize_sat_optimal.cpp
)

# ============================================================================
# readonlybox_dfa Static Library
# ============================================================================
add_library(readonlybox_dfa STATIC ${LIB_C_SOURCES})
target_compile_definitions(readonlybox_dfa PRIVATE
    NFABUILDER_NO_MAIN
    NFABUILDER_EXCLUDE_NFA_INIT
)
target_include_directories(readonlybox_dfa PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lib>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_link_libraries(readonlybox_dfa PUBLIC 
    readonlybox_dfa_headers
    cadical
)

# ============================================================================
# readonlybox_dfa Shared Library
# ============================================================================
add_library(readonlybox_dfa_shared SHARED ${LIB_C_SOURCES})
add_dependencies(readonlybox_dfa_shared sat_modules)
target_compile_definitions(readonlybox_dfa_shared PRIVATE
    NFABUILDER_NO_MAIN
    NFABUILDER_EXCLUDE_NFA_INIT
    USE_CADICAL
)
target_include_directories(readonlybox_dfa_shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lib>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_link_libraries(readonlybox_dfa_shared PRIVATE
    -Wl,--whole-archive $<TARGET_FILE:sat_modules> -Wl,--no-whole-archive
    readonlybox_dfa_headers
)
set_target_properties(readonlybox_dfa_shared PROPERTIES
    OUTPUT_NAME "readonlybox_dfa"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# ============================================================================
# SAT Modules Library
# sat_modules provides C++ SAT implementations and wraps CaDiCaL.
# All CaDiCaL usage goes through sat_modules.
# Compiled with -fvisibility=hidden -flto to hide C++ symbols, only C entry
# points are exported. Linked into readonlybox_dfa_shared via --whole-archive.
# ============================================================================
add_library(sat_modules STATIC ${SAT_CXX_SOURCES})
target_link_libraries(sat_modules PUBLIC
    readonlybox_dfa
    cadical
    readonlybox_dfa_headers
)
target_compile_definitions(sat_modules PUBLIC USE_CADICAL)
target_compile_options(sat_modules PRIVATE -fvisibility=hidden)
target_include_directories(sat_modules PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CADICAL_DIR}/src>
)

# ============================================================================
# Standalone Executables
# ============================================================================

# cdfatool - unified CLI for all DFA operations
add_executable(cdfatool dfa_cli.c)
target_link_libraries(cdfatool PRIVATE
    readonlybox_dfa
    sat_modules
    cadical
    readonlybox_dfa_headers
)
target_compile_definitions(cdfatool PRIVATE
    USE_CADICAL
)

# dfa_eval_wrapper - used for fuzzing
add_executable(dfa_eval_wrapper dfa_eval_wrapper.c)
target_link_libraries(dfa_eval_wrapper PRIVATE
    readonlybox_dfa
    sat_modules
    cadical
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
    sat_modules
    cdfatool
    dfa_eval_wrapper
)
