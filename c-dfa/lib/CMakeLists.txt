# Library sources - all reusable code
set(LIB_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/pipeline.c
    ${CMAKE_CURRENT_SOURCE_DIR}/build_dfa_state.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nfa2dfa_context.c
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
    # SAT C++ modules
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
add_library(readonlybox_dfa STATIC ${LIB_SOURCES})
target_compile_definitions(readonlybox_dfa PRIVATE
    NFABUILDER_NO_MAIN
    NFABUILDER_EXCLUDE_NFA_INIT
    USE_CADICAL
)
target_include_directories(readonlybox_dfa PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>
    $<BUILD_INTERFACE:${CADICAL_DIR}/src>
)
target_link_libraries(readonlybox_dfa PUBLIC
    readonlybox_dfa_headers
    cadical
)

# ============================================================================
# readonlybox_dfa Shared Library
# ============================================================================
add_library(readonlybox_dfa_shared SHARED ${LIB_SOURCES})
target_compile_definitions(readonlybox_dfa_shared PRIVATE
    NFABUILDER_NO_MAIN
    NFABUILDER_EXCLUDE_NFA_INIT
    USE_CADICAL
)
target_include_directories(readonlybox_dfa_shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>
    $<BUILD_INTERFACE:${CADICAL_DIR}/src>
)
target_link_libraries(readonlybox_dfa_shared PRIVATE
    readonlybox_dfa_headers
)
set_target_properties(readonlybox_dfa_shared PROPERTIES
    OUTPUT_NAME "readonlybox_dfa"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)
