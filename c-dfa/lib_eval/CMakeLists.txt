# Eval-only library sources
set(LIB_EVAL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_eval.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_loader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dfa_machine.c
)

# ============================================================================
# readonlybox_dfa_eval - Eval-only library (no building, just load and evaluate)
# ============================================================================
add_library(readonlybox_dfa_eval STATIC ${LIB_EVAL_SOURCES})
target_include_directories(readonlybox_dfa_eval PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
)
