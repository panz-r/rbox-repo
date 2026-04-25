# Testgen - Test Pattern Generation
# ============================================================================

set(TESTGEN_SOURCES
    testgen.cpp
    pattern_strategies.cpp
    expectation_gen.cpp
    inductive_builder.cpp
    pattern_factorization.cpp
    validation_helpers.cpp
    pattern_serializer.cpp
    command_utils.cpp
    edge_case_gen.cpp
    testgen_core.cpp
    testgen_operators.cpp
    testgen_mutation_tree.cpp
    pattern_matcher.cpp
)

# Library version for linking with other targets
add_library(testgen_lib STATIC ${TESTGEN_SOURCES})
target_include_directories(testgen_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
)
target_link_libraries(testgen_lib PUBLIC pthread readonlybox_dfa)

# Main testgen executable
add_executable(testgen main.cpp)
target_link_libraries(testgen PRIVATE testgen_lib)

# Unit test runner
add_executable(testgen_test
    testgen_test.cpp
    testgen_factorization_test.cpp
    testgen_validation_test.cpp
    testgen_strategies_test.cpp
    testgen_expectation_test.cpp
    testgen_inductive_builder_test.cpp
    testgen_serializer_test.cpp
    testgen_pattern_matcher_test.cpp
    testgen_pattern_matcher_fuzz.cpp
)
target_link_libraries(testgen_test PRIVATE testgen_lib)

add_custom_target(testgen_all DEPENDS testgen testgen_test)

# ============================================================================
# CTest Registration
# ============================================================================
include(CTest)
add_test(NAME testgen_test COMMAND testgen_test)
