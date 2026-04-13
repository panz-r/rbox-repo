# Test programs
# ============================================================================

# Test runner (dfa_test.c) - comprehensive test suite
# Note: dfa_test times out on full runs, use --test-set to limit scope
add_executable(dfa_test
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/dfa_test.c
)
target_link_libraries(dfa_test PRIVATE
    readonlybox_dfa
    sat_modules
    cadical
    readonlybox_dfa_headers
)

# Minimization integrity test
add_executable(test_minimize_integrity
    ${CMAKE_CURRENT_SOURCE_DIR}/test_minimize_integrity.c
)
target_link_libraries(test_minimize_integrity PRIVATE
    readonlybox_dfa
    sat_modules
    cadical
    readonlybox_dfa_headers
)

# Library API tests
add_executable(test_library_api
    ${CMAKE_CURRENT_SOURCE_DIR}/test_library_api.c
)
target_link_libraries(test_library_api PRIVATE
    readonlybox_dfa
    sat_modules
    cadical
    readonlybox_dfa_headers
)

# Eval-only test
add_executable(test_eval_only
    ${CMAKE_CURRENT_SOURCE_DIR}/test_eval_only.c
)
target_link_libraries(test_eval_only PRIVATE
    readonlybox_dfa
    readonlybox_dfa_headers
)

# Regression tests
add_executable(regression_test
    ${CMAKE_CURRENT_SOURCE_DIR}/regression_test.c
)
target_link_libraries(regression_test PRIVATE
    readonlybox_dfa
    sat_modules
    cadical
    readonlybox_dfa_headers
)

# ============================================================================
# Test Targets
# ============================================================================
add_custom_target(tests DEPENDS
    dfa_test
    test_minimize_integrity
    test_library_api
    test_eval_only
    regression_test
    testgen_test
)

# ============================================================================
# CTest Registration
# ============================================================================
enable_testing()

# All tests run from source directory (c-dfa/) for relative paths to work
set(TEST_WORKING_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

# dfa_test is excluded from ctest by default due to long runtime
# Run manually: ./build/tests/dfa_test --minimize-hopcroft --test-set A
# Or use: ctest -Ddtfa_test

add_test(NAME test_library_api
    COMMAND test_library_api
)
set_tests_properties(test_library_api PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 30
)

add_test(NAME test_eval_only
    COMMAND test_eval_only
)
set_tests_properties(test_eval_only PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 10
)
