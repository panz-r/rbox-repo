# Test programs
# ============================================================================

# Test runner (dfa_test.c) - comprehensive test suite
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

# CTest can run tests in parallel with: ctest --parallel <N>
# Or use: ctest -j <N>

# -----------------------------------------------------------------------------
# dfa_test test sets (A through G)
# -----------------------------------------------------------------------------

add_test(NAME dfa_test_set_a
    COMMAND dfa_test --minimize-moore --compress-sat --test-set A)
set_tests_properties(dfa_test_set_a PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_a")

add_test(NAME dfa_test_set_b
    COMMAND dfa_test --minimize-hopcroft --compress-sat --test-set B)
set_tests_properties(dfa_test_set_b PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_b")

add_test(NAME dfa_test_set_c
    COMMAND dfa_test --minimize-moore --compress-sat --test-set C)
set_tests_properties(dfa_test_set_c PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_c")

add_test(NAME dfa_test_set_d
    COMMAND dfa_test --minimize-moore --compress-sat --test-set D)
set_tests_properties(dfa_test_set_d PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_d")

add_test(NAME dfa_test_set_e
    COMMAND dfa_test --minimize-moore --compress-sat --test-set E)
set_tests_properties(dfa_test_set_e PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_e")

add_test(NAME dfa_test_set_f
    COMMAND dfa_test --minimize-moore --compress-sat --test-set F)
set_tests_properties(dfa_test_set_f PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_f")

add_test(NAME dfa_test_set_g
    COMMAND dfa_test --minimize-moore --compress-sat --test-set G)
set_tests_properties(dfa_test_set_g PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_g")

add_test(NAME dfa_test_set_h
    COMMAND dfa_test --minimize-moore --compress-sat --test-set H)
set_tests_properties(dfa_test_set_h PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_h")

add_test(NAME dfa_test_set_i
    COMMAND dfa_test --minimize-moore --compress-sat --test-set I)
set_tests_properties(dfa_test_set_i PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_i")

add_test(NAME dfa_test_set_j
    COMMAND dfa_test --minimize-moore --compress-sat --test-set J)
set_tests_properties(dfa_test_set_j PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_j")

add_test(NAME dfa_test_set_k
    COMMAND dfa_test --minimize-moore --compress-sat --test-set K)
set_tests_properties(dfa_test_set_k PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 300
    LABELS "dfa_test;set_k")

# -----------------------------------------------------------------------------
# Other test suites
# -----------------------------------------------------------------------------

add_test(NAME test_minimize_integrity
    COMMAND test_minimize_integrity)
set_tests_properties(test_minimize_integrity PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 60
    LABELS "other")

add_test(NAME test_library_api
    COMMAND test_library_api)
set_tests_properties(test_library_api PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 60
    LABELS "other")

add_test(NAME test_eval_only
    COMMAND test_eval_only)
set_tests_properties(test_eval_only PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 30
    LABELS "other")

add_test(NAME regression_test
    COMMAND regression_test)
set_tests_properties(regression_test PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    TIMEOUT 60
    LABELS "other")

# ============================================================================
# CTest Output Configuration
# ============================================================================

# Show full output on failure (use ctest --output-on-failure)
# For verbose output from tests themselves, use: ctest -V
# For XML output (JUnit format), use: ctest -T Test --output-on-failure
