# Test source files
set(TEST_SRCS
  test_radix_tree.c
  test_builder.c
  test_mock_fs.c
  test_main.c
  mock_fs.c
  test_radix_tree_extended.c
  test_builder_extended.c
  test_vfs_filter.c
  test_rule_engine.c
  test_arena.c
  test_builder_edge.c
  test_radix_tree_edge.c
  test_policy_parser.c
  test_landlock_bridge.c
  test_compilation_core.c
  test_compilation_internal.c
  test_compilation_remaining2.c
  test_compilation_remaining3.c
  test_compilation_final_gaps.c
  test_compilation_extra.c
  test_compilation_gaps.c
  test_compilation_binary.c
  test_compilation_layered.c
  test_fuzz_edge.c
  test_ruleset_management.c
  test_cache_associativity.c
)

# Create test executable
add_executable(test_runner ${TEST_SRCS})

# Link with library
target_link_libraries(test_runner PRIVATE landlock-builder)

# Use --wrap to intercept filesystem calls and redirect to mock versions
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_link_libraries(test_runner PRIVATE -Wl,--wrap=realpath -Wl,--wrap=stat -Wl,--wrap=lstat -Wl,--wrap=readlink -Wl,--wrap=opendir -Wl,--wrap=closedir -Wl,--wrap=readdir)
endif()

# Include directories
target_include_directories(test_runner
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Compiler warnings
setup_compiler_warnings(test_runner)

# Sanitizers - tests should use ASAN when enabled
if(ENABLE_ASAN)
  setup_sanitizers(test_runner)
endif()

# Add test command
add_test(NAME all_tests COMMAND test_runner)

# Print test info
message(STATUS "Configuring test suite")
message(STATUS "  - Test sources: ${TEST_SRCS}")
message(STATUS "  - ASAN enabled: ${ENABLE_ASAN}")
message(STATUS "  - Tests: ${BUILD_TESTING}")