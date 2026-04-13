cmake_minimum_required(VERSION 3.16)
project(landlock-builder
    VERSION     0.1.0
    LANGUAGES   C
    DESCRIPTION "Landlock policy builder library with text-policy rule engine"
)

set(CMAKE_C_STANDARD          11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS        OFF)

# Warn if building in-source
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(WARNING "In-source builds are discouraged. Use: cmake -B build && cmake --build build")
endif()

# -------------------------------------------------------------------
# Compiler warnings (equivalent to Makefile CFLAGS)
# -------------------------------------------------------------------
add_compile_options(-Wall -Wextra -Wpedantic)

# -------------------------------------------------------------------
# Static library: liblandlock-builder.a
#
# When consumed via add_subdirectory(), applications simply do:
#   add_subdirectory(vendor/landlock-builder)
#   target_link_libraries(myapp PRIVATE landlock-builder)
# CMake propagates include paths, link flags, and compile definitions
# transitively — no manual -I or -L flags needed.
# -------------------------------------------------------------------
add_library(landlock-builder STATIC
    src/arena.c
    src/radix_tree.c
    src/builder.c
    src/rule_engine.c
    src/rule_engine_compile.c
    src/policy_parser.c
    src/landlock_bridge.c
)

target_include_directories(landlock-builder
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# -------------------------------------------------------------------
# Mock filesystem layer (used by tests to intercept syscalls)
# -------------------------------------------------------------------
add_library(mock-fs STATIC
    tests/mock_fs.c
)

target_include_directories(mock-fs
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(mock-fs PRIVATE MOCK_FS)

# -------------------------------------------------------------------
# Test runner executable
# -------------------------------------------------------------------
set(TEST_SOURCES
    tests/test_radix_tree.c
    tests/test_builder.c
    tests/test_mock_fs.c
    tests/test_main.c
    tests/test_radix_tree_extended.c
    tests/test_builder_extended.c
    tests/test_vfs_filter.c
    tests/test_rule_engine.c
    tests/test_arena.c
    tests/test_builder_edge.c
    tests/test_radix_tree_edge.c
    tests/test_policy_parser.c
    tests/test_landlock_bridge.c
    tests/test_compilation_core.c
    tests/test_compilation_internal.c
    tests/test_compilation_remaining2.c
    tests/test_compilation_remaining3.c
    tests/test_compilation_final_gaps.c
    tests/test_compilation_extra.c
    tests/test_compilation_gaps.c
    tests/test_compilation_binary.c
    tests/test_compilation_layered.c
    tests/test_fuzz_edge.c
)

add_executable(test_runner ${TEST_SOURCES})

target_include_directories(test_runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
)

target_compile_definitions(test_runner PRIVATE MOCK_FS)

target_link_libraries(test_runner PRIVATE landlock-builder mock-fs)

# Register with CTest for `ctest` / `make test` integration
enable_testing()
add_test(NAME landlock-builder-tests COMMAND test_runner)
set_tests_properties(landlock-builder-tests PROPERTIES TIMEOUT 120)

# -------------------------------------------------------------------
# Benchmark executable
# -------------------------------------------------------------------
add_executable(benchmark tests/benchmark.c)

target_include_directories(benchmark PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/tests
)

target_compile_definitions(benchmark PRIVATE MOCK_FS MOCK_FS_INTERNAL)

target_link_libraries(benchmark PRIVATE landlock-builder mock-fs)

# -------------------------------------------------------------------
# Install rules (for system-wide or prefix installation)
# -------------------------------------------------------------------
include(GNUInstallDirs)

install(TARGETS landlock-builder
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# Generate CMake config file for find_package() after install
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/landlock-builder-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/landlock-builder-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/landlock-builder-config.cmake"
    @ONLY
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/landlock-builder-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/landlock-builder-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/landlock-builder
)

install(EXPORT landlock-builder-targets
    FILE landlock-builder-targets.cmake
    NAMESPACE landlock-builder::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/landlock-builder
)

install(TARGETS landlock-builder
    EXPORT landlock-builder-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# -------------------------------------------------------------------
# CPack configuration (optional: .deb/.rpm/tarball generation)
# -------------------------------------------------------------------
set(CPACK_PACKAGE_NAME        "landlock-builder")
set(CPACK_PACKAGE_VERSION     ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Landlock policy builder library")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
endif()
set(CPACK_SOURCE_IGNORE_FILES
    "/\\.git/" "/build/" "/_cmake_build/" "/CMakeFiles/" "CMakeCache.txt"
)
include(CPack)
