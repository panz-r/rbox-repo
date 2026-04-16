cmake_minimum_required(VERSION 3.15)
project(landlock-builder VERSION 1.0.0 LANGUAGES C)

# Project description
set(PROJECT_DESCRIPTION "Landlock-based access control library with policy compilation and evaluation")
set(PROJECT_HOMEPAGE "https://github.com/yourorg/landlock-builder")

# Build options
option(BUILD_TESTING "Build test suite" ON)
option(ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(ENABLE_LTO "Enable Link-Time Optimization" ON)
option(BUILD_BENCHMARK "Build benchmark programs" OFF)

# Compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Compiler warnings module
include(CompilerWarnings)

# Sanitizers module
include(Sanitizers)

# Export configuration
include(Export)

# Library target
add_subdirectory(src)

# Tests
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

# Benchmarks
if(BUILD_BENCHMARK)
  add_subdirectory(benchmark)
endif()

# Install targets
include(CMakePackageConfigHelpers)
install(EXPORT landlock-builderTargets
  FILE landlock-builderTargets.cmake
  NAMESPACE landlock::
  DESTINATION lib/cmake/landlock-builder
)

# Config file generation
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/landlock-builder-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/landlock-builder-config.cmake
  @ONLY
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/landlock-builder-config.cmake
  DESTINATION lib/cmake/landlock-builder
)

# Print build configuration
message(STATUS "Build configuration:")
message(STATUS "  - C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  - Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  - Testing: ${BUILD_TESTING}")
message(STATUS "  - ASAN: ${ENABLE_ASAN}")
message(STATUS "  - LTO: ${ENABLE_LTO}")
message(STATUS "  - Benchmarks: ${BUILD_BENCHMARK}")