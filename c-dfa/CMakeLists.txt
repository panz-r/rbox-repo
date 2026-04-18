cmake_minimum_required(VERSION 3.20)
project(readonlybox_dfa
    VERSION 1.0.0
    LANGUAGES C CXX
    DESCRIPTION "High-performance C DFA for fast command validation"
)

# ============================================================================
# Build Options
# ============================================================================
option(ENABLE_SAT "Enable SAT-based minimization (requires CaDiCaL)" ON)
option(ENABLE_COVERAGE "Enable coverage instrumentation" OFF)
option(ENABLE_FUZZ "Enable LibFuzzer harnesses (requires clang)" OFF)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# ============================================================================
# C/C++ Standards
# ============================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# Compiler Warnings - target-specific
# ============================================================================
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ============================================================================
# Build Type Configurations
# ============================================================================
set(RELEASE_COMPILE_FLAGS "-O3 -mcmodel=medium")
set(DEBUG_COMPILE_FLAGS "-g -O0 -mcmodel=medium")

# Apply sanitizer flags in debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    string(APPEND RELEASE_COMPILE_FLAGS " -fsanitize=address,undefined")
endif()

# Coverage
if(ENABLE_COVERAGE)
    string(APPEND CMAKE_C_FLAGS_DEBUG " -fprofile-arcs -ftest-coverage")
    string(APPEND CMAKE_CXX_FLAGS_DEBUG " -fprofile-arcs -ftest-coverage")
    string(APPEND CMAKE_EXE_LINKER_FLAGS_DEBUG " --coverage")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS_DEBUG " --coverage")
endif()

# ============================================================================
# LTO (Link Time Optimization) Configuration
# ============================================================================
# Enable LTO for Release and RelWithDebInfo builds to improve optimization
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    # Enable IPO globally - CMake adds -flto automatically for GCC/Clang
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    
    message(STATUS "LTO enabled")
endif()

# ============================================================================
# CaDiCaL SAT Solver
# ============================================================================
set(CADICAL_DIR "${CMAKE_SOURCE_DIR}/vendor/cadical")
set(CADICAL_LIB "${CADICAL_DIR}/build/libcadical.a")

include(${CMAKE_SOURCE_DIR}/cmake/CaDiCaL.cmake)

# ============================================================================
# Interface Library for Public Headers
# ============================================================================
add_library(readonlybox_dfa_headers INTERFACE)
target_include_directories(readonlybox_dfa_headers INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(readonlybox_dfa_headers INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/tools
)

# ============================================================================
# Build Libraries and Tools
# ============================================================================
add_subdirectory(tools)
add_subdirectory(tests)
add_subdirectory(testgen)
add_subdirectory(fuzz)

# ============================================================================
# CTest
# ============================================================================
include(CTest)

# ============================================================================
# Full Test Suite (equivalent to old `make test`)
# ============================================================================

# Run all test suites using the Python aggregator script
add_custom_target(test-full
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_test_suite.py --build-dir ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS
        dfa_test
        test_minimize_integrity
        test_library_api
        test_eval_only
        regression_test
)

# ============================================================================
# Build Verification
# ============================================================================

find_program(NM_COMMAND nm REQUIRED)
find_program(OBJDUMP_COMMAND objdump REQUIRED)

add_custom_target(verify
    DEPENDS readonlybox_dfa_shared sat_modules
    COMMENT "Running build verification checks"
)

add_custom_command(TARGET verify
    COMMAND ${CMAKE_SOURCE_DIR}/cmake/verify_build.sh ${CMAKE_BINARY_DIR}
    COMMENT "Running verification script"
)

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "=== ${PROJECT_NAME} build configuration ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CaDiCaL support: ${ENABLE_SAT}")
message(STATUS "Coverage: ${ENABLE_COVERAGE}")
message(STATUS "Fuzzers: ${ENABLE_FUZZ}")
message(STATUS "")
