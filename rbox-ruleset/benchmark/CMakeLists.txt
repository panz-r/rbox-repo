# Benchmark source
set(BENCH_SRCS
  benchmark.c
  mock_fs.c
)

# Create benchmark executable
add_executable(benchmark ${BENCH_SRCS})

# Link with library
target_link_libraries(benchmark PRIVATE landlock-builder)

# Include directories
target_include_directories(benchmark
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../tests
)

# Compiler warnings
setup_compiler_warnings(benchmark)

# Define MOCK_FS for benchmark
target_compile_definitions(benchmark PRIVATE MOCK_FS MOCK_FS_INTERNAL)

# Print benchmark info
message(STATUS "Configuring benchmark")
message(STATUS "  - Benchmark sources: ${BENCH_SRCS}")