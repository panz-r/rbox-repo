# Library source files
set(SRC_FILES
  arena.c
  radix_tree.c
  builder.c
  rule_engine.c
  rule_engine_compile.c
  rule_engine_diff.c
  policy_parser.c
  landlock_bridge.c
)

# Draugr hash table dependency
set(DRAUGR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../draugr)
list(APPEND SRC_FILES
  ${DRAUGR_DIR}/src/ht.c
  ${DRAUGR_DIR}/src/ht_cache.c
)

# Create library target
add_library(landlock-builder STATIC ${SRC_FILES})

# Include directories
target_include_directories(landlock-builder
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DRAUGR_DIR}/include
)

# Compiler warnings
setup_compiler_warnings(landlock-builder)

# Sanitizers
setup_sanitizers(landlock-builder)

# Export configuration
setup_export(landlock-builder)

# Compile options
if(ENABLE_LTO)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(landlock-builder PRIVATE -flto)
  endif()
endif()

# Optimization levels
target_compile_options(landlock-builder PRIVATE
  $<$<CONFIG:Release>:-O2>
  $<$<CONFIG:RelWithDebInfo>:-O2 -g>
  $<$<CONFIG:Debug>:-O0 -g>
)

# Note: MOCK_FS is only defined for test builds, not the library itself
# Tests will define MOCK_FS when building test_runner

# Install targets
install(TARGETS landlock-builder
  EXPORT landlock-builderTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)

# Generate config header
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/landlock-builder-config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/landlock-builder-config.h
)

target_include_directories(landlock-builder PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Print library info
message(STATUS "Configuring landlock-builder library")
message(STATUS "  - Sources: ${SRC_FILES}")
message(STATUS "  - LTO: ${ENABLE_LTO}")
message(STATUS "  - ASAN: ${ENABLE_ASAN}")
message(STATUS "  - Testing: ${BUILD_TESTING}")