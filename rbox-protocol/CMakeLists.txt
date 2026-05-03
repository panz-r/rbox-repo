cmake_minimum_required(VERSION 3.10)
project(rbox-protocol C)

# Enable testing
enable_testing()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Standard compile flags
set(CMAKE_C_FLAGS_INIT "-Wall -Wextra -std=gnu11 -pthread -fPIC")
set(CMAKE_C_FLAGS_DEBUG_INIT "-g -O0")
set(CMAKE_C_FLAGS_RELEASE_INIT "-O2")

# Option to enable AddressSanitizer
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)

# Option to enable ThreadSanitizer
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

# ASAN and TSAN are mutually exclusive
if(ENABLE_ASAN AND ENABLE_TSAN)
    message(FATAL_ERROR "ASAN and TSAN cannot be enabled simultaneously")
endif()

# Apply ASAN flags
if(ENABLE_ASAN)
    message(STATUS "AddressSanitizer enabled")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -O1 -g -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
endif()

# Apply TSAN flags
if(ENABLE_TSAN)
    message(STATUS "ThreadSanitizer enabled")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -O1 -g -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=thread")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/../shellsplit/include)
include_directories(${CMAKE_SOURCE_DIR}/../draugr/include)

# Define DEBUG_PRINTS for development builds
add_definitions(-DDEBUG_PRINTS=1)

# Shellsplit (static library)
set(SHELLSPLIT_SRC ${CMAKE_SOURCE_DIR}/../shellsplit/src/shell_tokenizer.c)
add_library(shellsplit STATIC ${SHELLSPLIT_SRC})
target_compile_options(shellsplit PRIVATE -Wall -Wextra -std=gnu11 -pthread -fPIC)

# Draugr hash table dependency
set(DRAUGR_DIR ${CMAKE_SOURCE_DIR}/../draugr)

# Source files for rbox-protocol library
set(LIB_SOURCES
    src/socket_io.c
    src/protocol.c
    src/runtime.c
    src/session.c
    src/server_client.c
    src/rbox_cache.c
    src/socket.c
    src/packet.c
    src/parser.c
    src/server.c
    src/protocol_encoding.c
    src/protocol_decoding.c
    src/timer_heap.c
    src/log.c
    ${DRAUGR_DIR}/src/ht.c
    ${DRAUGR_DIR}/src/ht_cache.c
)

# Build shared library
add_library(rbox_protocol SHARED ${LIB_SOURCES})
target_link_libraries(rbox_protocol PRIVATE shellsplit pthread m atomic)
set_target_properties(rbox_protocol PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    INSTALL_RPATH "$ORIGIN"
)

# Create additional symlink for unversioned .so (for Makefile compatibility)
add_custom_command(TARGET rbox_protocol POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink 
        ${CMAKE_CURRENT_BINARY_DIR}/librbox_protocol.so.1.0.0 
        ${CMAKE_CURRENT_SOURCE_DIR}/librbox_protocol.so
    COMMENT "Creating unversioned symlink in source dir"
)

# Compiler warnings for the library
target_compile_options(rbox_protocol PRIVATE -Wall -Wextra -std=gnu11 -pthread -fPIC)

# Helper macro to add a test
macro(add_rbox_test test_name test_source)
    add_executable(${test_name} ${test_source})
    target_link_libraries(${test_name} PRIVATE rbox_protocol pthread m atomic)
    if(ENABLE_ASAN OR ENABLE_TSAN)
        # Sanitizers already applied via CMAKE_C_FLAGS
    endif()
    # Ensure the test uses the local library
    if(UNIX)
        target_link_libraries(${test_name} PRIVATE "-Wl,-rpath,$ORIGIN")
    endif()
endmacro()

# Unit/integration tests
add_rbox_test(test_protocol tests/test_protocol.c)
add_test(NAME test_protocol COMMAND test_protocol)

add_rbox_test(test_protocol_full tests/test_protocol_full.c)
add_test(NAME test_protocol_full COMMAND test_protocol_full)

add_rbox_test(test_integration tests/test_integration.c)
add_test(NAME test_integration COMMAND test_integration)

add_rbox_test(test_blocking_server tests/test_blocking_server.c)
add_test(NAME test_blocking_server COMMAND test_blocking_server)

add_rbox_test(test_persistent tests/test_persistent.c)
add_test(NAME test_persistent COMMAND test_persistent)

add_rbox_test(test_env_decisions tests/test_env_decisions.c)
add_test(NAME test_env_decisions COMMAND test_env_decisions)

add_rbox_test(test_stress tests/test_stress.c)
add_test(NAME test_stress COMMAND test_stress)

add_rbox_test(test_cache tests/test_cache.c)
add_test(NAME test_cache COMMAND test_cache)

add_rbox_test(test_protocol_encoding tests/test_protocol_encoding.c)
add_test(NAME test_protocol_encoding COMMAND test_protocol_encoding)

add_rbox_test(test_protocol_decoding tests/test_protocol_decoding.c)
add_test(NAME test_protocol_decoding COMMAND test_protocol_decoding)

add_rbox_test(test_log tests/test_log.c)
add_test(NAME test_log COMMAND test_log)

add_rbox_test(test_timer_heap tests/test_timer_heap.c)
add_test(NAME test_timer_heap COMMAND test_timer_heap)

add_rbox_test(test_versioning tests/test_versioning.c)
add_test(NAME test_versioning COMMAND test_versioning)

# Custom target to run all tests sequentially
add_custom_target(test-all
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run-tests.sh ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running all tests..."
    DEPENDS test_protocol test_protocol_full test_integration test_blocking_server
            test_persistent test_env_decisions test_stress test_cache
            test_protocol_encoding test_protocol_decoding test_log
            test_timer_heap test_versioning
)

# Fuzzer (optional - only if libfuzz is available)
find_library(FUZZ_LIBRARY libFuzzer.a HINTS /usr/lib )
if(FUZZ_LIBRARY)
    message(STATUS "Found libFuzzer: ${FUZZ_LIBRARY}")
else()
    message(STATUS "libFuzzer not found - fuzzer will not be built")
endif()

# Installation rules
install(TARGETS rbox_protocol LIBRARY DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

# Create symlink in build dir for SONAME resolution
add_custom_command(TARGET rbox_protocol POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink 
        ${CMAKE_CURRENT_BINARY_DIR}/librbox_protocol.so.1.0.0 
        ${CMAKE_CURRENT_BINARY_DIR}/librbox_protocol.so
    COMMENT "Creating symlink for SONAME resolution in build dir"
)

# Print configuration summary
message(STATUS "")
message(STATUS "=== rbox-protocol build configuration ===")
message(STATUS "Source dir: ${CMAKE_SOURCE_DIR}")
message(STATUS "Build dir: ${CMAKE_CURRENT_BINARY_DIR}")
message(STATUS "ASAN: ${ENABLE_ASAN}")
message(STATUS "TSAN: ${ENABLE_TSAN}")
message(STATUS "==========================================")
message(STATUS "")
