# LibFuzzer harnesses for c-dfa
# Requires: clang with LibFuzzer support (-fsanitize=fuzzer)
#
# Build with:
#   cmake -B build -DENABLE_FUZZ=ON \
#       -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
#   cmake --build build

option(ENABLE_FUZZ "Enable LibFuzzer harnesses (requires clang with LibFuzzer)" OFF)

if(NOT ENABLE_FUZZ)
    message(STATUS "Fuzzers: DISABLED (use -DENABLE_FUZZ=ON to enable)")
    return()
endif()

message(STATUS "Fuzzers: ENABLED (using clang with LibFuzzer)")
message(STATUS "Note: If build fails, ensure clang is available and compile with:")
message(STATUS "  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++")

set(FUZZ_FLAGS_COMPILE
    -fsanitize=fuzzer,address,undefined
    -g
    -O1
    -fno-omit-frame-pointer
)

# C flags (no USE_CADICAL needed for simple fuzzers)
set(FUZZ_C_FLAGS
    -fsanitize=fuzzer,address,undefined
    -g
    -O1
    -fno-omit-frame-pointer
    -I${CMAKE_SOURCE_DIR}/include
)

# CXX flags (with USE_CADICAL for pipeline fuzzer)
set(FUZZ_CXX_FLAGS
    -fsanitize=fuzzer,address,undefined
    -g
    -O1
    -fno-omit-frame-pointer
    -I${CMAKE_SOURCE_DIR}/include
    -I${CMAKE_SOURCE_DIR}/vendor/cadical/src
    -DUSE_CADICAL
)

# Fuzz build directory (isolated from main build)
set(FUZZ_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/fuzz_build)

file(MAKE_DIRECTORY ${FUZZ_BUILD_DIR})

# ============================================================================
# C source files to compile for fuzzers
# ============================================================================

# Core library objects needed by dfa_eval_fuzzer and dfa_loader_fuzzer
set(FUZZ_CORE_LIB_OBJS
    ${FUZZ_BUILD_DIR}/dfa_eval.o
    ${FUZZ_BUILD_DIR}/dfa_loader.o
)

# Pipeline objects needed by pipeline_fuzzer
set(FUZZ_PIPELINE_LIB_OBJS
    ${FUZZ_BUILD_DIR}/pipeline.o
    ${FUZZ_BUILD_DIR}/build_dfa_state.o
    ${FUZZ_BUILD_DIR}/nfa2dfa_context.o
    ${FUZZ_BUILD_DIR}/nfa_builder_lib.o
    ${FUZZ_BUILD_DIR}/nfa_construct.o
    ${FUZZ_BUILD_DIR}/nfa_capture.o
    ${FUZZ_BUILD_DIR}/nfa_categories.o
    ${FUZZ_BUILD_DIR}/nfa_parser.o
    ${FUZZ_BUILD_DIR}/nfa_validate.o
    ${FUZZ_BUILD_DIR}/nfa_alphabet.o
    ${FUZZ_BUILD_DIR}/nfa2dfa.o
    ${FUZZ_BUILD_DIR}/dfa_minimize.o
    ${FUZZ_BUILD_DIR}/dfa_minimize_brzozowski.o
    ${FUZZ_BUILD_DIR}/dfa_minimize_sat.o
    ${FUZZ_BUILD_DIR}/dfa_layout.o
    ${FUZZ_BUILD_DIR}/dfa_compress.o
    ${FUZZ_BUILD_DIR}/dfa_compress_sat.o
    ${FUZZ_BUILD_DIR}/nfa_preminimize.o
    ${FUZZ_BUILD_DIR}/nfa_preminimize_sat.o
    ${FUZZ_BUILD_DIR}/nfa_preminimize_windowed.o
    ${FUZZ_BUILD_DIR}/nfa_preminimize_sat_optimal.o
    ${FUZZ_BUILD_DIR}/dfa_layout_sat.o
    ${FUZZ_BUILD_DIR}/pattern_order.o
    ${FUZZ_BUILD_DIR}/multi_target_array.o
    ${FUZZ_BUILD_DIR}/dfa_machine.o
    ${FUZZ_BUILD_DIR}/dfa_eval.o
    ${FUZZ_BUILD_DIR}/dfa_loader.o
)

# ============================================================================
# Build C objects with clang and special defines for tool sources
# ============================================================================

# Core src C objects
add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_eval.o
    COMMAND clang ${FUZZ_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/src/dfa_eval.c -o ${FUZZ_BUILD_DIR}/dfa_eval.o
    DEPENDS ${CMAKE_SOURCE_DIR}/src/dfa_eval.c
    COMMENT "Building dfa_eval.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_loader.o
    COMMAND clang ${FUZZ_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/src/dfa_loader.c -o ${FUZZ_BUILD_DIR}/dfa_loader.o
    DEPENDS ${CMAKE_SOURCE_DIR}/src/dfa_loader.c
    COMMENT "Building dfa_loader.o for fuzzer"
)

# lib C objects for pipeline
add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/pipeline.o
    COMMAND clang ${FUZZ_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/lib/pipeline.c -o ${FUZZ_BUILD_DIR}/pipeline.o
    DEPENDS ${CMAKE_SOURCE_DIR}/lib/pipeline.c
    COMMENT "Building pipeline.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/build_dfa_state.o
    COMMAND clang ${FUZZ_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/lib/build_dfa_state.c -o ${FUZZ_BUILD_DIR}/build_dfa_state.o
    DEPENDS ${CMAKE_SOURCE_DIR}/lib/build_dfa_state.c
    COMMENT "Building build_dfa_state.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa2dfa_context.o
    COMMAND clang ${FUZZ_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/lib/nfa2dfa_context.c -o ${FUZZ_BUILD_DIR}/nfa2dfa_context.o
    DEPENDS ${CMAKE_SOURCE_DIR}/lib/nfa2dfa_context.c
    COMMENT "Building nfa2dfa_context.o for fuzzer"
)

# tool C objects for pipeline (need NFABUILDER_NO_MAIN etc)
set(FUZZ_TOOL_C_FLAGS
    -fsanitize=fuzzer,address,undefined
    -g
    -O1
    -fno-omit-frame-pointer
    -I${CMAKE_SOURCE_DIR}/include
    -DNFABUILDER_NO_MAIN
    -DNFABUILDER_EXCLUDE_NFA_INIT
    -DNFA2DFA_BUILDING_LIB
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_builder_lib.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_builder_lib.c -o ${FUZZ_BUILD_DIR}/nfa_builder_lib.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_builder_lib.c
    COMMENT "Building nfa_builder_lib.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_construct.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_construct.c -o ${FUZZ_BUILD_DIR}/nfa_construct.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_construct.c
    COMMENT "Building nfa_construct.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_capture.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_capture.c -o ${FUZZ_BUILD_DIR}/nfa_capture.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_capture.c
    COMMENT "Building nfa_capture.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_categories.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_categories.c -o ${FUZZ_BUILD_DIR}/nfa_categories.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_categories.c
    COMMENT "Building nfa_categories.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_parser.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_parser.c -o ${FUZZ_BUILD_DIR}/nfa_parser.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_parser.c
    COMMENT "Building nfa_parser.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_validate.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_validate.c -o ${FUZZ_BUILD_DIR}/nfa_validate.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_validate.c
    COMMENT "Building nfa_validate.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_alphabet.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_alphabet.c -o ${FUZZ_BUILD_DIR}/nfa_alphabet.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_alphabet.c
    COMMENT "Building nfa_alphabet.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa2dfa.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa2dfa.c -o ${FUZZ_BUILD_DIR}/nfa2dfa.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa2dfa.c
    COMMENT "Building nfa2dfa.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_minimize.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/dfa_minimize.c -o ${FUZZ_BUILD_DIR}/dfa_minimize.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/dfa_minimize.c
    COMMENT "Building dfa_minimize.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_minimize_brzozowski.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/dfa_minimize_brzozowski.c -o ${FUZZ_BUILD_DIR}/dfa_minimize_brzozowski.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/dfa_minimize_brzozowski.c
    COMMENT "Building dfa_minimize_brzozowski.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_layout.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/dfa_layout.c -o ${FUZZ_BUILD_DIR}/dfa_layout.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/dfa_layout.c
    COMMENT "Building dfa_layout.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_compress.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/dfa_compress.c -o ${FUZZ_BUILD_DIR}/dfa_compress.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/dfa_compress.c
    COMMENT "Building dfa_compress.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_preminimize.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_preminimize.c -o ${FUZZ_BUILD_DIR}/nfa_preminimize.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_preminimize.c
    COMMENT "Building nfa_preminimize.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/pattern_order.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/pattern_order.c -o ${FUZZ_BUILD_DIR}/pattern_order.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/pattern_order.c
    COMMENT "Building pattern_order.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/multi_target_array.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/multi_target_array.c -o ${FUZZ_BUILD_DIR}/multi_target_array.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/multi_target_array.c
    COMMENT "Building multi_target_array.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_machine.o
    COMMAND clang ${FUZZ_TOOL_C_FLAGS} -c ${CMAKE_SOURCE_DIR}/src/dfa_machine.c -o ${FUZZ_BUILD_DIR}/dfa_machine.o
    DEPENDS ${CMAKE_SOURCE_DIR}/src/dfa_machine.c
    COMMENT "Building dfa_machine.o for fuzzer"
)

# ============================================================================
# Build C++ tool objects for pipeline (need NFABUILDER_NO_MAIN etc)
# ============================================================================

set(FUZZ_TOOL_CXX_FLAGS
    -fsanitize=fuzzer,address,undefined
    -g
    -O1
    -fno-omit-frame-pointer
    -I${CMAKE_SOURCE_DIR}/include
    -I${CMAKE_SOURCE_DIR}/vendor/cadical/src
    -DUSE_CADICAL
    -DNFABUILDER_NO_MAIN
    -DNFABUILDER_EXCLUDE_NFA_INIT
    -DNFA2DFA_BUILDING_LIB
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_minimize_sat.o
    COMMAND clang++ ${FUZZ_TOOL_CXX_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/dfa_minimize_sat.cpp -o ${FUZZ_BUILD_DIR}/dfa_minimize_sat.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/dfa_minimize_sat.cpp
    COMMENT "Building dfa_minimize_sat.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_compress_sat.o
    COMMAND clang++ ${FUZZ_TOOL_CXX_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/dfa_compress_sat.cpp -o ${FUZZ_BUILD_DIR}/dfa_compress_sat.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/dfa_compress_sat.cpp
    COMMENT "Building dfa_compress_sat.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_preminimize_sat.o
    COMMAND clang++ ${FUZZ_TOOL_CXX_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_preminimize_sat.cpp -o ${FUZZ_BUILD_DIR}/nfa_preminimize_sat.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_preminimize_sat.cpp
    COMMENT "Building nfa_preminimize_sat.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_preminimize_windowed.o
    COMMAND clang++ ${FUZZ_TOOL_CXX_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_preminimize_windowed.cpp -o ${FUZZ_BUILD_DIR}/nfa_preminimize_windowed.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_preminimize_windowed.cpp
    COMMENT "Building nfa_preminimize_windowed.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/nfa_preminimize_sat_optimal.o
    COMMAND clang++ ${FUZZ_TOOL_CXX_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/nfa_preminimize_sat_optimal.cpp -o ${FUZZ_BUILD_DIR}/nfa_preminimize_sat_optimal.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/nfa_preminimize_sat_optimal.cpp
    COMMENT "Building nfa_preminimize_sat_optimal.o for fuzzer"
)

add_custom_command(OUTPUT ${FUZZ_BUILD_DIR}/dfa_layout_sat.o
    COMMAND clang++ ${FUZZ_TOOL_CXX_FLAGS} -c ${CMAKE_SOURCE_DIR}/tools/dfa_layout_sat.cpp -o ${FUZZ_BUILD_DIR}/dfa_layout_sat.o
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/dfa_layout_sat.cpp
    COMMENT "Building dfa_layout_sat.o for fuzzer"
)

# ============================================================================
# Fuzzer Executables
# ============================================================================

# DFA evaluation fuzzer
add_executable(dfa_eval_fuzzer dfa_eval_fuzzer.cpp ${FUZZ_CORE_LIB_OBJS})
target_compile_options(dfa_eval_fuzzer PRIVATE ${FUZZ_CXX_FLAGS})
target_link_options(dfa_eval_fuzzer PRIVATE ${FUZZ_FLAGS_COMPILE} -lm)
add_custom_target(fuzz_dfa_eval ALL DEPENDS dfa_eval_fuzzer)

# Pattern parser fuzzer
add_executable(pattern_parse_fuzzer pattern_parse_fuzzer.cpp)
target_compile_options(pattern_parse_fuzzer PRIVATE ${FUZZ_CXX_FLAGS})
target_link_options(pattern_parse_fuzzer PRIVATE ${FUZZ_FLAGS_COMPILE} -lm)
add_custom_target(fuzz_pattern_parse ALL DEPENDS pattern_parse_fuzzer)

# NFA build fuzzer
add_executable(nfa_build_fuzzer nfa_build_fuzzer.cpp)
target_compile_options(nfa_build_fuzzer PRIVATE ${FUZZ_CXX_FLAGS})
target_link_options(nfa_build_fuzzer PRIVATE ${FUZZ_FLAGS_COMPILE} -lm)
add_custom_target(fuzz_nfa_build ALL DEPENDS nfa_build_fuzzer)

# Pipeline fuzzer - needs CaDiCaL for SAT-based optimization
set(CADICAL_LIB "${CMAKE_SOURCE_DIR}/vendor/cadical/build/libcadical.a")
add_executable(pipeline_fuzzer pipeline_fuzzer.cpp ${FUZZ_PIPELINE_LIB_OBJS})
target_compile_options(pipeline_fuzzer PRIVATE ${FUZZ_CXX_FLAGS})
target_link_options(pipeline_fuzzer PRIVATE ${FUZZ_FLAGS_COMPILE} -lstdc++ -lm)
target_link_libraries(pipeline_fuzzer PRIVATE "${CADICAL_LIB}")
add_custom_target(fuzz_pipeline ALL DEPENDS pipeline_fuzzer)

# DFA loader fuzzer
add_executable(dfa_loader_fuzzer dfa_loader_fuzzer.cpp ${FUZZ_CORE_LIB_OBJS})
target_compile_options(dfa_loader_fuzzer PRIVATE ${FUZZ_CXX_FLAGS})
target_link_options(dfa_loader_fuzzer PRIVATE ${FUZZ_FLAGS_COMPILE} -lm)
add_custom_target(fuzz_dfa_loader ALL DEPENDS dfa_loader_fuzzer)

# Master fuzz target
add_custom_target(fuzz ALL
    DEPENDS
        dfa_eval_fuzzer
        pattern_parse_fuzzer
        nfa_build_fuzzer
        pipeline_fuzzer
        dfa_loader_fuzzer
)

# Run 4-hour fuzzing session
add_custom_target(fuzz-4h
    COMMAND ${CMAKE_SOURCE_DIR}/fuzz/run_fuzzing_4h.sh ${CMAKE_BINARY_DIR} ${ARGN}
    COMMENT "Running 4-hour fuzzing session"
    VERBATIM
)

# Setup corpus directories
file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/fuzz/corpus/interesting/dfa_eval")
file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/fuzz/corpus/interesting/pattern_parser")
file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/fuzz/corpus/interesting/nfa_build")
file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/fuzz/corpus/interesting/pipeline")
file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/fuzz/corpus/interesting/loader")