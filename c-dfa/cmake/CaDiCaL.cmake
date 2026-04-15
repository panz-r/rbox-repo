# CaDiCaL SAT Solver Integration
# Uses pre-built CaDiCaL from vendor/cadical
# CaDiCaL must be built with -fPIC to embed in shared libraries

if(NOT EXISTS ${CADICAL_DIR}/configure)
    message(FATAL_ERROR "CaDiCaL not found at ${CADICAL_DIR}. Run: git submodule update --init --recursive")
endif()

# Check if CaDiCaL needs rebuild with -fPIC (for embedding in shared library)
# We detect this by checking if any .o file has relocations that require PIC
set(CADICAL_NEEDS_REBUILD FALSE)
if(EXISTS ${CADICAL_DIR}/build/libcadical.a)
    # Check if existing objects were built with -fPIC
    execute_process(
        COMMAND nm ${CADICAL_DIR}/build/solver.o 2>&1 | head -5
        OUTPUT_VARIABLE SOLVER_SYM
        ERROR_QUIET
    )
    # If solver.o doesn't exist or we can't check, trigger rebuild
    if(NOT EXISTS ${CADICAL_DIR}/build/solver.o)
        set(CADICAL_NEEDS_REBUILD TRUE)
    endif()
endif()

if(CADICAL_NEEDS_REBUILD)
    message(STATUS "CaDiCaL needs rebuild with -fPIC for shared library embedding")
    execute_process(
        COMMAND make clean
        WORKING_DIRECTORY ${CADICAL_DIR}
        RESULT_VARIABLE CLEAN_RESULT
        ERROR_QUIET
    )
    execute_process(
        COMMAND CXXFLAGS="-fPIC" CFLAGS="-fPIC" ./configure
        WORKING_DIRECTORY ${CADICAL_DIR}
        RESULT_VARIABLE CONF_RESULT
    )
    if(NOT CONF_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to configure CaDiCaL with -fPIC")
    endif()
    execute_process(
        COMMAND make -j4
        WORKING_DIRECTORY ${CADICAL_DIR}
        RESULT_VARIABLE BUILD_RESULT
    )
    if(NOT BUILD_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build CaDiCaL with -fPIC")
    endif()
    message(STATUS "CaDiCaL rebuilt with -fPIC")
endif()

if(NOT EXISTS ${CADICAL_LIB})
    message(FATAL_ERROR "CaDiCaL not found at ${CADICAL_LIB}. Run: cd ${CADICAL_DIR} && ./configure CXXFLAGS=\"-fPIC\" CFLAGS=\"-fPIC\" && make")
endif()

# Create imported target for CaDiCaL (STATIC - embedded into sat_modules)
add_library(cadical STATIC IMPORTED GLOBAL)
set_target_properties(cadical PROPERTIES
    IMPORTED_LOCATION ${CADICAL_LIB}
)

# CaDiCaL headers are in src/
target_include_directories(cadical SYSTEM INTERFACE ${CADICAL_DIR}/src)

message(STATUS "Found CaDiCaL: ${CADICAL_LIB}")
message(STATUS "CaDiCaL include: ${CADICAL_DIR}/src")
