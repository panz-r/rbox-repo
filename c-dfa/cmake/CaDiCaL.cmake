# CaDiCaL SAT Solver Integration
# Uses pre-built CaDiCaL from vendor/cadical

if(NOT EXISTS ${CADICAL_LIB})
    message(FATAL_ERROR "CaDiCaL not found at ${CADICAL_LIB}. Run: cd ${CADICAL_DIR} && ./configure && make")
endif()

# Create imported target for CaDiCaL
add_library(cadical STATIC IMPORTED GLOBAL)
set_target_properties(cadical PROPERTIES
    IMPORTED_LOCATION ${CADICAL_LIB}
)

# CaDiCaL headers are in src/
target_include_directories(cadical SYSTEM INTERFACE ${CADICAL_DIR}/src)

message(STATUS "Found CaDiCaL: ${CADICAL_LIB}")
message(STATUS "CaDiCaL include: ${CADICAL_DIR}/src")
