# Sanitizers configuration

function(setup_sanitizers target)
  if(ENABLE_ASAN)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      message(STATUS "Enabling AddressSanitizer for target: ${target}")
      
      # Compiler flags
      target_compile_options(${target} PRIVATE
        -fsanitize=address
        -fsanitize=leak
        -fsanitize=undefined
        -fno-omit-frame-pointer
        -O1  # Recommended optimization level for ASAN
      )
      
      # Linker flags
      target_link_options(${target} PRIVATE
        -fsanitize=address
        -fsanitize=leak
        -fsanitize=undefined
      )
      
      # ASAN requires debug symbols
      target_compile_options(${target} PRIVATE -g)
      
      # Disable optimizations that interfere with ASAN
      if(CMAKE_BUILD_TYPE STREQUAL "Release")
        message(WARNING "ASAN is enabled with Release build - consider using RelWithDebInfo")
      endif()
      
    else()
      message(WARNING "ASAN not supported for compiler: ${CMAKE_C_COMPILER_ID}")
    endif()
  endif()
endfunction()