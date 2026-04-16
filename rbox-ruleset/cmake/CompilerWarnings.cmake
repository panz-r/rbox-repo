# Compiler warnings configuration

function(setup_compiler_warnings target)
  if(MSVC)
    # Microsoft Visual C++
    target_compile_options(${target} PRIVATE
      /W4
      /wd4201  # nonstandard extension used: nameless struct/union
    )
  else()
    # GCC and Clang
    target_compile_options(${target} PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wshadow
      -Wconversion
      -Wsign-conversion
      -Wnull-dereference
      -Wdouble-promotion
      -Wformat=2
      -Werror=implicit-function-declaration
      -Werror=incompatible-pointer-types
      -Werror=int-conversion
    )
    
    # Clang-specific warnings
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
      target_compile_options(${target} PRIVATE
        -Weverything
        -Wno-padded
        -Wno-switch-enum
        -Wno-cast-qual
        -Wno-disabled-macro-expansion
        -Wno-documentation
        -Wno-documentation-unknown-command
        -Wno-exit-time-destructors
        -Wno-global-constructors
        -Wno-missing-prototypes
        -Wno-used-but-marked-unused
      )
    endif()
    
    # Debug builds get more warnings
    target_compile_options(${target} PRIVATE
      $<$<CONFIG:Debug>:
        -Wunused-parameter
        -Wunused-variable
        -Wunused-function
      >
    )
  endif()
endfunction()