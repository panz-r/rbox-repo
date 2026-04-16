# Export configuration

function(setup_export target)
  # Set visibility to hidden by default
  set_target_properties(${target} PROPERTIES
    C_VISIBILITY_PRESET hidden
  )
  
  # For static libraries, ensure proper positioning
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(${target} PRIVATE
      -Wl,--whole-archive
      $<TARGET_OBJECTS:${target}>
      -Wl,--no-whole-archive
    )
  endif()
  
  # Export headers
  install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../include/
    DESTINATION include
    FILES_MATCHING
      PATTERN "*.h"
  )
  
  # Generate export header for public API
  set(PUBLIC_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/rule_engine.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/landlock_builder.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/policy_parser.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/landlock_bridge.h
  )
  
  # Create version script for symbol control
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(VERSION_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/${target}.version)
    file(WRITE ${VERSION_SCRIPT} "{\n  global:\n")
    
    # Extract public symbols from headers - simplified approach
    # Instead of complex regex, we'll use known public API functions
    set(KNOWN_PUBLIC_FUNCTIONS
      soft_ruleset_new
      soft_ruleset_free
      soft_ruleset_add_rule
      soft_ruleset_compile
      soft_ruleset_check_ctx
      soft_ruleset_check_batch_ctx
      soft_ruleset_remove_rule
      soft_ruleset_clone
      soft_ruleset_merge
      soft_ruleset_diff
      soft_ruleset_save_compiled
      soft_ruleset_load_compiled
      soft_ruleset_is_compiled
      soft_ruleset_rule_count
      soft_ruleset_layer_count
      soft_ruleset_get_rule_info
      soft_ruleset_set_layer_type
      soft_ruleset_add_rule_at_layer
      soft_ruleset_remove_rule_at_index
      soft_ruleset_get_layer_info
      soft_ruleset_meld
      soft_ruleset_meld_into
      soft_ruleset_meld_at_layer
      soft_ruleset_meld_ruleset
      soft_ruleset_meld_ruleset_at_layer
      soft_ruleset_meld_ruleset_with_depth
      soft_ruleset_insert_at_layer
      soft_ruleset_insert_ruleset_at_layer
      soft_ruleset_insert_ruleset_at_layer_with_depth
      soft_ruleset_diff_free
      soft_ruleset_validate_for_landlock
      soft_ruleset_prepare_for_landlock
      soft_ruleset_get_landlock_rules
      soft_ruleset_get_stats
      soft_ruleset_reset_stats
      soft_ruleset_get_compiled_size
      soft_ruleset_get_compiled_rules
      soft_ruleset_get_compiled_layers
      soft_ruleset_get_compiled_layer_rules
      soft_ruleset_get_compiled_layer_type
      soft_ruleset_get_compiled_layer_count
      soft_ruleset_get_compiled_rule_count
      soft_ruleset_get_compiled_total_rules
      soft_ruleset_get_compiled_effective_rules
      soft_ruleset_get_compiled_shadowed_rules
      soft_ruleset_get_compiled_subsumed_rules
      soft_ruleset_get_compiled_identical_rules
      soft_ruleset_get_compiled_duplicate_rules
      soft_ruleset_get_compiled_invalid_rules
      soft_ruleset_get_compiled_warning_count
      soft_ruleset_get_compiled_error_count
      soft_ruleset_get_compiled_compilation_time
      soft_ruleset_get_compiled_peak_memory
      soft_ruleset_get_compiled_current_memory
      soft_ruleset_get_compiled_total_allocations
      soft_ruleset_get_compiled_total_frees
      soft_ruleset_get_compiled_current_allocations
      soft_ruleset_get_compiled_peak_allocations
      soft_ruleset_get_compiled_total_reallocations
      soft_ruleset_get_compiled_total_realloc_size
      soft_ruleset_get_compiled_total_strdup
      soft_ruleset_get_compiled_total_strdup_size
      soft_ruleset_get_compiled_total_strdup_count
      soft_ruleset_get_compiled_total_strdup_peak
      soft_ruleset_get_compiled_total_strdup_current
      soft_ruleset_get_compiled_total_arena_allocations
      soft_ruleset_get_compiled_total_arena_size
      soft_ruleset_get_compiled_total_arena_peak
      soft_ruleset_get_compiled_total_arena_current
      soft_ruleset_get_compiled_total_arena_allocations
      soft_ruleset_get_compiled_total_arena_size
      soft_ruleset_get_compiled_total_arena_peak
      soft_ruleset_get_compiled_total_arena_current
    )
    
    foreach(func ${KNOWN_PUBLIC_FUNCTIONS})
      file(APPEND ${VERSION_SCRIPT} "    ${func};\n")
    endforeach()
    
    file(APPEND ${VERSION_SCRIPT} "  local:\n    *;\n};\n")
    
    set_target_properties(${target} PROPERTIES
      LINK_FLAGS "-Wl,--version-script,${VERSION_SCRIPT}"
    )
  endif()
endfunction()