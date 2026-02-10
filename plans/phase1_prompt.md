# Phase 1: Binary Format & Scalable Metadata

## Context
The DFA format must support an arbitrary number of capture names and rule-based markers.

## Task
1.  **Update `include/dfa_types.h`**:
    *   **`dfa_rule_t`**: Replace reserved bytes with `uint32_t marker_offset`.
    *   **`dfa_state_t`**: Add `uint32_t eos_marker_offset`.
    *   **Metadata Block**: Define a structure for the new `metadata_offset` in the header.
2.  **Scalable Metadata Table**:
    *   Implement a table: `[EntryCount][Entry1: pattern_id, name_len, name_data...][Entry2...]`.
    *   This allows the system to scale to thousands of unique names.
3.  **Marker Block**:
    *   Pack markers as `uint32_t`: `[16-bit PatternID][15-bit UID][1-bit Type]`.
    *   Lists are terminated by a `0xFFFFFFFF` sentinel.
4.  **Update `tools/nfa2dfa.c`**:
    *   Update `write_dfa_file` to serialize the new block order: `Header -> Identifier -> Name Table -> States -> Rules -> Marker Block`.

## Background for Implementation
*   Every offset must be an **absolute byte offset** from the start of the DFA data.
*   Rule `target` offsets must be fixed to point to the correct byte position of the target state.
