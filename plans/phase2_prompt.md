# Phase 2: NFA Edge Payloads & RDP Integration

## Context
The NFA builder must attach markers to transitions. Markers on epsilon transitions are "carried" by the path.

## Task
1.  **Update `tools/nfa_builder.c`**:
    *   **Transition Metadata**: Augment the internal NFA transition struct to store a `MarkerList`.
    *   **RDP Integration**:
        *   `parse_capture_start`: Assign a globally unique UID. Attach `START(pattern_id, uid)` to all outgoing transitions from the current state.
        *   `parse_capture_end`: Attach `END(pattern_id, uid)` to all incoming transitions to the current state.
    *   **UID Management**: Ensure every distinct capture pair in the file gets a globally unique ID (0 to 2^31).
2.  **Metadata Table**:
    *   Maintain the mapping of `UID -> Name String` for the `Capture Name Table` in Phase 1.

## Background for Implementation
*   If a marker is added to an epsilon transition, it is perfectly fine. The DFA converter will "collect" it when it collapses the epsilon-closure into a real character rule.
