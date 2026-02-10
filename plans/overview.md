# Capture System Implementation Overview (Industrial Mealy Replay)

This system implements high-precision, scalable capture extraction by treating markers as "output" produced by transitions.

## Architectural Core
1.  **Mealy Transitions**: Every DFA rule (`dfa_rule_t`) and the `eos_target` path carry a `marker_offset`. This points to a variable-length list of marker events.
2.  **Winner-Filtered Two-Pass**:
    *   **Pass 1 (The Scout)**: High-speed O(N) traversal. Records the `trace_buffer[]` (sequence of state IDs) and identifies the **Winning Pattern ID**.
    *   **Pass 2 (The Scribe)**: Replays the trace. For every transition, it iterates through its markers but **only processes those belonging to the Winning Pattern ID**.
3.  **Marker Harvesting**: During construction, markers from epsilon-closures are aggregated into the literal DFA transitions that "trigger" them.
4.  **LIFO Balancing**: A stack-based extractor ensures only balanced START/END pairs produce results.

## Component Impact
*   **`nfa_builder.c`**: RDP parser attaches marker UIDs to NFA edges.
*   **`nfa2dfa.c`**: Subset construction "harvests" markers from NFA epsilon-closures and literal edges, packing them into a deduplicated **Marker Block**.
*   **`dfa_eval.c`**: Traversal records the state trace; replay logic executes the marker payloads using a LIFO stack.

## Advantages
*   **Scalability**: Supports thousands of unique captures via pointer-based Marker Lists.
*   **Precision**: Captures align perfectly with character consumption.
*   **Stability**: Eliminates ambiguity from overlapping NFA paths.
