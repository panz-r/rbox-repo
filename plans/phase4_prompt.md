# Phase 4: Path-Trace Evaluator

## Context
The evaluator records the matching path and uses it to filter markers.

## Task
1.  **Modify `src/dfa_eval.c`**:
    *   **Pass 1 (Match)**:
        *   Record every state index visited into a `uint32_t trace_buffer[MAX_INPUT_LEN]`.
        *   Identify the `Winning Pattern ID` from the final accepting state subset.
    *   **Pass 2 (Extraction Replay)**:
        *   Walk the recorded trace.
        *   For each transition `trace[i] --input[i]--> trace[i+1]`:
            1. Find the rule that was triggered.
            2. Follow `marker_offset` to the Marker Block.
            3. **The Filter**: For every marker in the list, if `marker.pattern_id == winning_pattern_id`, process it.
            4. **START**: Push `(uid, i)` to stack.
            5. **END**: Pop from stack, lookup name from Metadata, and save to `result->captures`.
    *   **EOS**: Process `final_state->eos_marker_offset` using the same filter.

## Background for Implementation
*   This approach is O(N) and handles thousands of overlapping patterns by using the Winning ID as a "key" to extract only the relevant markers.
