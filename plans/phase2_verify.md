# Verification: Phase 2 (NFA Edge Payloads)

## 1. Edge Metadata Audit
*   **Question**: Does `nfa_builder` store the `pattern_id` on every transition?
*   **Question**: Does `parse_capture_start/end` successfully attach markers to the transitions?

## 2. NFA Dump Check
*   **Task**: Dump the NFA for `<cap>a</cap>+`.
*   **Requirement**:
    *   The transition for `a` should have the START marker.
    *   The loop-back epsilon transition should carry any markers nested in the loop.
    *   The exit transition should have the END marker.

**Proceed to Phase 3 only when markers are confirmed to be on the correct edges in the NFA dump.**
