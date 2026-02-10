# Verification: Phase 3 (Aggregation & Minimization)

## 1. Subset Harvesting
*   **Question**: In `nfa2dfa.c`, does the rule generation collect markers from the epsilon closure of BOTH the source and target states?
*   **Verification**: Build `<a>b</a>`. The DFA rule for `b` should have both START and END markers in its list.

## 2. Output-Sensitive Minimization
*   **Question**: If you run Hopcroft on `<a>abc</a>` and `<b>abc</b>`, does the final state count reflect that these paths are distinct?
*   **Logic Check**: They have identical transitions but different `marker_offset` values. They MUST be treated as non-equivalent.

## 3. Marker Block Deduplication
*   **Question**: Does `write_dfa_file` reuse offsets for identical marker sequences?

**Proceed to Phase 4 only when markers are correctly aggregated and survive all three minimization algorithms.**
