# Phase 3: Construction & Output-Sensitive Minimization

## Context
Subset construction must aggregate markers while keeping their Pattern ID identity intact.

## Task
1.  **Update `tools/nfa2dfa.c`**:
    *   **The Harvest**: In `dfa_add_state`, when creating a transition `SetA --char--> SetB`:
        1. Trace all markers on `epsilon_closure(SetA)`.
        2. Trace markers on the literal character edges.
        3. Trace all markers on `epsilon_closure(SetB)`.
        4. Concatenate these into a single list for that DFA rule.
2.  **Update ALL Minimizers (`dfa_minimize.c`, `dfa_minimize_brzozowski.c`)**:
    *   **Equivalence Rule**: Two states are only equivalent if:
        *   Their category masks match.
        *   Their `eos_marker_offset` matches.
        *   **AND** every one of their transitions has the same `target` AND the same `marker_offset`.
    *   **Hashing**: Update state signatures to include `marker_offset` for every transition.

## Background for Implementation
*   If the minimizer merges two states that lead to the same target but produce different markers, the capture data will be corrupted. You must treat the "Output" as a fundamental part of the state's identity.
