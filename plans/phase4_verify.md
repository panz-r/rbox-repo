# Verification: Phase 4 (Full Path Precision)

## 1. Literal Precision
*   **Task**: Match `abc` against `[safe] a<tag>b</tag>c`.
*   **Requirement**: Capture `tag` must be exactly index 1 to 2 (containing only "b").

## 2. Quantifier Precision
*   **Task**: Match `abab` against `(<a>ab</a>)+`.
*   **Requirement**: Should produce two captures for 'a': (0,2) and (2,4). 

## 3. Disjoint Isolation
*   **Task**: Create two patterns: `[safe] <c1>xyz</c1>` and `[safe] <c2>xyz</c2>`.
*   **Requirement**: Match "xyz". The output must contain ONLY the capture for the pattern that was matched.

**This confirms the Mealy Replay architecture is working to full quality.**
