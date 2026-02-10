# Verification: Phase 1 (Binary Format)

## 1. Packed Structure Check
*   **Question**: Are `dfa_rule_t` and `dfa_state_t` marked with `__attribute__((packed))`?
*   **Question**: Does `sizeof(dfa_rule_t)` equal 12?
*   **Question**: Does `sizeof(dfa_state_t)` equal 16?

## 2. Offset Audit
*   **Question**: In `write_dfa_file`, is rule `target` calculated as an absolute file offset?
*   **Question**: Is `eos_target` also an absolute file offset?

## 3. Metadata Table
*   **Question**: Does the binary layout include the new variable-length Metadata Block?
*   **Question**: Is `ds->initial_state` correctly pointing past the header, identifier, and metadata?

**Proceed to Phase 2 only when the binary format is verified to be stable and alignment-safe.**
