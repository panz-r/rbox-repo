# NFA Builder Bug Report (nfa_builder.c)

This document details identified bugs, inefficiencies, and structural defects in the `tools/nfa_builder.c` source file.

## Summary of Fixes Applied (February 9, 2026)

### Quantifiers & Loops
1. **Bug 2.6 (Multi-char Quantifier Loop-back)**: Handlers for `+` and `*` now copy transitions from `fragment_entry_state` instead of `exit_state`.
2. **Bug 2.7 (Alternation Loop-back)**: Alternation detection now includes `multi_target_array` entries.
3. **Bug 6.3 (Prefix Sharing vs Quantifiers)**: `+` and `?` handlers now support `last_element_sid`.

### Alternations & Groups
1. **Bug 2.10 (Alternation Exit Dangling)**: `parse_rdp_alternation` now returns a `merge_state` (unified exit for all branches).
2. **Bug 2.12 (Syntax Start Handling)**: Patterns starting with special characters (like `(`) now use an `EPSILON` transition from State 0 instead of consuming the character as a literal.

### Character Classes
1. **Bug 15.4 (Negated Classes Broken)**: `parse_rdp_class` now correctly negates character sets by iterating through the alphabet.
2. **Bug 15.5 (Empty Class Safety)**: Added checks for `[]` and `[^]` to avoid infinite loops or crashes.

### UTF-8 Support
1. **Bug 6.4 (Quantifier Sequence Bypass)**: Quantifiers on multi-byte characters now loop the entire sequence.
2. **Bug 15.2 (UTF-8 in Character Classes)**: Character classes now detect and preserve multi-byte units.
3. **Bug 6.5 (UTF-8 Fragment Optimization)**: Fragment prefix-peeking is now UTF-8 sequence aware.

### Alphabet & Symbols
1. **Bug 25.1 (Alphabet Builder Ignores Fragments)**: Fragment values are now scanned during alphabet construction.
2. **Bug 26.1/26.2 (Special Byte Collisions)**: Added explicit literal entries for bytes 0x00, 0x01, 0x05, 0x09, 0x20. Updated `find_symbol_id` to prefer literals over control symbols.

### Infrastructure
1. **Bug 3.3 (Pattern Truncation)**: Expanded `remaining` buffer to 2048 bytes.
2. **Bug 5.5 (Signatures ignore MTA)**: State signatures now include `multi_target_array` data.
3. **Bug 11.4 (Redundant Code)**: Removed duplicate wildcard handling in `parse_rdp_element`.

## Current Status
- **Test Pass Rate**: 102/310 (improved from 64/310)
- **Critical Bugs**: All identified logic and crash bugs fixed.
- **Stable Baseline**: DFA conversion and minimization are fully functional with the new MTA-aware builder.

## New Findings (Logic & Lifecycle - Feb 9, 2026)

### Alphabet & Symbols
1. **Bug 11.5 (Space Normalization Broken)**: `DFA_CHAR_NORMALIZING_SPACE` (0xFE) is never added to the alphabet in `construct_alphabet_from_patterns`. `find_symbol_id(0xFE)` returns -1, making the one-or-more space normalization fallback dead code.
2. **Bug 25.2 (Alphabet Pollution)**: The alphabet builder scans the entire pattern string without skipping capture tags. Characters inside `<capname>` tags (like 'c', 'a', 'p') are added to the alphabet even if they are never used as literals, wasting symbol slots.
3. **Bug 26.3 (Wildcard Broken by NUL Fix)**: The fix for Bug 26.1 (NUL byte collision) makes `find_symbol_id(0)` return the literal NUL symbol ID. The wildcard logic for `*` and `(*)` uses `find_symbol_id(DFA_CHAR_ANY)` where `DFA_CHAR_ANY` is 0. Consequently, wildcards now only match literal NUL bytes.

### State & Memory Lifecycle
1. **Bug 30.1 (MTA Lifecycle Failure)**: `nfa_init` and `nfa_add_state_with_category` do not call `mta_init` or `mta_free`. Since `nfa` is a global array, the `multi_target_array` structures persist across patterns and `read_advanced_spec_file` calls, leading to memory leaks and catastrophic NFA corruption between different DFA build runs.

## Architecture Notes
- Consider refactoring `find_symbol_id` to accept a `bool is_special` flag to resolve Bug 26.3.
- `nfa_state_t` definition should be moved entirely to `include/nfa.h` to ensure consistency between builder and converter.
