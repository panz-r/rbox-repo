# Suffix Factorization - Implementation Complete

## Overview

Suffix factorization is an optimization that creates NEW intermediate states to factor out common suffixes in the NFA. Unlike suffix merging (which merges existing states), this approach creates new "pass-through" states that can reduce the overall number of transitions.

## Status: COMPLETE ✓

The feature has been **FIXED AND ENABLED**. All tests pass (579/579).

## The Bug That Was Fixed

### Original Problem

The original implementation created intermediate states with transitions on the **SAME symbol** as the original:

```
Before: X --a--> T, Y --a--> T
After:  X --a--> A', Y --a--> A', A' --a--> T  ❌ WRONG!
```

This required TWO `a` symbols to reach T instead of ONE - it changed the language!

### The Fix

The intermediate state now uses **EPSILON** (VSYM_EPS = 257) to connect to the target:

```
Before: X --a--> T, Y --a--> T
After:  X --a--> A', Y --a--> A', A' --EPSILON--> T  ✓ CORRECT
```

This preserves semantics because epsilon transitions don't consume input.

## Implementation Details

### Key Code Change

**File:** [`c-dfa/tools/nfa_preminimize.c:2282-2288`](c-dfa/tools/nfa_preminimize.c:2282)

```c
// Add EPSILON transition from new_state to target
// This is CRITICAL: using the same symbol would change the language!
// (e.g., X --a--> A' --a--> T requires TWO 'a' symbols, not one)
nfa[new_state].multi_targets.has_first_target[VSYM_EPS] = true;
nfa[new_state].multi_targets.first_targets[VSYM_EPS] = target;
```

### Algorithm

1. Find all transitions grouped by (target, symbol)
2. For groups with 2+ sources pointing to same (target, symbol):
   - Create a new intermediate state
   - Add EPSILON transition from intermediate to target
   - Redirect all sources to point to intermediate instead of target

### Safety Properties

- **Only factorizes through ORIGINAL states** - prevents infinite chains
- **Single pass** - prevents unbounded state creation
- **Pure intermediate states** - no accepting properties inherited
- **Dynamic array growth** - handles large NFAs

## Test Results

All 579 tests pass, including 15 new factorization-specific tests:

```
=== SUFFIX FACTORIZATION TESTS ===
Patterns: patterns_factorization_test.txt
  [PASS] ab matches (factorization test)
  [PASS] cb matches (factorization test)
  [PASS] xy matches (factorization test)
  ...
  Result: 15/15 passed
```

## Files Modified

| File | Change |
|------|--------|
| [`c-dfa/tools/nfa_preminimize.c`](c-dfa/tools/nfa_preminimize.c) | Fixed EPSILON transition, updated docs |
| [`c-dfa/.gitignore`](c-dfa/.gitignore) | Added `tools/*_asan` pattern |
| [`c-dfa/patterns/basic/factorization_test.txt`](c-dfa/patterns/basic/factorization_test.txt) | New test patterns |
| [`c-dfa/src/dfa_test.c`](c-dfa/src/dfa_test.c) | Added factorization test function |

## Future Optimizations

1. **Group by target only** - Instead of (target, symbol), could create fewer intermediate states
2. **Multi-pass factorization** - Currently limited to single pass for safety
3. **Interaction with SAT optimal** - Could improve merge selection after factorization
