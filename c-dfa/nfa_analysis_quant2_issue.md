# NFA Analysis: Why 'abcb' Doesn't Reach quant2 Accepting State

## Issue Summary
The test results show that 'abcb' returns category_mask=0x05 instead of the expected 0x04 (quant2 only), and 'abc' incorrectly matches when it should NOT match.

## Key NFA States Analysis

### Pattern 15 (quant1: a((b))+)
- **State 84**: Start after 'a' → Symbol 4 ('b') → State 86
- **State 86**: After 'ab' (CRITICAL STATE)
  - Symbol 4 ('b') → 87,,86 (loop back + go to accepting)
  - **Symbol 5 ('c') → 89,,95** ← PROBLEM!
- **State 87**: EOS target → Symbol 90 (EOS) → State 88
- **State 88**: Accepting with CategoryMask: 0x01 (quant1)

### Pattern 16 (quant2: abc((b))+)
- **State 89**: Start after 'abc' → PatternId: 16
  - Symbol 4 ('b') → 91
  - Symbol 6 ('d') → 98
- **State 91**: After 'abcb'
  - Symbol 4 ('b') → 92,,91 (loop for more b's)
- **State 92**: EOS target (CategoryMask: 0x01) → Symbol 90 → State 93
- **State 93**: Accepting with CategoryMask: 0x04 (quant2)

### Pattern 17 (quant3: ab((c))+)
- **State 95**: PatternId: 17
  - Symbol 5 ('c') → 96,,95 (loop)
- **State 96**: EOS target (CategoryMask: 0x04) → Symbol 90 → State 97
- **State 97**: Accepting with CategoryMask: 0x08 (quant3)

## Root Cause

**State 86 has incorrect transitions on Symbol 5 ('c')**: `Symbol 5 -> 89,,95`

This means:
1. After matching 'ab', State 86 transitions to BOTH State 89 (Pattern 16) AND State 95 (Pattern 17) on 'c'
2. This incorrectly merges the three patterns that should be completely separate
3. The multi-target notation `89,,95` indicates multiple transitions were added

## Impact on 'abcb' Processing

1. **'a'** → State 84 (Pattern 15)
2. **'b'** → State 86 (Pattern 15, has loop on 'b' via 87,,86)
3. **'c'** → State 86 transitions to BOTH State 89 AND State 95:
   - State 89 (Pattern 16 quant2): Expects 'b' next → can continue to 'abcb'
   - State 95 (Pattern 17 quant3): Has loop on 'c' → creates category 0x04 interference
4. **'b'** → From State 89, goes to State 91
   - But State 95 might also contribute to the category mask
5. **Result**: Mixed category 0x05 instead of clean 0x04

## Why 'abc' Incorrectly Matches

- State 86 → on 'c' → State 95 (Pattern 17 quant3)
- State 95 has CategoryMask: 0x00 but is an intermediate state
- State 96 is an EOS target (CategoryMask: 0x04)
- The DFA construction incorrectly makes 'abc' match via some path

## The Fix Needed

**State 86 should ONLY have transitions for Pattern 15 (quant1):**
- Symbol 4 ('b') → 87,,86 (correct - loop for + quantifier)
- **NO transitions on Symbol 5 ('c')** ← This should be removed

The transition `Symbol 5 -> 89,,95` was incorrectly added, likely during:
1. NFA construction where patterns share prefix 'ab'
2. State sharing/minimization that merged incompatible states
3. Fragment expansion for the ((b)) fragment being reused incorrectly

## Next Steps

1. Examine nfa2dfa.c to see how these multi-target transitions are created
2. Check if State 86 was incorrectly shared between patterns
3. The patterns a((b))+, abc((b))+, and ab((c))+ share 'ab' prefix but must remain separate
4. State sharing across different patterns with different category masks must be prevented
