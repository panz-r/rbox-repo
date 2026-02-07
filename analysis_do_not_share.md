The do_not_share flag is NOT the right strategy. It causes state explosion and timeouts.

## Root Cause Analysis

Looking at the test output:
- `'ab'` returns `category_mask=0x19` (bits 0, 3, 4 set) instead of just `0x01`
- `'abcb'` returns `category_mask=0x05` (bits 0, 2 set) instead of just `0x02`

The problem is in how `move_accepting_mask` is computed in the DFA converter.

### The Bug

In nfa2dfa.c around line 400, when building a DFA state, the code does:

```c
// Compute combined category mask from all NFA states in this DFA state
uint16_t move_accepting_mask = 0;
for (int k = 0; k < move_count; k++) {
    move_accepting_mask |= nfa[move_states[k]].category_mask;
}
```

**This ORs together category masks from ALL NFA states in the DFA state.**

When the DFA state contains NFA states from different patterns:
- Pattern 1 NFA states contribute category mask 0x01
- Pattern 2 NFA states contribute category mask 0x02  
- Pattern 3 NFA states contribute category mask 0x04

They all get ORed together into one mask! This is why `'ab'` returns `0x19` - it's ORing masks from multiple patterns.

### Why do_not_share Doesn't Help

The `do_not_share` flag tries to prevent NFA states from being shared between patterns during NFA construction. But:

1. **It's too aggressive** - causes combinatorial state explosion (your timeout issue)
2. **It's at the wrong level** - the issue isn't state sharing, it's how category masks are combined during DFA construction
3. **State sharing is actually correct and necessary** for DFA minimization

### The Right Solution

**Don't try to prevent state sharing. Instead, don't combine category masks from different patterns.**

Option 1: Track pattern membership
- Track which pattern each NFA state belongs to
- When computing `move_accepting_mask`, only OR masks from the SAME pattern
- This keeps categories isolated even when states are shared

Option 2: Multiple DFA runs (simpler)
- Build one DFA per acceptance category
- Run the input through each DFA separately
- No category mask combination issues because each DFA only has one category

Option 3: Accept set instead of mask (most correct)
- Instead of `uint8_t category_mask`, use a set/list of matching patterns
- DFA evaluation returns all matching pattern IDs, not a combined mask
- This allows proper multi-pattern matching without interference

### Recommended Fix

The cleanest fix is Option 3: change the DFA to track which patterns match, not just a combined mask.

Change DFA state from:
```c
uint16_t flags;  // bits 0-7: category_mask
```

To:
```c
uint16_t accept_set[MAX_PATTERNS];  // List of matching pattern IDs, 0xFFFF = end
```

During evaluation, collect all matching pattern IDs instead of ORing masks. This naturally isolates patterns.

If that's too complex, Option 2 (multiple DFAs) is easier to implement and debug.