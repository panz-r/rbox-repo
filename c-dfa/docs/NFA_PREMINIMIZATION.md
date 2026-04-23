# NFA Pre-Minimization Design

## Problem Statement

NFA construction from patterns can create redundant states. Subset construction (NFA→DFA) can cause exponential blowup. Pre-minimizing the NFA reduces this blowup.

## Optimization Phases

The pre-minimization pipeline consists of multiple phases, each with O(n) or O(n log n) complexity:

### Phase 1: Unreachable State Pruning (O(n))
- BFS from start state to find reachable states
- Marks unreachable states as dead

### Phase 2: Epsilon Pass-Through Bypass (O(n))
- Finds states with single epsilon transition and no accepting properties
- Redirects incoming transitions directly to epsilon target
- Safe because it only shortens paths without changing language

### Phase 3: Epsilon Chain Compression (O(n))
- Generalizes pass-through bypass for multi-hop epsilon chains
- Follows chains to find ultimate target
- Compresses A→B→C→D to A→D

### Phase 4: Common Prefix Merging (O(n log n))
- Groups states by (source, symbol, outgoing_signature)
- Merges states reached via same (source, symbol) pair
- Combines outgoing transitions using UNION (preserves all futures)

### Phase 5: Common Suffix Merging (O(n log n))
- Groups states by (target, symbol, incoming_signature, accepting_properties)
- Merges states that transition to same (target, symbol) pair
- Combines incoming transitions using UNION (preserves all pasts)
- **Critical**: Only merges states with identical accepting properties

## Prefix vs Suffix Merging

| Aspect | Prefix Merging | Suffix Merging |
|--------|---------------|----------------|
| Direction | Forward from start | Backward from accepting |
| Grouping key | (source, symbol, outgoing_sig) | (target, symbol, incoming_sig, accept_sig) |
| Merge operation | Union of outgoing transitions | Union of incoming transitions |
| Safety condition | Same incoming path | Same outgoing path + accepting props |

## Safety Guarantees

### Prefix Merging Safety
Two states can be merged if:
1. They have exactly one incoming transition
2. That incoming transition is from the same (source, symbol) pair
3. They have identical outgoing behavior (transitions, markers, etc.)
4. They do NOT have accepting properties (category_mask == 0)

### Suffix Merging Safety
Two states can be merged if:
1. They have exactly one outgoing transition
2. That outgoing transition is to the same (target, symbol) pair
3. They have identical incoming behavior
4. They have IDENTICAL accepting properties (category_mask, pattern_id, markers)

**Key Difference**: Accepting states have semantic meaning. Two accepting states can only be merged if they have identical accepting properties.

## Scalability Analysis

| NFA Size | Prefix Merging | Suffix Merging |
|----------|---------------|----------------|
| 1K states | ~10K candidates | ~10K candidates |
| 10K states | ~100K candidates | ~100K candidates |
| 100K states | ~1M candidates | ~1M candidates |

Both algorithms are O(n log n) due to sorting by signature.

## Expected Results

For typical pattern sets:
- **10-30% reduction** in NFA states from prefix merging
- **5-15% reduction** in NFA states from suffix merging
- **10-25% total reduction** in resulting DFA states
- **Minimal overhead** (O(n log n) complexity)

## Integration Point

```
Pattern File → NFA Builder → [NFA Pre-Minimization] → Subset Construction → DFA Minimization
```

Pre-minimization runs between NFA construction and DFA conversion.

## Configuration Options

```c
typedef struct {
    bool enable_epsilon_elim;   // O(n) - safe, default: true
    bool enable_epsilon_chain;  // O(n) - safe, default: true
    bool enable_prune;          // O(n) - safe, default: true
    bool enable_final_dedup;    // O(n log n) - safe, default: true
    bool enable_bidirectional;  // O(n log n) - safe, default: true
    
    // Advanced options (disabled by default)
    bool enable_landing_pad;    // O(n²) - superseded by bidirectional
    bool enable_merge;          // O(n²) - too aggressive
    bool enable_sat;            // For bounded subproblems only
} nfa_premin_options_t;
```

## Implementation Notes

### Bidirectional Incremental Merging

The core optimization combines prefix and suffix merging into an incremental
fixpoint algorithm that:
1. Processes only "dirty" states that may have new merge opportunities
2. Alternates between prefix and suffix merging until no more merges
3. Maintains O(n log n) overall complexity through amortized analysis

### Multi-Target Array (MTA) Fast Path

The NFA builder uses an optimization for storing transitions:
- **Single transitions**: Stored in `first_targets[symbol_id]` with `has_first_target[symbol_id]` flag
- **Multiple transitions**: Stored in `mta_entry_t` array

This means `mta_get_entry_count()` returns 0 for states with only single transitions. The merging code must check both:
1. `has_first_target[symbol_id]` and `first_targets[symbol_id]` for single transitions
2. `mta_get_entry_count()` and `mta_get_entries()` for multiple transitions

### Final State Deduplication

Final state deduplication MUST run before bidirectional merging. This creates longer common suffixes by merging accepting states with identical:
- `category_mask`
- `eos_target`
- `marker_count` and marker contents

### Iterative Passes

Bidirectional merging uses iterative passes (max 20) because:
- After merging states at one level, their children/parents may become merge candidates
- Each pass may enable new merge opportunities
- Convergence is typically reached in 3-6 passes

## Pattern Ordering Integration

Pattern ordering is now integrated into the NFA builder pipeline, running before NFA construction:

```
Pattern File → [Pattern Ordering] → NFA Builder → [NFA Pre-Minimization] → Subset Construction
```

### Features

1. **Prefix Tree Ordering**: Groups patterns with common prefixes using a trie structure
2. **Duplicate Detection**: Warns and removes duplicate patterns (using full line comparison)
3. **Fragment Reference Validation**: Validates fragment references with namespace semantics

### Fragment Namespace Semantics

Fragments follow namespace-qualified naming:

- `[[a::b]]` - References fragment 'b' in namespace 'a' (explicit cross-namespace)
- `[[c]]` - References fragment 'c' in the **same namespace** as the pattern

Example:
```
[fragment:safe::digit] 0|1|2|3|4|5|6|7|8|9
[fragment:caution::word] a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z

[safe] [[digit]]+     → Looks for safe::digit ✓
[caution] [[word]]+   → Looks for caution::word ✓
[test] [[safe::digit]]+ → Looks for safe::digit directly ✓
[caution] [[digit]]+  → ERROR: Looks for caution::digit (not defined)
```

### Implementation

See `tools/pattern_order.c` and `tools/pattern_order.h` for the implementation.

## Current Status

| Feature | Status |
|---------|--------|
| Prefix Merging | ✅ Complete |
| Suffix Merging | ✅ Complete |
| MTA Fast-Path Handling | ✅ Fixed |
| Pattern Ordering Integration | ✅ Complete |
| Duplicate Detection | ✅ Complete |
| Fragment Validation | ✅ Complete |
| Namespace Semantics | ✅ Complete |

## Future Enhancements

1. **Incremental merging**: Process groups in parallel
2. **Approximate signatures**: Use locality-sensitive hashing for near-matches
3. **Pattern-aware grouping**: Consider pattern structure for better grouping
