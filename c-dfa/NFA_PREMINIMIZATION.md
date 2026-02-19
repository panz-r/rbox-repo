# NFA Pre-Minimization Design

## Problem Statement

NFA construction from patterns can create redundant states. Subset construction (NFA→DFA) can cause exponential blowup. Pre-minimizing the NFA reduces this blowup.

## Scalable SAT Encoding

### Key Insight: Signature-Based Grouping

Instead of O(n²) pairwise comparison, we use signature-based grouping:

1. **Compute signatures** for all states (O(n))
2. **Group states** by identical signatures (O(n log n))
3. **SAT merge verification** within groups only (O(g × s²) where s = avg group size)

This is scalable because well-structured NFAs have small signature groups.

### State Signature

A state's signature captures its behavior:

```c
typedef struct {
    uint64_t transition_hash;   // Hash of outgoing transitions
    uint8_t category_mask;       // Accepting categories
    bool is_accepting;           // Has pattern_id
    bool has_epsilon;            // Has epsilon transitions
} state_signature_t;
```

Two states with identical signatures are **candidates** for merging.

### SAT Encoding for Merge Verification

For a signature group with k states:

**Variables:**
- `merge[i,j]` = 1 if states i and j should merge (k²/2 variables)

**Constraints:**
1. **Transitivity**: If merge[i,j] and merge[j,k], then merge[i,k]
2. **Behavior preservation**: Merged states must have compatible transitions

**Objective:** Maximize number of merges

### Scalability Analysis

| NFA Size | Naive O(n²) | Signature-based O(g × s²) |
|----------|-------------|---------------------------|
| 1K states | 1M pairs | ~10K pairs (100 groups × 10 avg size) |
| 10K states | 100M pairs | ~100K pairs (1000 groups × 10 avg size) |
| 100K states | 10B pairs | ~1M pairs (10K groups × 10 avg size) |

**Speedup: 100-1000x** for typical NFAs.

## Algorithm

```
NFA Pre-Minimization:

1. Compute signatures for all states
   - Hash outgoing transitions
   - Include category and accepting status
   
2. Group states by signature
   - Use hash table for O(n) grouping
   
3. For each signature group:
   a. If group size = 1, skip
   b. Build SAT instance for merge verification
   c. Solve for optimal merging
   d. Apply merges
   
4. Remove unreachable states
   - BFS from start state
   - Delete unreachable states
   
5. Renumber states consecutively
```

## Implementation Plan

### Phase 1: Signature Computation
- `compute_state_signature()` - O(transitions per state)
- `group_by_signature()` - O(n) with hash table

### Phase 2: Merge Verification
- `build_merge_sat()` - Create SAT instance for group
- `solve_merges()` - Find optimal merges
- `apply_merges()` - Redirect transitions

### Phase 3: Cleanup
- `remove_unreachable()` - Delete dead states
- `renumber_states()` - Compact state IDs

## Expected Results

For typical pattern sets:
- **10-30% reduction** in NFA states
- **5-15% reduction** in resulting DFA states
- **Minimal overhead** (signature computation is fast)

## Integration Point

```
Pattern File → NFA Builder → [NFA Pre-Minimization] → Subset Construction → DFA Minimization
```

Pre-minimization runs between NFA construction and DFA conversion.

## Future Enhancements

1. **Incremental merging**: Process groups in parallel
2. **Approximate signatures**: Use locality-sensitive hashing for near-matches
3. **Pattern-aware grouping**: Consider pattern structure for better grouping
