# Efficient SAT Encoding for DFA Minimization

## Problem Analysis

The current SAT encoding has complexity O(n² × |Σ| × p²) where:
- n = number of states
- |Σ| = alphabet size (up to 256)
- p = number of partitions

For a DFA with 1000 states and 100 partitions, this generates ~2.5 billion clauses.

## Divide-and-Conquer Strategies

### Strategy 1: Equivalence Relation Encoding

Instead of encoding partition assignment (x[s][p]), encode equivalence directly:
- Variables: eq[i][j] for all i < j (n×(n-1)/2 variables)
- eq[i][j] = true means states i and j are equivalent

**Constraints:**
1. **Symmetry**: Implicit (only encode eq[i][j] for i < j)
2. **Transitivity**: eq[i][j] ∧ eq[j][k] → eq[i][k]
   - O(n³) clauses, but can be reduced using path compression
3. **Accepting separation**: ¬eq[i][j] if i accepting, j not (or different categories)
4. **Transition consistency**: eq[i][j] → eq[δ(i,c)][δ(j,c)] for each symbol c
   - O(n² × |Σ|) clauses

**Complexity**: O(n² × |Σ| + n³) - much better than O(n² × |Σ| × p²)

### Strategy 2: SCC-Based Decomposition

1. Compute strongly connected components (SCCs) of the DFA graph
2. States in different SCCs can never be equivalent
3. Minimize each SCC independently
4. Combine results

**Benefit**: Reduces problem size from n to max(|SCC|)

### Strategy 3: Incremental Pair Merging

1. Start with Hopcroft's result (already minimal or near-minimal)
2. For each pair of states (i, j) that Hopcroft kept separate:
   - Create small SAT instance: "Can i and j be merged?"
   - If satisfiable, merge them
3. Iterate until no more merges possible

**Benefit**: Each SAT instance is small (just checking one pair)

### Strategy 4: Symbolic Partition Refinement

1. Use BDDs (Binary Decision Diagrams) to represent state sets
2. Encode partition refinement symbolically
3. SAT solver works on BDD operations, not individual states

**Benefit**: Compact representation for large state sets

## Recommended Approach: Hybrid

Combine multiple strategies:

```
1. Run Hopcroft minimization (O(n log n))
2. Compute SCCs of the minimized DFA
3. For each SCC with > threshold states:
   a. Use equivalence relation encoding
   b. Limit to states within the SCC
4. For SCCs below threshold:
   a. Use incremental pair merging
```

## Implementation Plan

### Phase 1: Equivalence Relation Encoding

```cpp
class EquivalenceEncoder {
    // Variables: eq[i][j] for i < j
    int eq_var(int i, int j) {
        if (i > j) std::swap(i, j);
        return i * n + j - i * (i + 1) / 2 + 1;
    }
    
    void encode_transitivity() {
        // For each triple i < j < k:
        // eq[i][j] ∧ eq[j][k] → eq[i][k]
        // eq[i][j] ∧ eq[i][k] → eq[j][k]
        // eq[j][k] ∧ eq[i][k] → eq[i][j]
    }
    
    void encode_transition_consistency() {
        // For each pair (i, j) and symbol c:
        // eq[i][j] → eq[δ(i,c)][δ(j,c)]
    }
};
```

### Phase 2: SCC Decomposition

```cpp
// Compute SCCs using Tarjan's algorithm
std::vector<std::vector<int>> compute_sccs(const DFA& dfa);

// Minimize each SCC independently
for (const auto& scc : sccs) {
    if (scc.size() > THRESHOLD) {
        minimize_scc_sat(scc);
    } else {
        minimize_scc_hopcroft(scc);
    }
}
```

### Phase 3: Incremental Refinement

```cpp
// After Hopcroft, try to merge additional pairs
bool try_merge_pair(int i, int j, const DFA& dfa) {
    // Create small SAT instance
    // Check if merging i and j preserves language
}
```

## Complexity Analysis

| Strategy | Variables | Clauses | Practical Limit |
|----------|-----------|---------|------------------|
| Current (partition) | n × p | n² × |Σ| × p² | ~100 states |
| Equivalence | n²/2 | n² × |Σ| + n³ | ~500 states |
| SCC decomposition | n²/2 | n² × |Σ| (per SCC) | ~2000 states |
| Incremental | O(n) | O(n × |Σ|) | Unlimited |

## Next Steps

1. Implement equivalence relation encoding
2. Add SCC decomposition
3. Benchmark on real-world DFAs
4. Consider parallel solving for independent SCCs
