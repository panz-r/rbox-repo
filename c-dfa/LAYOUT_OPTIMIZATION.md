# DFA Layout Optimization

## Overview

This document describes the cache-optimized layout strategy for the ReadOnlyBox DFA binary representation. The layout algorithm reorders DFA states to maximize cache performance throughout all stages of evaluation.

## Problem Statement

During DFA evaluation, the evaluator traverses states by following transitions. Cache performance is critical for high-throughput command validation. A naive layout (states in arbitrary order) results in poor cache locality, especially for:

1. **Early evaluation**: States near the start are accessed frequently
2. **Mid evaluation**: States in the "middle" of the DFA are accessed based on input patterns
3. **Late evaluation**: States near accepting states are accessed when approaching match completion

## Solution: 3-Region Layout

The DFA is divided into three regions, each optimized for a different evaluation phase:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Region 1: Forward-BFS    │  Region 2: Affinity    │  Region 3:    │
│  (Early Evaluation)       │  Groups (Mid Eval)     │  Backward-BFS │
│                           │                        │  (Late Eval)  │
├───────────────────────────┼────────────────────────┼───────────────┤
│  States close to start    │  States grouped by     │  States close │
│  Sorted by forward depth  │  mutual transitions    │  to accepting │
│                           │  Then by combined depth│  Sorted by    │
│                           │                        │  backward depth│
└─────────────────────────────────────────────────────────────────────┘
```

### Region 1: Forward-BFS Region

**Purpose**: Optimize cache performance during early evaluation when the evaluator is close to the start state.

**Algorithm**:
1. Run BFS from start state (state 0)
2. Calculate forward depth for each state: `forward_depth[s] = distance from start`
3. Define threshold: `forward_threshold = max_forward_depth / 3`
4. States with `forward_depth <= forward_threshold` belong to this region
5. Sort by forward depth (ascending)

**Rationale**: States close to the start are accessed most frequently during the initial characters of input matching.

### Region 2: Affinity Groups (Middle Region)

**Purpose**: Optimize cache performance during mid-evaluation when the evaluator is traversing the "middle" of the DFA.

**Algorithm**:
1. Build affinity groups using Union-Find:
   - For each pair of states (s, t), check if they have mutual transitions
   - Mutual transition: s → t on some symbol AND t → s on some symbol
   - Union states with mutual transitions into the same group
2. States not in Region 1 or Region 3 belong to this region
3. Sort by affinity group ID, then by combined depth score

**Rationale**: States that transition to each other are likely to be accessed in sequence. Grouping them together improves cache locality for mid-evaluation patterns.

### Region 3: Backward-BFS Region

**Purpose**: Optimize cache performance during late evaluation when approaching accepting states.

**Algorithm**:
1. Build reverse graph (predecessor lists)
2. Run BFS from all accepting states simultaneously
3. Calculate backward depth for each state: `backward_depth[s] = distance to nearest accepting state`
4. Define threshold: `backward_threshold = max_backward_depth / 3`
5. States with `backward_depth <= backward_threshold` belong to this region
6. Sort by backward depth (ascending)

**Rationale**: As the evaluator approaches an accepting state, it traverses states close to acceptance. These states should be cache-friendly.

## Implementation Details

### Data Structures

```c
// Forward depths (BFS from start)
int* forward_depths;  // forward_depths[state] = depth from start

// Backward depths (BFS from accepting states)
int* backward_depths;  // backward_depths[state] = distance to accepting

// Affinity groups (Union-Find)
int* parent;  // parent[state] = representative of group
int* rank;    // rank[state] = tree depth for union by rank

// Region classification
int* region;  // region[state] = {REGION_FORWARD, REGION_MIDDLE, REGION_BACKWARD}
```

### Algorithm Complexity

| Step | Complexity |
|------|------------|
| Forward BFS | O(V + E) |
| Backward BFS | O(V + E) |
| Affinity grouping | O(V × Σ) where Σ = alphabet size |
| Sorting | O(V²) with simple sort, O(V log V) with qsort |
| **Total** | O(V²) or O(V log V) with optimized sort |

Where V = number of states, E = number of transitions.

### Code Location

- Header: [`tools/dfa_layout.h`](tools/dfa_layout.h)
- Implementation: [`tools/dfa_layout.c`](tools/dfa_layout.c)
- Integration: Called from [`tools/dfa_minimize.c`](tools/dfa_minimize.c) after minimization

## Configuration

The layout algorithm is controlled by `layout_options_t`:

```c
typedef struct {
    bool reorder_states;         // Enable state reordering
    bool place_rules_near_state; // Place rule tables near source state (future)
    bool align_cache_lines;      // Align to 64-byte cache lines (future)
    int cache_line_size;         // Cache line size (default 64)
} layout_options_t;
```

Default options enable all optimizations.

## Tuning Parameters

The region boundaries are controlled by threshold divisors:

```c
int forward_threshold = max_forward / 3;   // Top 1/3 by forward depth
int backward_threshold = max_backward / 3; // Top 1/3 by backward depth
```

These can be tuned based on:
- DFA structure (wide vs deep)
- Typical input patterns
- Cache size of target hardware

## Future Improvements

1. **Rule table placement**: Place transition rules near their source state
2. **Cache line alignment**: Align state structures to 64-byte boundaries
3. **Profile-guided optimization**: Use runtime profiling to determine hot paths
4. **NUMA awareness**: Consider NUMA topology for large DFAs

## Testing

The layout algorithm is tested as part of the minimization integrity tests:

```bash
make test-integrity
```

Functional correctness is verified by running the full test suite:

```bash
./dfa_test --dfa /tmp/optimized.dfa --test-set ABC
```

## References

- Hopcroft's Algorithm for DFA Minimization
- Cache-Oblivious Algorithms and Data Structures
- Union-Find Data Structure (Disjoint Set Union)
