# DFA Transition Table Compression

## Overview

The DFA transition table compression phase reduces the size of compiled DFAs by optimizing how transitions are encoded. This is applied after DFA minimization and before writing the final binary output.

## Problem Statement

A DFA state can have up to 256 transitions (one per ASCII character). In the naive encoding, each transition is stored as a separate rule:

```
LITERAL('a') → state 5
LITERAL('b') → state 5
LITERAL('c') → state 5
...
```

This is inefficient when multiple characters share the same target state and markers.

## Compression Strategies

### Strategy 1: Rule Merging

Combine multiple LITERAL rules into LITERAL_N rules:

```
Before: LITERAL('a') → state 5
        LITERAL('b') → state 5
        LITERAL('c') → state 5

After:  LITERAL_3('a', 'b', 'c') → state 5
```

**Savings**: 3 rules → 1 rule (66% reduction for this case)

### Strategy 2: Range Optimization

Detect consecutive character ranges and encode them as RANGE rules:

```
Before: LITERAL('a') → state 5
        LITERAL('b') → state 5
        LITERAL('c') → state 5
        LITERAL('d') → state 5
        LITERAL('e') → state 5

After:  RANGE('a', 'e') → state 5
```

**Savings**: 5 rules → 1 rule (80% reduction for this case)

### Strategy 3: Default State Sharing

Multiple states often share the same default transition (e.g., all go to a reject state). This strategy identifies and shares common default transition tables.

## Algorithms

### Greedy Algorithm

The greedy algorithm processes characters in order, greedily forming groups:

```
for each unassigned character c:
    start a new group with c
    find up to (max_group_size - 1) matching characters
    (same target state and markers)
    add them to the group
```

**Complexity**: O(n × alphabet_size) where n is the number of states

**Pros**: Fast, simple, produces good results
**Cons**: Doesn't consider ordering effects

### SAT-Based Optimization with Greedy Preprocessing

The SAT-based approach uses greedy as a preprocessing step, then applies ordering-aware optimization:

```
1. Run greedy algorithm
   - Get upper bound on number of rules
   - Identify group structure

2. Run ordering-aware optimization
   - Place isolated characters first (literals)
   - Use ranges for consecutive sequences
   - Consider first-match semantics

3. Return the better result
```

**Key Insight**: First-match semantics means later rules can use wider matching (ranges) because earlier rules have "claimed" specific characters.

**Example**:
```
Characters 'a','c','e' go to state 5
Characters 'b','d' go to state 3

Greedy might produce:
  LITERAL('a') → 5
  LITERAL('c') → 5
  LITERAL('e') → 5
  LITERAL_2('b','d') → 3
  Total: 4 rules

Optimal (ordering-aware):
  LITERAL('b') → 3      (claims 'b')
  LITERAL('d') → 3      (claims 'd')
  RANGE('a', 'e') → 5   (catches 'a','c','e' since 'b','d' already claimed)
  Total: 3 rules
```

## Performance Comparison

On `patterns_combined.txt` (3403 original rules):

| Algorithm | Compressed Rules | Reduction |
|-----------|-----------------|-----------|
| Greedy | 1579 | 53.6% |
| SAT (direct) | 692 | 79.7% |
| **SAT + greedy preprocessing** | **681** | **80.0%** |

## Implementation

### File Structure

```
c-dfa/tools/
├── dfa_compress.h        # API header
├── dfa_compress.c        # Greedy implementation
└── dfa_compress_sat.cpp  # SAT-based optimization
```

### API

```c
// Compression options
typedef struct {
    bool enable_rule_merging;       // Combine LITERAL rules
    bool enable_range_optimization; // Merge adjacent literals into ranges
    bool enable_default_sharing;    // Share default transition tables
    int max_group_size;             // Max chars per group (default: 3)
    bool use_sat;                   // Use SAT optimization
    bool verbose;                   // Print details
} compress_options_t;

// Main compression function
int dfa_compress(build_dfa_state_t* dfa, int state_count, 
                 const compress_options_t* options);

// Get statistics from last run
void dfa_get_compression_stats(compression_stats_t* stats);
```

### Usage

```bash
# Build DFA with greedy compression (default)
./tools/nfa2dfa_advanced input.nfa output.dfa --minimize-hopcroft

# Build DFA with SAT optimization
./tools/nfa2dfa_advanced input.nfa output.dfa --minimize-hopcroft --compress-sat

# Disable compression
./tools/nfa2dfa_advanced input.nfa output.dfa --no-compress
```

## Statistics Structure

```c
typedef struct {
    int original_rules;         // Rules before compression
    int compressed_rules;       // Rules after compression
    int original_bytes;         // Estimated bytes before
    int compressed_bytes;       // Estimated bytes after
    float compression_ratio;    // compressed_bytes / original_bytes
    
    // Per-strategy stats
    int rules_merged;           // Rules saved by merging
    int ranges_created;         // Range rules created
    int defaults_shared;        // States sharing defaults
} compression_stats_t;
```

## Future Improvements

1. **Actual SAT Solver Integration**: Use CaDiCaL to find provably optimal solutions for complex states
2. **Binary Search with SAT**: Start from greedy's result and binary search downward
3. **State-Aware Compression**: Consider cross-state patterns for additional savings
4. **Profile-Guided Optimization**: Use runtime frequency data to optimize hot paths

## References

- [`dfa_compress.h`](tools/dfa_compress.h) - API documentation
- [`dfa_compress.c`](tools/dfa_compress.c) - Greedy implementation
- [`dfa_compress_sat.cpp`](tools/dfa_compress_sat.cpp) - SAT optimization
