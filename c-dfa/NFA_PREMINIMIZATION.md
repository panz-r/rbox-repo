# NFA Pre-Minimization

This document describes the NFA pre-minimization system that reduces NFA state count before subset construction, minimizing DFA blowup.

## Overview

The pre-minimization system applies several optimization passes to reduce NFA size while preserving language equivalence:

1. **Epsilon elimination** - Bypass pass-through states connected only by epsilon
2. **Epsilon chain compression** - Shorten multi-hop epsilon chains
3. **Unreachable state pruning** - Remove states not reachable from start
4. **Final state deduplication** - Merge equivalent accepting states
5. **Bidirectional incremental merging** - O(n log n) prefix/suffix merging
6. **SAT-based optimal merge selection** - Find maximum set of non-conflicting merges

## Algorithm Details

### Epsilon Elimination (O(n))

States that have only a single epsilon outgoing transition and no accepting properties can be safely bypassed. All incoming transitions are redirected to the epsilon target.

### Epsilon Chain Compression (O(n))

Multi-hop epsilon chains A → B → C → D are compressed to A → D when intermediate states have no accepting properties.

### Final State Deduplication (O(n log n))

Accepting states with identical outcomes (category_mask, pending_markers) and identical outgoing transitions are merged. This is a prerequisite for effective suffix merging.

### Bidirectional Incremental Merging (O(n log n))

Combines prefix and suffix merging in an iterative fixpoint:

**Prefix merging**: States with the same single incoming (source, symbol) pair and identical prefix properties can be merged by combining their outgoing transitions (union of futures).

**Suffix merging**: States with the same single outgoing (target, symbol) pair and identical accepting properties can be merged by combining their incoming transitions (union of pasts).

The algorithm alternates between prefix and suffix passes until no more merges are possible.

### SAT-Based Optimal Merge Selection

The SAT-based approach uses the CaDiCaL solver to find the **maximum set of non-conflicting merges** from pre-filtered candidates.

#### Key Insight

Instead of using SAT for bisimulation verification (which is hard), we use SAT for **optimal selection** from pre-filtered candidates. This transforms SAT from a verification tool into an optimization tool.

#### Algorithm

1. **Candidate Generation** (O(n log n)): Collect merge candidates from prefix/suffix analysis
2. **Conflict Analysis** (O(m²)): Build conflict graph between candidates
3. **SAT Encoding**: Variables for each candidate, constraints for conflicts
4. **Solve**: Find maximum set of non-conflicting merges
5. **Apply**: Execute all selected merges

#### Configuration

```c
nfa_premin_options_t opts = nfa_premin_default_options();
opts.enable_sat_optimal = true;    // Enable SAT optimal selection
opts.max_sat_candidates = 200;     // Maximum candidates (bounds complexity)
```

#### Complexity

The SAT instance size is bounded by `max_candidates`, ensuring predictable performance. For most NFAs, the number of merge candidates is small, making SAT solving fast.

## Usage

### Default Options

```c
nfa_premin_options_t opts = nfa_premin_default_options();
// Default enables: epsilon_elim, epsilon_chain, prune, final_dedup, bidirectional
// Default disables: merge, identical, sat, sat_optimal
```

### With SAT Optimization

```c
nfa_premin_options_t opts = nfa_premin_default_options();
opts.enable_sat_optimal = true;
opts.max_sat_candidates = 100;
opts.verbose = true;

int removed = nfa_preminimize(nfa, &state_count, &opts);
```

### Statistics

```c
nfa_premin_stats_t stats;
nfa_premin_get_stats(&stats);

printf("Original states: %d\n", stats.original_states);
printf("Final states: %d\n", stats.minimized_states);
printf("Epsilon bypassed: %d\n", stats.epsilon_bypassed);
printf("Bidirectional merged: %d\n", stats.prefix_merged);
printf("SAT optimal merged: %d\n", stats.sat_optimal);
```

## Implementation Files

- [`nfa_preminimize.c`](tools/nfa_preminimize.c) - Main implementation
- [`nfa_preminimize.h`](tools/nfa_preminimize.h) - Public API
- [`nfa_preminimize_sat_optimal.cpp`](tools/nfa_preminimize_sat_optimal.cpp) - SAT-based optimal selection
- [`nfa_preminimize_sat.cpp`](tools/nfa_preminimize_sat.cpp) - Legacy SAT verification (deprecated)
- [`nfa_preminimize_windowed.cpp`](tools/nfa_preminimize_windowed.cpp) - Windowed SAT (deprecated)

## Performance Characteristics

| Optimization | Complexity | Default |
|-------------|------------|---------|
| Epsilon elimination | O(n) | Enabled |
| Epsilon chain compression | O(n) | Enabled |
| Unreachable pruning | O(n) | Enabled |
| Final state deduplication | O(n log n) | Enabled |
| Bidirectional merging | O(n log n) | Enabled |
| SAT optimal selection | O(m²) + SAT | Disabled |

Where n = NFA states, m = number of merge candidates (bounded).

## Safety Guarantees

All enabled optimizations preserve language equivalence:

- **Epsilon elimination**: Only bypasses states with no accepting properties
- **Prefix merging**: Only merges states with identical prefix properties
- **Suffix merging**: Only merges states with identical accepting properties
- **SAT optimal**: Only merges pre-verified safe candidates

The `enable_identical` option is **disabled by default** because merging states with identical signatures can change the language for NFAs (unlike DFAs).
