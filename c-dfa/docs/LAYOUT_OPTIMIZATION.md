# Layout Optimization

## Overview

The layout optimizer reorders DFA states in the binary output to maximize cache locality during evaluation. It uses **SCC-based decomposition** with **condensation graph ordering**.

## Algorithm

### 1. Region Decomposition

```
S0 → S1 → S2 → [SCC_A] → [SCC_B] → S8 → S9 ✓
          ↕    [SCC_C]
   fan-out     intermediate    fan-in
```

- **Fan-out** (Forward BFS from S0): States near start state
- **Fan-in** (Reverse BFS from accepting states): States near accept states
- **Intermediate**: Everything in between - decomposed into SCCs

### 2. SCC Detection (Tarjan's Algorithm)

Finds strongly connected components in the intermediate region. Each SCC is a maximal set of states where every state is reachable from every other.

- Iterative implementation (handles deep graphs without stack overflow)
- O(V + E) complexity
- Dynamic allocation (no hardcoded state limits)

### 3. Condensation Graph

Builds a DAG of SCCs:
- Nodes: SCCs
- Edges: Transitions between SCCs (weighted by count)
- This DAG captures the coarse structure of the DFA

### 4. SCC Ordering

Orders SCCs to minimize total weighted transition distance:

```
cost = Σ cond[i][j] × |pos[i] - pos[j]|
```

**Strategy:**
1. Topological sort of condensation DAG (respects edge directions)
2. Greedy refinement via adjacent swap optimization
3. Optional: Bounded SAT for small graphs (≤20 SCCs)

### 5. Layered BFS Unrolling

Within each SCC, states are ordered by BFS layer from entry points:

```
SCC: A → B → C → D
     ↑         ↓
     F ← E ←───┘

Unrolled: Layer 0: A
          Layer 1: B, F
          Layer 2: C, E
          Layer 3: D
```

Forward paths through loops become cache-linear. Back-edges become long jumps, but that's unavoidable with cycles.

### 6. Final Layout

```
[Entry fan-out BFS layers]
[SCC_0 unrolled, SCC_1 unrolled, ...]  ← SAT/refined order
[Exit fan-in reverse-BFS layers]
```

## Cache-Line Alignment

States are aligned to 64-byte cache boundaries with a max-slack constraint:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `MAX_SLACK` | 5 | Max bytes wasted for alignment |
| Hot state slack | 20 | 4× slack for start + accepting states |
| Cache line | 64 bytes | Alignment boundary |

**Example:**
```
State 0 (start):    offset 64   ← aligned (hot state, ≤20 bytes padding)
State 1:            offset 84   ← not aligned (28 bytes padding > 5)
State 2 (accept):   offset 128  ← aligned (hot state)
```

## Bounded SAT (Optional)

**File:** `tools/dfa_layout_sat.cpp` (requires CaDiCaL)

For condensation graphs with ≤20 SCCs, SAT finds optimal ordering:

### Encoding:
- **Variables**: `x[i][p]` = SCC i at position p (one-hot, k² vars)
- **All-different**: Each SCC at one position, each position has one SCC
- **Topological**: If edge i→j, then pos[i] < pos[j]
- **Distance**: `t_{i,j,d}` = (|pos[i] - pos[j]| ≥ d) for d = 1..k-1
- **Cost**: Σ cond[i][j] × Σ_d t_{i,j,d}
- **Bound**: Sequential counter ≤ greedy_cost

### Search:
Binary search: find minimum cost that is SAT.

### When it helps:
- Condensation graphs with 5-20 SCCs
- When greedy ordering isn't optimal
- Not needed for graphs with <5 SCCs (greedy is already optimal)

## Small DFA Guard

For DFAs with <8 states, SCC analysis is skipped. The BFS layout (fan-out → identity → fan-in) is already optimal for small DFAs.

## Files

| File | Purpose |
|------|---------|
| `tools/dfa_layout.c` | Layout optimizer (SCC, BFS, greedy refinement) |
| `tools/dfa_layout_sat.cpp` | Bounded SAT for condensation ordering |
| `tools/dfa_layout_sat_stub.c` | Stub when CaDiCaL not available |
| `tools/dfa_layout_sat.h` | Header |
