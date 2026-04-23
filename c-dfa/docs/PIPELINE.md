# Pattern Validation Pipeline

This document describes the complete pipeline from raw command patterns to optimized DFA for fast pattern matching.

> **Note:** While patterns use character syntax (e.g., `[a-z]`), all phases after parsing operate on **bytes** (0-255), not text. The DFA processes raw byte values, making it suitable for binary data.

## Overview

```
Pattern Input → Validation → Ordering → NFA Build + Parsing → NFA Pre-Minimize → DFA Construct → Flatten → Minimize → Re-Flatten → Compress → Layout → Binary DFA
```

---

## Phase 1: Pattern Validation

**File:** `tools/pattern_order.c`

Validates patterns using a **light shallow parse** before full processing.

### What it does:
- **Category Verification**: Validates category tags (safe, caution, dangerous, etc.)
- **Fragment Existence**: Checks that referenced fragments are defined
- **Basic Syntax Check**: Light validation only (full parsing happens later)

### Why it matters:
Catches obvious errors early with minimal overhead.

---

## Phase 2: Pattern Ordering

**File:** `tools/pattern_order.c`

Reorders patterns using a **light shallow parse** to optimize downstream processing.

### What it does:
- **Prefix Tree Grouping**: Uses a trie to group patterns with common prefixes
- **Category Organization**: Groups patterns by category
- **Fragment Ordering**: Ensures fragments are defined before use

### Why it matters:
Patterns sharing common prefixes can share NFA/DFA states, dramatically reducing overall state count.

---

## Phase 3: NFA Construction + Parsing

**File:** `tools/nfa_builder.c` (integrated recursive descent parser)

Parses pattern syntax and builds NFA in a single pass.

### Supported Syntax:

| Syntax | Meaning |
|--------|---------|
| `git status` | Literal characters (space normalizes to `[ \t]+`) |
| `[abc]` | Character class - matches one of a, b, or c |
| `[^abc]` | Negated character class |
| `a*` | Zero or more of preceding element |
| `a+` | One or more of preceding element |
| `a?` | Zero or one of preceding element |
| `a\|b` | Alternation - matches a OR b |
| `(expr)` | Groups expressions |
| `[[FRAGMENT]]` | Fragment reference |
| `<cap>pattern</cap>` | Capture tag |
| `\*` | Standalone `*` as wildcard argument |
| `\x` | Escape character x literally |

### Single-Pass RDP:

The parser combines parsing and NFA construction:
1. **Parse** the pattern syntax (RDP)
2. **Build** NFA states/transitions immediately
3. **Emit** complete NFA when pattern completes

This avoids creating an intermediate parse tree - NFA is built directly during parsing.

### NFA Structure:
```
State 0 (start) --ε--> State 1 --'g'--> State 2 --'i'--> State 3 --'t'--> ...
                                      
Each state has:
- transitions[symbol_id] → target_state (or -1)
- category_mask → security category bits
- is_eos_target → can match empty (for *, ?)
- pattern_id → which pattern this state accepts
```

### Key Concepts:
- **Epsilon (ε)**: Non-consuming transitions (VSYM_EPS = 257)
- **EOS Marker**: Marks end-of-string (VSYM_EOS = 258)
- **Fork State**: State with `is_eos_target = true` - allows zero-length match for quantifiers
- **Branch**: Alternative path in alternation (`a|b`)

---

## Phase 4: NFA Pre-Minimization

**File:** `tools/nfa_preminimize.c` (incoming)

Reduces NFA complexity before DFA conversion using prefix-merging and local simplifications.

### What it does:
- **Prefix Merging**: Patterns with common prefixes share NFA states
- **Unreachable State Pruning**: Removes states not reachable from start
- **Local Simplifications**: Removes redundant epsilon transitions, merges equivalent states

### Why it matters:
- Reduces NFA size before expensive subset construction
- Less strain on the full DFA pipeline
- Smaller initial NFA → fewer DFA states generated

---

## Phase 5: DFA Construction (Subset Construction)

**File:** `tools/nfa2dfa.c`

Converts NFA to Deterministic Finite Automaton using subset construction.

### What it does:
- **Epsilon Closure**: Computes all NFA states reachable via epsilon
- **State Subset Creation**: Each DFA state represents a set of NFA states
- **Transition Construction**: For each input symbol, compute next DFA state
- **Category Collection**: Aggregates category masks from constituent NFA states
- **Fork Category Handling**: Special handling for `is_eos_target` states in quantifiers
- **Marker Harvesting**: Collects capture group markers from NFA

### Subset Construction Algorithm:
```
1. Start with epsilon-closure of NFA start state
2. For each DFA state S:
   For each input symbol c:
     Compute epsilon-closure of all NFA states reachable from S on c
     This becomes the next DFA state
3. Mark DFA states as accepting if any constituent NFA state is accepting
```

### Key Optimizations:
- **Hash-based Deduplication**: Uses `DFA_HASH_SIZE = 32749` to detect duplicate states
- **Fork State Categories**: Collects category from all reachable fork states for initial state
- **EOS Target Handling**: Properly handles states that can match empty via `is_eos_target`

---

## Phase 6: DFA Flattening

**File:** `tools/nfa2dfa.c` (`flatten_dfa()`)

Expands special transitions into full 256-byte transition tables.

### What it does:
- **ANY Symbol Expansion**: Expands symbol 256 to all 256 byte values
- **SPACE/TAB Expansion**: Expands symbols 259/260 to space and tab
- **Full Transition Table**: Each state gets explicit transition for all 256 chars

### Why it matters:
- Converts sparse NFA-style transitions to dense DFA-style tables
- Enables efficient O(1) transition lookup during evaluation
- Required before minimization and compression

### Example:
```
Before: state 5 has ANY→10 (one transition)
After:  state 5 has 'a'→10, 'b'→10, ..., 'z'→10 (256 transitions)
```

---

## Phase 7: DFA Minimization

**File:** `tools/dfa_minimize.c`

Reduces DFA to minimal equivalent form.

### Algorithms Available:

#### Hopcroft's Algorithm (Default)
- **Complexity**: O(n log n)
- **How it works**: Partition refinement using worklist
- **Best for**: General-purpose minimization

#### Moore's Algorithm
- **Complexity**: O(n²)
- **How it works**: Table-filling method
- **Note**: Used as fallback/verification

#### Brzozowski's Algorithm
- **Complexity**: O(2^n) worst case
- **How it works**: Double reversal (reverse DFA, minimize, reverse again, minimize)
- **Note**: Can produce different result than Hopcroft

#### SAT-based Minimization
- **Requires**: CaDiCaL SAT solver
- **Guarantee**: Provably minimal
- **Note**: Slower but optimal

### What it does:
1. **Dead State Pruning**: Remove states that can't reach accepting states
2. **Partition Refinement**: Split partitions until all states in each partition are equivalent
3. **State Merging**: Merge equivalent states into single representative

### Partition Structure:
```
Initial partition: {accepting states}, {non-accepting states}
Refinement: Split based on transition behavior
Final: Each block contains equivalent states
```

### Re-Flatten After Minimization:
After minimization, states are re-numbered. The DFA must be re-flattened to update transition tables with new state indices (except for Brzozowski algorithm which handles this internally).

---

## Mealy Machine Subsystem: Capture Group Extraction

The c-dfa project uses a **Mealy Machine** architecture to support capture group extraction. While the core DFA is a standard acceptor (output: match/no-match), the Mealy layer outputs capture metadata during evaluation.

### What is a Mealy Machine?

A Mealy Machine is a finite state machine where output depends on both **current state** and **input symbol**. In contrast:
- **DFA (Moore/Mealy output)**: Output associated with states
- **Mealy Machine**: Output associated with **transitions**

### Capture Architecture

```
Input: "git status"
         ↓
    [DFA Evaluation] → Match found!
         ↓
    [Mealy Replay] → Extract captures
         ↓
Output: {capture_0: "status", start: 4, end: 10}
```

### How Captures Work

#### Phase A: NFA Marker Creation (nfa_builder.c)

When parsing patterns like `cmd (?<arg>.*)`, markers are inserted on transitions:

```c
// Marker types
#define MARKER_TYPE_START 0   // Capture group start
#define MARKER_TYPE_END 1      // Capture group end

// Marker structure
typedef struct {
    uint16_t type;    // START or END
    uint16_t uid;     // Unique capture ID
} marker_t;
```

#### Phase B: DFA Marker Harvesting (nfa2dfa.c)

During subset construction, markers from NFA states are "harvested" into the DFA:

```c
// Each DFA transition can have multiple markers
typedef struct {
    uint32_t markers[MAX_MARKERS_PER_DFA_TRANSITION];
    int count;
} MarkerList;
```

#### Phase C: Two-Pass Evaluation (dfa_eval.c)

The DFA evaluator uses a **delayed-output Mealy machine** pattern:

**Pass 1: Forward Evaluation**
- Run standard DFA evaluation
- Record state transitions in a trace buffer
- Determine winning pattern (if multiple patterns match)

**Pass 2: Mealy Replay**
- Replay the trace from start
- For each transition, check if it carries output (markers)
- On START marker: Push position to capture stack
- On END marker: Pop from stack, record capture

### Capture Stack

```c
typedef struct {
    int capture_id;
    size_t start_pos;
    size_t end_pos;
} capture_range_t;

// During replay
capture_range_t capture_stack[MAX_CAPTURE_STACK];
int stack_depth = 0;
```

### Capture Filtering

Critical: Only extract captures from the **winning pattern**. This prevents "capture smearing" where captures from non-matching patterns would be incorrectly included.

```c
// Filter by winning pattern
if (result.winning_pattern_id == pattern_id) {
    // Process markers for this pattern
}
```

### Files Involved

| File | Role |
|------|------|
| `tools/nfa_builder.c` | Creates START/END markers during NFA construction |
| `tools/nfa2dfa.c` | Harvests markers into DFA transition tables |
| `src/dfa_eval.c` | Two-pass evaluation with capture replay |
| `src/dfa_loader.c` | Loads capture name table from binary DFA |

### Marker Encoding

Markers are encoded in transition metadata:

```c
// Encode marker
uint32_t marker = MARKER_ENCODE(type, uid);

// Decode marker
uint16_t type = MARKER_GET_TYPE(marker);
uint16_t uid = MARKER_GET_UID(marker);
```

### Name Table

Capture IDs are mapped to human-readable names in the binary DFA:

```
Pattern: cmd (?<action>status|log|branch)
Capture UID: 0 → Name: "action"

Pattern: cmd (?<arg>.*)
Capture UID: 0 → Name: "arg"
```

### Example: Pattern `cmd (?<cmd>git) (?<sub>status|log)`

```
Input: "cmd git status"

Pass 1 (DFA):
  State 0 → 'c' → State 1 → 'm' → State 2 → ... → Match!
  Winning pattern: 0 (cmd git status)

Pass 2 (Mealy Replay):
  'c' → no marker
  'm' → no marker
  'd' → no marker
  ' ' → no marker
  'g' → MARKER_START(uid=0)  // Start "cmd" capture
  'i' → no marker
  't' → MARKER_END(uid=0)    // End "cmd" capture
  ' ' → MARKER_START(uid=1)  // Start "sub" capture
  's' → no marker
  ...
  's' → MARKER_END(uid=1)    // End "sub" capture

Result:
  captures[0]: {name: "cmd", start: 4, end: 7}
  captures[1]: {name: "sub", start: 8, end: 14}
```

### Key Design Decisions

1. **Delayed Output**: Captures extracted in second pass, not during forward evaluation
2. **Pattern Filtering**: Only winning pattern's captures are extracted
3. **Stack-based Tracking**: Handles nested captures correctly
4. **UID-based Matching**: START/END markers matched by unique ID, not position
5. **Minimization-aware**: Capture payloads prevent incorrect state merging

### Known Limitations

- NFA-to-DFA conversion with capture markers can hang on complex patterns
- Quantifier `+` with nested captures has known issues
- Full capture extraction has edge cases with alternation

## Phase 8: Transition Rule Compression

**File:** `tools/dfa_compress.c`

Compresses transition tables to reduce memory usage.

### Compression Strategies:

#### Rule Merging
Combines multiple LITERAL rules with same target:
```
Before: 'a'→S1, 'b'→S1, 'c'→S1
After:  ['a','b','c']→S1 (merged rule)
```

#### Range Optimization
Expands character ranges:
```
Before: 'a'-'z'→S1
After:  RANGE('a','z')→S1
```

#### Default Sharing
Uses default transition for unspecified characters:
```
Before: Many specific rules
After:  DEFAULT→S_default + specific overrides
```

### SAT-based Compression (Optional)
- Uses CaDiCaL SAT solver
- Finds optimal grouping
- Slower but produces minimal rule count

### Options:
```c
compress_options_t opts = {
    .enable_rule_merging = true,
    .enable_range_optimization = true,
    .enable_default_sharing = true,
    .max_group_size = 3,
    .use_sat = false
};
```

## Phase 9: DFA Layout

**File:** `tools/dfa_layout.c`

Optimizes binary layout for cache performance using **SCC-based decomposition**.

### SCC-Based Layout

The layout decomposes the DFA into strongly connected components (SCCs), then orders them optimally.

#### Algorithm:
1. **Forward BFS**: States close to start state (fan-out region)
2. **Reverse BFS**: States close to accepting states (fan-in region)
3. **SCC Detection**: Tarjan's algorithm finds strongly connected components in the intermediate region
4. **Condensation Graph**: Build DAG of SCCs with edge weights (transition counts)
5. **SCC Ordering**: Greedy refinement of topological sort to minimize cross-SCC transition distances
6. **Bounded SAT** (optional): Optimal ordering for small condensation graphs (≤20 SCCs)
7. **Layered BFS Unrolling**: Within each SCC, states ordered by BFS layer from entry points

### Cache-Line Alignment

States are aligned to 64-byte cache boundaries with a **max-slack** constraint:

- `MAX_SLACK = 5`: only pad if ≤5 bytes wasted
- Hot states (start + accepting): 4× slack (20 bytes)
- Dynamic buffer sizing based on actual alignment

### Why it matters:
- **Forward path locality**: BFS layers within SCCs are contiguous in memory
- **Cross-SCC locality**: Frequently connected SCCs are adjacent
- **Cache-line boundaries**: Hot states start at cache-line boundaries
- **Bounded SAT**: Finds optimal SCC ordering for small graphs

### Layout Order:
```
[Entry fan-out: BFS layers 0..d1]
[SCC_0 unrolled, SCC_1 unrolled, ...]  ← refined condensation order
[Exit fan-in: rev-BFS layers 0..d2]
```

### Option: Bounded SAT for Condensation Ordering

**File:** `tools/dfa_layout_sat.cpp` (requires CaDiCaL)

For condensation graphs with ≤20 SCCs, bounded SAT finds optimal ordering:
- One-hot position encoding: `x[i][p]` = SCC i at position p
- Topological constraints: edge i→j implies pos[i] < pos[j]
- Sequential counter: bounds total weighted transition distance
- Binary search: iteratively tightens bound until UNSAT

## Summary

| Phase | File | Purpose | Key Output |
|-------|------|---------|------------|
| 1. Validation | `pattern_order.c` | Validate patterns (shallow) | Validation report |
| 2. Ordering | `pattern_order.c` | Order patterns by prefix (shallow) | Ordered patterns |
| 3. NFA Build + Parsing | `nfa_builder.c` | Parse & build NFA | NFA states/transitions |
| 4. NFA Pre-Minimize | `nfa_preminimize.c` | Prefix merging, local simplifications | Reduced NFA |
| 5. DFA Construct | `nfa2dfa.c` | Subset construction | DFA states/transitions |
| 6. DFA Flatten | `nfa2dfa.c` | Expand special transitions | Full 256-char tables |
| 7. DFA Minimize | `dfa_minimize.c` | Minimize DFA | Minimal DFA |
| 8. Compress | `dfa_compress.c` | Rule merging, range opt | Compressed rules |
| 9. Layout | `dfa_layout.c` | SCC-based cache-optimized layout | Optimized binary |

## Usage Flow

```bash
# Build the main tool
make

# Build NFA from patterns
./tools/nfa_builder patterns/*.txt > output.nfa

# Convert to DFA with minimization
./tools/nfa2dfa_advanced --minimize-hopcroft input.nfa -o output.dfa

# Or run full pipeline via test runner
./bin/dfa_test --test-set A --minimize-hopcroft
```
