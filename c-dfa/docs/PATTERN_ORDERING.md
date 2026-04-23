# Pattern Ordering Optimization

## Problem Statement

The order in which patterns are added to an NFA can affect the resulting DFA size. Patterns with common prefixes should be grouped together to maximize state sharing.

## Key Insight

NFA construction adds patterns sequentially. When patterns share prefixes, they can share NFA states. The more state sharing in the NFA, the smaller the resulting DFA after subset construction.

## Scalable Approach

### Naive Approach (Intractable)
- Try all N! permutations of patterns
- For 100 patterns, this is 100! ≈ 10^158 possibilities
- Clearly infeasible

### Prefix Tree (Trie) Approach (Scalable)
1. Build a prefix tree of all patterns
2. Traverse depth-first to get ordering
3. Patterns with common prefixes are naturally grouped

**Complexity**: O(n × m) where n = number of patterns, m = average pattern length

## Algorithm

```
Pattern Ordering Optimization:

1. Parse all patterns
2. Build prefix tree (trie):
   - Each node represents a character
   - Patterns are paths from root to leaf
   - Shared prefixes share nodes
   
3. Extract ordering:
   - Depth-first traversal
   - Group patterns by common prefix
   - Within groups, sort by specificity (longer first)
   
4. Output reordered patterns
```

## Example

Original order:
```
[safe] cat file.txt
[safe] grep pattern file.txt
[safe] cat (*).txt
[safe] git log
[safe] git status
```

Prefix tree:
```
root
├── c-a-t
│   ├── ' ' → "file.txt"
│   └── ' ' → "(*).txt"
├── g-r-e-p → "pattern file.txt"
└── g-i-t
    ├── ' ' → "log"
    └── ' ' → "status"
```

Optimized order:
```
[safe] cat file.txt
[safe] cat (*).txt
[safe] grep pattern file.txt
[safe] git log
[safe] git status
```

## Implementation

### Pattern Prefix Tree

```c
typedef struct pattern_node {
    char ch;                        // Character at this node
    int pattern_idx;                // -1 if not a leaf
    struct pattern_node* sibling;   // Next sibling (same parent)
    struct pattern_node* child;     // First child
} pattern_node_t;
```

### Ordering Extraction

```c
void extract_ordering(pattern_node_t* node, int* order, int* count) {
    if (node->pattern_idx >= 0) {
        order[(*count)++] = node->pattern_idx;
    }
    // Children first (depth-first)
    for (pattern_node_t* child = node->child; child; child = child->sibling) {
        extract_ordering(child, order, count);
    }
}
```

## Expected Results

For typical pattern sets:
- **5-15% reduction** in NFA states
- **3-10% reduction** in DFA states
- **Minimal overhead** (linear time)

## Integration Point

```
Pattern File → [Pattern Ordering] → NFA Builder → Subset Construction → DFA Minimization
```

Pattern ordering runs before NFA construction.

## Advanced Optimizations

### 1. Category-Aware Grouping
Group patterns by category first, then by prefix within each category:
```
[safe] cat ...
[safe] git ...
[caution] cat /etc/...
[caution] find / ...
```

### 2. Wildcard Handling
Treat wildcards specially in the prefix tree:
- `*` matches any sequence
- `+` matches one or more
- Place wildcard patterns after literal patterns

### 3. SAT Refinement
After prefix-based ordering, use SAT to optimize within groups:
- Small groups (≤10 patterns) can be exhaustively searched
- Larger groups use greedy refinement

## Future Work

1. **Profile-guided ordering**: Use runtime frequency data
2. **Conflict-aware ordering**: Separate patterns that cause DFA blowup
3. **Incremental updates**: Reorder when patterns are added/removed

## Validation Features

The pattern ordering module also performs validation before NFA construction:

### Duplicate Detection

Patterns are checked for duplicates using full line comparison. Duplicates are warned and removed:

```
WARNING: Duplicate pattern detected:
  Duplicate: [safe] cat file.txt
  (duplicate will be removed)
```

### Fragment Reference Validation

Fragment references are validated with namespace semantics:

- `[[name]]` - Looks for `name` in the **same namespace** as the pattern's category
- `[[ns::name]]` - Looks for `ns::name` explicitly (cross-namespace)

Example:
```
[fragment:safe::digit] 0|1|2|3|4|5|6|7|8|9
[fragment:caution::word] a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z

[safe] [[digit]]+        → Looks for safe::digit ✓
[caution] [[word]]+      → Looks for caution::word ✓
[test] [[safe::digit]]+  → Cross-namespace reference ✓
[caution] [[digit]]+     → ERROR: Looks for caution::digit (not defined)
```

### Fragment Syntax

**Correct syntax:**
- `[[fragment]]` - Reference to a fragment in the current namespace
- `[[ns::fragment]]` - Reference to a fragment in a specific namespace
- `(a|b)` - Alternation (single parentheses)

**Incorrect syntax:**
- `((a|b))` - Double parentheses are not allowed - use alternation `(a|b)` or fragment reference `[[ns::name]]`

**Note:** The `[[...]]` syntax was previously `((...))`. Double parentheses `((...))` now result in an error.

## Current Status

| Feature | Status |
|---------|--------|
| Prefix Tree Ordering | ✅ Complete |
| Category-Aware Grouping | ✅ Complete |
| Wildcard Last Placement | ✅ Complete |
| Duplicate Detection | ✅ Complete |
| Fragment Validation | ✅ Complete |
| Namespace Semantics | ✅ Complete |
