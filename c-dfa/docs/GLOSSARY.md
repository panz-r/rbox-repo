# C-DFA Terminology Glossary

This document defines all terminology used in the C-DFA project. Use this document to understand the codebase and maintain consistent naming.

## Core Automata Concepts

### NFA (Non-deterministic Finite Automaton)
A finite state machine where each state can transition to multiple states for a given input symbol. Used internally during pattern building.

### DFA (Deterministic Finite Automaton)
A finite state machine where each state has exactly one transition for each possible input. The final output format used for command matching.

### Mealy Machine
An FSM where outputs are associated with transitions (not just states). Used for capture group extraction in C-DFA.

---

## State Types

### State
A single node in an automaton. Can be:
- **NFA State**: Building block during pattern compilation
- **DFA State**: Final state used at runtime

### Accepting State (`accepting`)
A state that represents a successful match. In C-DFA:
- Has a non-zero `category_mask` (command category)
- Has a non-zero `pattern_id` (specific pattern matched)
- Set via `DFA_STATE_ACCEPTING` flag

### Error State
A state that indicates the input cannot match. Has `DFA_STATE_ERROR` flag.

### Dead State
A state with no outgoing transitions. Set via `DFA_STATE_DEAD` flag.

### Fork State
A special state created for quantifiers (like `a+`, `a*`, `a?`):
- Has `is_eos_target = true` (can match empty)
- Has a non-zero `category_mask`
- Enables proper handling of "zero or more", "one or more", "zero or one" patterns

---

## Transitions

### Transition
An edge from one state to another, triggered by input character(s).

### Rule
The encoded representation of a transition in the DFA file format. Includes:
- Match type (literal, range, default, etc.)
- Target state
- Capture markers

### EPSILON Transition (VSYM_EPS = 257)
A non-consuming transition that doesn't require input. Used for:
- Alternation branches `(a|b)`
- Quantifier zero-cases `(a)*`
- Fragment references

### EOS Transition (VSYM_EOS = 258)
End-of-sequence marker. Used for:
- Quantifier one-or-more cases `(a)+`
- Indicates the end of valid input

---

## Pattern Concepts

### Pattern
A specification of characters to match, potentially with:
- Category (safe, caution, modifying, etc.)
- Capture groups
- Quantifiers

### Category
A classification of matched commands:
| Name | Mask | Description |
|------|------|-------------|
| SAFE | 0x01 | Read-only, safe to execute |
| CAUTION | 0x02 | May have side effects |
| MODIFYING | 0x04 | Modifies files or state |
| DANGEROUS | 0x08 | Potentially harmful |
| NETWORK | 0x10 | Network operations |
| ADMIN | 0x20 | Administrative tasks |
| BUILD | 0x40 | Build/compile |
| CONTAINER | 0x80 | Container operations |

### Quantifier
A modifier indicating repetition:
- `*` - Zero or more (uses EPSILON)
- `+` - One or more (uses EOS)
- `?` - Zero or one (uses EPSILON)

### Alternation
A choice between patterns: `(a|b|c)` - matches a, b, or c

### Fragment
A named pattern that can be referenced elsewhere: `[fragment:name] value`

---

## Capture & Markers

### Capture
A named sub-pattern whose matched text is extracted:
- Syntax: `<name>pattern</name>`
- Example: `<cmd>git</cmd>` captures "git" as "cmd"

### Marker
Metadata attached to transitions for capture extraction:
- `pending_marker_t`: In NFA builder, queued markers
- Stored in DFA as marker lists

### Marker Types
- **START** (type=0): Beginning of capture region
- **END** (type=1): End of capture region

### Marker Encoding
Packed into 32-bit integer: `[16-bit PatternID][15-bit UID][1-bit Type]`

---

## Building Process Terms

### Subset Construction
The algorithm that converts NFA to DFA by tracking which NFA states are active simultaneously.

### Minimization
Reducing DFA state count while preserving language:
- **Hopcroft**: O(n log n) algorithm
- **Moore**: Table-filling algorithm
- **Brzozowski**: Double reversal
- **SAT**: Provably optimal (requires CaDiCaL)

### Compression
Reducing DFA file size by merging similar rules:
- **Rule merging**: Combining literal rules
- **Range encoding**: Using character ranges

---

## Data Structures

### NFA State (`nfa_state_t`)
```c
typedef struct {
    uint8_t category_mask;      // Command category
    uint16_t pattern_id;         // Which pattern
    int transitions[MAX_SYMBOLS];  // Outgoing transitions
    multi_target_array_t multi_targets;  // Multiple targets
    bool is_eos_target;         // Can match empty
    pending_marker_t pending_markers[MAX_PENDING_MARKERS];
    int pending_marker_count;
} nfa_state_t;
```

### DFA State (`dfa_state_t`)
```c
typedef struct {
    uint32_t transitions_offset;  // Offset to rule table
    uint16_t transition_count;   // Number of rules
    uint16_t flags;              // ACCEPTING, ERROR, DEAD, CAPTURE_*
    uint16_t accepting_pattern_id; // Which pattern matched
    uint32_t eos_target;         // End-of-sequence target
} dfa_state_t;
```

---

## File Format

### Virtual Symbol IDs
| ID | Name | Purpose |
|----|------|---------|
| 0-255 | Literal | Regular character |
| 256 | ANY | Wildcard match |
| 257 | EPSILON | Non-consuming |
| 258 | EOS | End-of-sequence |
| 259 | SPACE | Whitespace |
| 260 | TAB | Tab character |

---

## Searching This Document

To find definitions in source code:

```bash
# Find accepting state usage
grep -r "accepting" --include="*.c"

# Find fork state handling
grep -r "fork state\|is_eos_target" --include="*.c"

# Find marker definitions
grep -r "pending_marker\|MARKER_TYPE" --include="*.c"

# Find category usage
grep -r "category_mask\|CAT_MASK" --include="*.c"
```
