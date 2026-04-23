# DSL Format Specification

## Overview

The DSL (Domain Specific Language) provides a text-based serialization format for NFA and DFA graphs. It is used for testing, verification, and golden-file comparison of the C-DFA pipeline.

## Grammar (EBNF)

```ebnf
document     ::= nfa-doc | dfa-doc

nfa-doc       ::= nfa-header nfa-state*
nfa-header    ::= "version: " number eol
                 [ "#" comment eol ]

dfa-doc       ::= dfa-header dfa-state*
dfa-header    ::= "type: DFA" eol
                 "version: " number eol
                 "alphabet_size: " number eol
                 "initial: " number eol

nfa-state     ::= state-id [": start"] [": accept"
                   [" category=" hex-number]
                   [" pattern=" number] eol
                  transition*

dfa-state     ::= state-id [": start"] [": accept"
                   [" pattern=" number]
                   [" category=" hex-number] eol
                  transition*

transition     ::= state-id symbol [marker-list] "->" target eol
                 | state-id symbol "-" symbol "->" target eol
                 | state-id "default ->" target eol
                 | state-id "EOS" [marker-list] "->" target eol

marker-list    ::= "[" marker ("," marker)* "]"
marker         ::= hex-number

symbol         ::= literal | escape | virtual
literal        ::= [a-z] | [A-Z] | [0-9] | printable
escape         ::= "'" char "'" | '"' char '"'
virtual        ::= "EPS" | "ANY" | "SPACE" | "TAB" | "EOS"
                 | "0x" hex-byte

hex-number     ::= "0x" [0-9a-fA-F]+
number         ::= [0-9]+
hex-byte       ::= [0-9a-fA-F]{2}
eol            ::= "\n"
comment        ::= any characters (ignored)
```

## Header Lines

### NFA Header
```
version: 1
```

### DFA Header
```
type: DFA
version: 1
alphabet_size: 256
initial: 0
```

## State Definition

States are numbered sequentially starting from 0. The canonical ordering is determined by BFS from the start state.

### NFA State Format
```
0: start
0 EPS -> 1,2
1: accept category=0x01 pattern=1
```

### DFA State Format
```
0: start: accept pattern=1 category=0x01
0 'a' -> 1
0 'b' -> 2
0 default -> 3
0 EOS -> 4
1 'a'-'z' -> 0
```

## Transitions

### Symbol Transitions
```
0 'a' -> 1
0 0x20 -> 2
```

### Range Transitions (DFA)
```
0 'a'-'z' -> 1
0 0x00-0x1F -> 2
```

### EPS Transitions (NFA)
```
0 EPS -> 1
0 EPS -> 1,2,3
```

### Default Transition (DFA)
Default transitions handle any byte not covered by explicit transitions.
```
0 default -> 1
```

### EOS Transition
```
0 EOS -> 1
```

### Marker Lists
```
0 'a' [0x00000001,0x00000002] -> 1
```

## Virtual Symbols

| Symbol | Description |
|--------|-------------|
| `EPS` | Epsilon transition (NFA only) |
| `ANY` | Matches any byte |
| `SPACE` | Matches whitespace (0x20) |
| `TAB` | Matches tab (0x09) |
| `EOS` | End-of-string marker |

## Examples

### Simple NFA: `a`
```
version: 1
0: start
0 'a' -> 1
1: accept category=0x01 pattern=0
```

### NFA with Alternation: `(a|b)`
```
version: 1
0: start
0 EPS -> 1,2
1:
1 'a' -> 3
2:
2 'b' -> 3
3: accept category=0x01 pattern=0
```

### Simple DFA
```
type: DFA
version: 1
alphabet_size: 256
initial: 0
0: start: accept pattern=0
0 'a' -> 1
1:
1 'b' -> 2
2: accept pattern=0
2 default -> 2
```

### DFA with Range Compression
```
type: DFA
version: 1
alphabet_size: 256
initial: 0
0: start: accept pattern=0
0 'a'-'z' -> 1
0 'A'-'Z' -> 1
1:
1 default -> 0
```

## Canonicalization

The DSL uses deterministic canonical ordering:

1. **BFS from start state** - States are ordered by Breadth-First Search from state 0
2. **Signature-based sorting** - At each BFS level, states are sorted by their signature (accepting properties + transitions)
3. **Symbol ordering** - Transitions are ordered by symbol ID for determinism

## Round-Trip Guarantee

Serialization produces deterministic output. For NFAs, `serialize -> deserialize -> serialize` produces identical output. For DFAs, the same property holds when using the same build_dfa_state_t structures.

## Validation

The DSL validator checks:
- **Determinism** - At most one transition per symbol per state
- **Range validity** - Start <= end, boundaries in [0, 255]
- **Non-overlapping ranges** - Warning for overlapping ranges
- **Target bounds** - All transition targets reference valid states
- **Default conflicts** - Warning if default coexists with explicit byte transitions

## Integration with Tests

### Using ASSERT_NFA_EQ_STR
```c
nfa_graph_t *graph = nfa_builder_finalize(ctx, NULL);
ASSERT_NFA_EQ_STR(graph,
    "version: 1\n"
    "0: start\n"
    "0 'a' -> 1\n"
    "1: accept category=0x01 pattern=0\n",
    "literal 'a' test");
```

### Using ASSERT_DFA_EQ_STR
```c
ASSERT_DFA_EQ_STR(dfa_ptr, state_count, alphabet, 256, NULL, 0,
    "type: DFA\n"
    "version: 1\n"
    "alphabet_size: 256\n"
    "initial: 0\n"
    "0: start: accept pattern=0\n"
    "0 'a' -> 1\n",
    "simple DFA test");
```

### Round-Trip Verification
```c
char *err = dfa_dsl_verify_roundtrip(dfa, state_count, alphabet, 256, markers, marker_count);
if (err) {
    fprintf(stderr, "Round-trip failed: %s\n", err);
    free(err);
}
```

### DOT Output
```c
char *dot = dfa_dsl_to_dot(parsed_dfa);
// Render with: dot -Tpng -o output.png
```
