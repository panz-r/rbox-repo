# NFA DSL - Compact Serialization Format

## Overview

The NFA DSL provides a human-readable text format for dumping, comparing, and
verifying NFA structures. It is used exclusively for testing and debugging --
not linked into production builds.

## Format

Each NFA is a sequence of **state definitions** and **transition lines**,
preceded by a version header.

```
version: 1
0: start
0 'a' -> 1
0 EPS -> 2,3
1: accept category=0x01 pattern=1
```

## Grammar (EBNF)

```
nfa_file     = version_header { global_meta | state_def | transition } .

version_header = "version:" integer .

global_meta  = "identifier=" string
             | "alphabet_size=" integer .

state_def    = state_id ":" { "start" | "accept" | "eos"
               | "category" "=" hex_number
               | "pattern" "=" integer } .

transition   = state_id symbol "->" target_list [ "[" marker_list "]" ] .

symbol       = literal_char | escape_seq | virtual_sym | integer .

literal_char = "'" char "'" .
escape_seq   = "\n" | "\t" | "\r" | "\\x" hex_digit hex_digit .
virtual_sym  = "EPS" | "ANY" | "EOS" | "SPACE" | "TAB" .

target_list  = integer { "," integer } .
marker_list  = hex_number { "," hex_number } .
```

### Lexical Notes

- Comments start with `#` and go to end of line.
- Whitespace separates tokens but is otherwise ignored.
- Keywords are case-insensitive.

## Virtual Symbols

| Name   | ID  | Meaning           |
|--------|-----|-------------------|
| `ANY`  | 256 | Any byte (0-255)  |
| `EPS`  | 257 | Epsilon           |
| `EOS`  | 258 | End of string     |
| `SPACE`| 259 | Space (ASCII 32)  |
| `TAB`  | 260 | Tab (ASCII 9)     |

## Canonicalization Rules

Serialized output is always **canonical** -- two structurally identical NFAs
produce byte-identical output.

| Element            | Rule                                              |
|--------------------|---------------------------------------------------|
| Version header     | Always `version: 1` on first line                 |
| State IDs          | BFS from start, tie-break by (signature, old ID)  |
| Unreachable states | Omitted                                           |
| Transitions/state  | Sorted by symbol ID                               |
| Targets            | Sorted ascending after remapping                  |
| Markers            | Sorted by packed 32-bit value                     |
| Accept line        | Always `accept category=0xNN pattern=PP`          |

## API

### Serialization

```c
// Full NFA to FILE or string
void nfa_dsl_dump(FILE *out, const void *ctx);
char *nfa_dsl_to_string(const void *ctx);

// Focused sub-graph extraction
void nfa_dsl_dump_filtered(FILE *out, const void *ctx, nfa_dsl_filter_t filter);
char *nfa_dsl_to_string_filtered(const void *ctx, nfa_dsl_filter_t filter);
```

### Deserialization

```c
dsl_nfa_t *nfa_dsl_parse_file(const char *filename);
dsl_nfa_t *nfa_dsl_parse_string(const char *text);
void       nfa_dsl_free(dsl_nfa_t *nfa);
```

### Comparison and Diff

```c
bool  nfa_dsl_equal(const dsl_nfa_t *a, const dsl_nfa_t *b);
char *nfa_dsl_diff(const char *expected, const char *actual);
bool  nfa_dsl_assert_equal(const char *label, const char *expected, const char *actual);
char *nfa_dsl_verify_roundtrip(const void *ctx);
```

### Validation

```c
dsl_validation_t *nfa_dsl_validate(const dsl_nfa_t *nfa);
void nfa_dsl_validation_free(dsl_validation_t *v);
void nfa_dsl_validation_print(FILE *out, const dsl_validation_t *v);
```

### Visualization

```c
void  nfa_dsl_dump_dot(FILE *out, const dsl_nfa_t *nfa);
char *nfa_dsl_to_dot(const dsl_nfa_t *nfa);
```

### Test Macros

```c
// Compare builder output against expected string
ASSERT_NFA_EQ_STR(ctx, expected_str, "test label");

// Compare builder output against golden file
ASSERT_NFA_EQ_FILE(ctx, "tests/expected/test.nfa", "test label");
```

## Cookbook

### Literal `"a"`

```
version: 1
0: start
0 'a' -> 1
1: accept category=0x01 pattern=1
```

### Alternation `(a|b)`

```
version: 1
0: start
0 EPS -> 1,2
1:
1 'a' -> 3
2:
2 'b' -> 3
3: accept category=0x01 pattern=1
```

### Kleene star `(a)*`

```
version: 1
0: start
0 EPS -> 1,3
1:
1 'a' -> 2
2 EPS -> 1,3
3: accept category=0x01 pattern=1
```

## DFA Serialization

The DSL also supports **DFA output** using a subset of the NFA DSL with
additional features for determinism and compression. A `type: DFA` header
distinguishes DFA files from NFA files.

### DFA vs NFA Differences

| Feature                | NFA             | DFA                    |
|------------------------|-----------------|------------------------|
| Multiple targets/sym   | Yes (`-> 1,2`)  | **No** (exactly one)   |
| Epsilon (`EPS`)        | Yes             | **No**                 |
| Ranges (`'a'-'z'`)     | No              | **Yes**                |
| Default transitions    | No              | **Yes** (`default ->`) |
| Virtual symbols        | Yes             | Yes                    |
| Markers                | Yes             | Yes                    |
| Accept state props     | Yes             | Yes                    |

### DFA Grammar Extension

```
dfa_file    = type_header version_header alphabet_header initial_header
              { global_meta | state_def | dfa_transition } .

type_header   = "type:" "DFA" .
version_header = "version:" integer .
alphabet_header = "alphabet_size:" integer .
initial_header = "initial:" integer .

dfa_transition = state_id dfa_symbol "->" integer [ "[" marker_list "]" ]
               | state_id "default" "->" integer
               | state_id "EOS" "->" integer [ "[" marker_list "]" ] .

dfa_symbol   = literal_char | literal_char "-" literal_char | virtual_sym .
```

### DFA Canonicalization

DFA serialization applies these additional canonicalization rules:

| Element              | Rule                                               |
|----------------------|----------------------------------------------------|
| Header               | `type: DFA`, `version:`, `alphabet_size:`, `initial:` |
| Range compression    | Consecutive same-target literals → `'a'-'z' -> N`  |
| Default transition   | Most common target (>= 4 literals) → `default -> N`|
| Default placement    | Always last transition in a state                  |
| EOS transitions      | Separate from byte transitions                     |

### DFA Example

```
type: DFA
version: 1
alphabet_size: 261
initial: 0
0: start
0 'a'-'z' -> 1
0 default -> 2
1: accept category=0x01 pattern=1
2:
```

### DFA API

```c
// Serialize build-time DFA states to DSL format
void dfa_dsl_dump(FILE *out,
                   const build_dfa_state_t * const *dfa,
                   int state_count,
                   const alphabet_entry_t *alphabet,
                   int alphabet_size,
                   const void *marker_lists,
                   int marker_list_count);

char *dfa_dsl_to_string(const build_dfa_state_t * const *dfa,
                         int state_count,
                         const alphabet_entry_t *alphabet,
                         int alphabet_size,
                         const void *marker_lists,
                         int marker_list_count);

// Parse DFA DSL text back to dsl_dfa_t
dsl_dfa_t *dfa_dsl_parse_string(const char *text);
dsl_dfa_t *dfa_dsl_parse_file(const char *filename);
void       dfa_dsl_free(dsl_dfa_t *dfa);
```

## Golden File Workflow

1. Build the NFA from your pattern using the builder context.
2. Call `nfa_dsl_to_string(ctx)` to get canonical output.
3. Compare against a golden file with `ASSERT_NFA_EQ_FILE`.
4. On failure, a diff is printed automatically.
5. Use `tests/update_goldens.sh --accept-all` to regenerate all golden files.

## DOT Visualization

Convert any parsed NFA to Graphviz DOT format:

```c
dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
char *dot = nfa_dsl_to_dot(nfa);
// write dot to file, then: dot -Tpng file.dot -o file.png
```
