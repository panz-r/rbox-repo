# ARCHITECTURE Skill

**Scope:** c-dfa subproject only

---
name: architecture
description: Understand ReadOnlyBox NFA/DFA architecture in c-dfa subproject, pattern processing pipeline, and state management
license: MIT
compatibility: opencode
metadata:
  project: readonlybox
  component: c-dfa
  workflow: architecture
  scope: c-dfa-subproject
---

## What I do

Explain the NFA/DFA architecture of the **c-dfa subproject**. Describe how patterns become matching state machines, and why each step matters.

## Scope: c-dfa Subproject

This skill applies to files in `c-dfa/` directory:

```
readonlybox/
├── c-dfa/                              ← THIS SCOPE
│   ├── tools/
│   │   ├── nfa_builder.c              # Pattern → NFA
│   │   ├── nfa2dfa_advanced           # NFA → DFA
│   │   └── dfa2c_array                # DFA → C array
│   ├── src/
│   │   ├── dfa_eval.c                 # Runtime matching
│   │   ├── dfa_loader.c               # DFA loading
│   │   └── dfa_test.c                 # Tests
│   ├── patterns_safe_commands.txt      # Pattern files
│   ├── Makefile
│   └── include/dfa_types.h            # Type definitions
└── cmd/readonlybox/       # Main binary (uses DFA at runtime)
```

## c-dfa Subproject Skills

For c-dfa-specific architecture tasks, use:

- **dfa-building-cdfa** - Build pipeline details
- **dfa-testing-cdfa** - Test execution
- **dfa-debugging-cdfa** - Debugging state machines
- **patterns-cdfa** - Pattern syntax
readonlybox/
├── c-dfa/                              ← THIS SCOPE
│   ├── tools/
│   │   ├── nfa_builder.c              # Pattern → NFA
│   │   ├── nfa2dfa_advanced          # NFA → DFA
│   │   └── dfa2c_array               # DFA → C array
│   ├── src/
│   │   ├── dfa_eval.c                # Runtime matching
│   │   ├── dfa_loader.c              # DFA loading
│   │   └── dfa_test.c                # Tests
│   ├── patterns_safe_commands.txt     # Pattern files
│   ├── Makefile
│   └── include/dfa_types.h           # Type definitions
└── cmd/readonlybox/       # Main binary (uses DFA at runtime)
```

## Architecture Overview

```
Pattern File
    ↓
nfa_builder (C)
    ↓ (NFA)
nfa2dfa_advanced (C)
    ↓ (DFA)
dfa_eval (C)
    ↓
Runtime Matching
```

## Pattern Processing Pipeline

### Step 1: Pattern Parsing

Location: `c-dfa/tools/nfa_builder.c`

Input: `patterns_safe_commands.txt`

Process:
1. Parse each line: `[category:subcategory:ops] pattern`
2. Extract category components
3. Extract fragment definitions
4. Parse pattern syntax into NFA states

### Step 2: NFA Generation

Location: `c-dfa/tools/nfa_builder.c`

Output: `build/readonlybox.nfa` (text format)

NFA Structure:
```
START → state_0 → state_1 → ... → ACCEPTING
```

Each state has transitions on characters.

### Step 3: DFA Conversion

Location: `c-dfa/tools/nfa2dfa_advanced`

Input: NFA file
Output: `build/readonlybox.dfa` (binary)

Process:
1. Subset construction algorithm
2. NFA states → DFA states
3. Generate symbol table
4. Assign acceptance categories

**Note:** Alphabet is now constructed automatically by nfa_builder from pattern file - no external alphabet file needed.

### Step 4: DFA Compilation to C

Location: `c-dfa/tools/dfa2c_array`

Input: DFA binary
Output: `c-dfa/tools/readonlybox_dfa.c` (C array)

```c
static const uint8_t dfa_data[] = {
    0x44, 0x46, 0x41, 0x03,  // Magic + version
    // ... binary DFA data
};
```

### Step 5: Runtime Evaluation

Location: `c-dfa/src/dfa_eval.c`

Process:
1. Load DFA from binary/C array
2. For each input character:
   - Find current state transitions
   - Move to next state
3. At EOS (end of string):
   - Check if accepting
   - Return category mask
   - Extract captures if any

## Key Concepts

### State Sharing

Patterns that share structure share NFA states:

```
Pattern A: git status
Pattern B: git log
```

Both share `git ` prefix states.

### Acceptance Categories

Each pattern has a category. Multiple patterns can share states but have different accepting categories.

```bash
[safe:readonly:git] git status       # cat=0x01
[caution:network:git] git push        # cat=0x02
```

Same `git ` prefix states, different accepting states.

### Category Bitmask

| Bit | Category | Value |
|-----|----------|-------|
| 0 | safe | 0x01 |
| 1 | caution | 0x02 |
| 2 | modifying | 0x04 |
| 3 | dangerous | 0x08 |
| 4 | network | 0x10 |
| 5 | admin | 0x20 |
| 6 | build | 0x40 |
| 7 | container | 0x80 |

### Fragment Expansion

Fragments expand inline during NFA generation:

```bash
[fragment:git::digit] [0-9]

Pattern: git log -n ((git::digit))+

Expands to: git log -n [0-9]+
```

### Quantifier Implementation

#### Plus (+)

```
a((b))+  →  a b (b)*
          START → a → b → b* → ACCEPT
```

#### Star (*)

```
a((b))*  →  a (b)*
          START → a → b* → ACCEPT
```

#### Question Mark (?)

```
git((B))?  →  git (git)?
           START → git → (git)? → ACCEPT
```

## File Formats

### NFA File Format

```
# Comment
NUM_STATES: <count>
START_STATE: <num>
ACCEPTING_STATE: <num> category=0xXX

# Transitions
STATE <num>:
  'a' → <next_state>
  'b' → <next_state>
  EPSILON → <next_state>
```

### DFA Binary Format

```
+---+---+---+---+---+---+---+
| D | F | A | version | ... |
+---+---+---+---+---+---+---+
| state_count | symbol_count |
+---+---+---+---+---+---+---+
| states array (variable)      |
+---+---+---+---+---+---+---+
| symbols array               |
+---+---+---+---+---+---+---+
| transitions (4 bytes each)  |
+---+---+---+---+---+---+---+
```

## Critical Implementation Details

### State Sharing Prevents Interference

**Problem:** If patterns share too much, wrong acceptance category matches.

**Solution:** Category isolation in acceptance state assignment.

```c
// patterns:
[safe] a((b))+        # category 0x01
[caution] abc((b))+   # category 0x02

// Same 'a' prefix state, but different accepting states
// State machine branches before accepting
```

### Fragment Naming Prevents Conflicts

```bash
# Good - different namespaces
[fragment:quant1::b] b
[fragment:quant2::b] b

# Reference:
((quant1::b))+   # Uses quant1 namespace
((quant2::b))+  # Uses quant2 namespace
```

### Quantifier Bug: Single-Char Fragments

**Issue:** Exit transition logic could incorrectly add transitions.

**Fix:** Check `loop_state != accepting_state` before adding exit:

```c
if (pending_loop_accepting != -1 &&
    pending_loop_state != pending_loop_accepting) {
    nfa_add_transition(pending_loop_state,
                        pending_loop_accepting,
                        char_sid);
}
```

### EOS Target Logic

At end-of-string, find accepting state reachable via EPSILON transitions.

## Alphabet Construction

**IMPORTANT:** No external alphabet files are needed. The nfa_builder automatically constructs the alphabet from pattern files:

- Parses all characters used in patterns
- Assigns symbol IDs automatically
- Handles special symbols (space, tab, EOS, captures)
- Generates consistent symbol table for DFA construction

Format (internal, not stored in files):
```
0 0 0           # ANY (wildcard)
1 1 1           # EPSILON (non-consuming)
2 5 5           # EOS (End of String)
3 32 32         # space
4 9 9           # tab
...
```

## When to Use Me

Use this skill when:
- Understanding pattern matching behavior
- Debugging category interference
- Modifying NFA builder
- Optimizing DFA size
- Adding new regex features
- Understanding state machine behavior

## Performance Considerations

### Efficient Patterns

- Simple literals: `git status`
- Fixed arguments: `git log --oneline`
- Named fragments: `((FILENAME))`

### Expensive Patterns

- Multi-char fragments: `((LONG_PATTERN))+`
- Nested alternations: `(git|svn|hg) (status|log|diff)`
- Wide character classes: `[a-zA-Z0-9_.-]+`

## Debugging Tips

### Check State Count

```bash
cat build/readonlybox.nfa | grep "NUM_STATES"
```

### Check DFA States

```bash
dfa_test 2>&1 | grep "State.*FINAL"
```

### Verbose NFA Building

```bash
NFA_BUILDER_VERBOSE=1 make dfa
```

### Verbose DFA Conversion

```bash
NFA2DFA_VERBOSE=1 make dfa
```
