# Full Solution: Pattern Compilation to Binary DFA - All Stages Design

## Overview

This document outlines the complete design for the pattern compilation pipeline, from pattern parsing through NFA construction, NFA-to-DFA conversion, flattening to binary format, and final DFA evaluation. The design prioritizes correctness for EOS transitions, capture support, and efficient evaluation.

## Architecture Overview

The system has 5 stages:

```
Pattern File → NFA Builder → NFA-to-DFA → Flatten to Binary → DFA Evaluation
              (symbol NFA)   (symbol DFA)   (binary DFA)      (runtime)
```

### Key Design Principles

1. **Symbols vs Characters**: The NFA and intermediate DFA use symbols (character classes). The final binary DFA uses actual byte values and rule opcodes.

2. **EOS Transitions**: The special EOS symbol represents end-of-input. Patterns accept by having an EOS transition from an accepting state.

3. **Fragments Don't Accept**: Fragment and character class definitions do not accept strings. Only full patterns accept.

4. **First-Match Short-Circuit**: Binary DFA transitions are ordered by priority, evaluation stops at first match.

5. **Byte Offsets in Binary Format**: Binary DFA uses byte offsets (not indices) for memory-mapped direct access.

## Stage 1: Pattern Parsing (RDP - Recursive Descent Parser)

### Current State
- Basic RDP implementation in `nfa_builder.c`
- Supports literal characters, `*` quantifier, character classes

### Required Changes

#### 1.1 Subgraph Return Structure
Each RDP function returns a structured result:

```c
typedef struct {
    int entry_state;      // First state in the subpattern
    int exit_state;       // Last state in the subpattern  
    int accepting_state;  // The accepting state (may differ from exit_state)
    bool has_captures;    // Whether this subgraph contains capture markers
} nfa_subgraph_t;
```

#### 1.2 Instant Transition Handling
- Add `DFA_CHAR_INSTANT` (0xFF) as special symbol for non-consuming transitions
- Used during NFA building to link subgraph exit to next entry
- **Removed during NFA-to-DFA conversion** via epsilon closure

#### 1.3 Capture Syntax Support
Support `<name>...</name>` syntax:
- Capture begin: special transition marker
- Capture end: special transition marker
- Can be encoded as dedicated states or transition markers

#### 1.4 Character Escaping
Complete escaping support:
- `\` escapes: `*`, `+`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `|`, `\`, `.`, `^`, `$`
- `'` and `"` for literal string sections

## Stage 2: NFA Construction

### Current State
- NFA states with symbol-indexed transitions
- EOS target marking for accepting states
- Basic prefix sharing for state reuse

### Required Changes

#### 2.1 Enhanced State Structure

```c
typedef struct {
    uint8_t category_mask;      // Bitmask of accepting categories
    bool is_eos_target;         // This state accepts via EOS transition
    bool has_capture_start;     // Has capture begin marker
    bool has_capture_end;       // Has capture end marker
    int capture_id;             // Capture ID if applicable
    int transitions[MAX_SYMBOLS]; // Symbol-indexed transitions (-1 = none)
    int instant_transitions[8];   // Instant transition targets (non-consuming)
    char* tags[MAX_STATES];       // Debug tags
} nfa_state_t;
```

#### 2.2 EOS Transition Handling (CRITICAL)

The EOS symbol (Symbol 1, value 32 = space) marks end-of-pattern:

1. Each accepting state has `is_eos_target = true`
2. EOS transitions chain: accepting_state --EOS--> terminal_accepting
3. **Critical rule**: Only states with `is_eos_target == true` are accepting
4. States with EOS transitions TO accepting states are NOT accepting (can consume more input)

```c
// When building pattern "cat":
// State 0 --c(99)--> State 1
// State 1 --a-z(97-122)--> State 4
// State 4 --a-z(97-122)--> State 5
// State 5 --space(32)--> State 6
// State 6 --EOS(5)--> State 8 (is_eos_target=true, category_mask=0x01)
```

#### 2.3 State Reuse (Prefix Sharing)
- Use exact character symbols (not ranges) for first character
- Check for equivalent states before creating new ones
- Equivalence: same transitions on same symbols, same capture markers

#### 2.4 Instant Transition Chain
```c
// For pattern "a+":
// State 0 --a--> State 1
// State 1 --instant--> State 2 (landing pad)
// State 2 --a--> State 1  (loop back)
// State 1 --instant--> State 3 (exit)
// State 3 --EOS--> State 4 (accepting)
```

## Stage 3: NFA to Symbol-DFA Conversion

### Current State
- Subset construction algorithm
- Epsilon closure computation
- Alphabet symbol-based transitions

### Required Changes

#### 3.1 Epsilon Closure with Instant Transitions

```c
void epsilon_closure(int* states, int* count, int max_states) {
    // Process all states in the set
    for (int i = 0; i < *count; i++) {
        int state = states[i];
        
        // Follow instant transitions (non-consuming)
        for (int j = 0; j < 8 && nfa[state].instant_transitions[j] != -1; j++) {
            int target = nfa[state].instant_transitions[j];
            // Add target to closure if not already present
            // Continue following instant transitions from target
        }
    }
    // NOTE: Do NOT follow EOS transitions here
    // NOTE: Do NOT follow ANY transitions here (handled in nfa_move)
}
```

#### 3.2 EOS Target Detection (CRITICAL BUG FIX)

**WRONG** (current bug - marks all states as accepting):
```c
// Computes accepting mask by OR-ing ALL NFA state category_masks
for (int i = 0; i < move_count; i++) {
    move_accepting_mask |= nfa[move_states[i]].category_mask;
}
```

**CORRECT** (only EOS target states are accepting):
```c
for (int i = 0; i < move_count; i++) {
    if (nfa[move_states[i]].is_eos_target) {
        move_accepting_mask |= nfa[move_states[i]].category_mask;
    }
}
```

#### 3.3 Symbol-Based Transition Resolution

For each symbol in alphabet:
1. Compute move closure (follow symbol transitions)
2. If move_count > 0, compute epsilon closure of move result
3. This handles instant transition chains correctly

#### 3.4 Capture State Propagation
- If any NFA state in DFA state set has capture marker, record it
- Capture markers on states handled during DFA evaluation

## Stage 4: DFA to Binary Flattened DFA Conversion

### Current State
- Symbol-based transitions flattened to character-based
- State indices converted to byte offsets
- Compact binary format

### Required Changes

#### 4.1 Binary Format Enhancement

```c
// Header (24 bytes, no padding)
typedef struct __attribute__((packed)) {
    uint32_t magic;           // 0xDFA1DFA1
    uint16_t version;         // 4 for capture-support
    uint16_t state_count;     // Number of DFA states
    uint32_t initial_state;   // Byte offset to initial state
    uint32_t accepting_mask;  // Bitmask of accepting states
    uint16_t flags;           // DFA flags
    uint16_t reserved;
} dfa_t;

// State (16 bytes, no padding)
typedef struct __attribute__((packed)) {
    uint32_t transitions_offset;  // Byte offset to transition table
    uint16_t transition_count;    // Number of transitions
    uint16_t flags;               // State flags | category mask (bits 8-15)
    uint32_t eos_target;          // Byte offset to EOS accepting state (0 = none)
    uint32_t capture_start;       // Capture ID if this state starts capture (0 = none)
    uint32_t capture_end;         // Capture ID if this state ends capture (0 = none)
} dfa_state_t;

// Transition (5 bytes, no padding)
typedef struct __attribute__((packed)) {
    char character;              // 0=end, 1=EOS, 2-255=literal, 0xF0=capture_start, 0xF1=capture_end, 0xFF=ANY
    uint32_t next_state_offset;  // Byte offset to next state
} dfa_transition_t;
```

#### 4.2 Transition Priority Ordering (First-Match)

Order for correct short-circuit evaluation:
1. Capture start markers (0xF0)
2. Capture end markers (0xF1)  
3. Exact character matches (sorted by character value)
4. Character class rules (negation, ranges)
5. ANY wildcard (0xFF)
6. EOS marker (0x01) - only at end of input

#### 4.3 EOS Target Encoding
- Store `eos_target` as byte offset to accepting state
- EOS transition only matches when input fully consumed
- DFA evaluation checks EOS target at end of input

#### 4.4 Capture Marker Encoding
- Capture start: Character 0xF0 followed by capture ID transition
- Capture end: Character 0xF1 followed by capture ID transition
- Non-consuming transitions like EOS

#### 4.5 Transition Table Layout
```
[State 0 transitions...]
[State 1 transitions...]
...
[State N transitions...]
```

Each state has:
- N transitions (transition_count)
- End marker: character=0, next_state_offset=0

## Stage 5: Binary DFA Evaluation

### Current State
- Basic state machine evaluation
- Transition lookup by character
- EOS target handling at end of input

### Required Changes

#### 5.1 Evaluation State

```c
typedef struct {
    int category;              // Derived category from category_mask
    uint8_t category_mask;     // 8-bit category mask
    bool matched;              // Full pattern match
    size_t matched_length;     // Characters matched
    int capture_stack[16];     // Stack of active capture IDs
    int capture_count;         // Number of active captures
    dfa_capture_t captures[16]; // Completed captures
} dfa_result_t;
```

#### 5.2 State Offset Computation

States accessed via byte offsets from DFA base:

```c
#define STATE_OFFSET(idx) (sizeof(dfa_t) + ((size_t)(idx) * sizeof(dfa_state_t)))

const dfa_state_t* get_state(uint32_t offset) {
    return (const dfa_state_t*)((const char*)current_dfa + offset);
}
```

#### 5.3 Transition Evaluation Loop

```c
for (pos = 0; pos < length; pos++) {
    unsigned char c = input[pos];
    const dfa_state_t* state = get_state(current_state_offset);
    
    // Get transitions
    const dfa_transition_t* trans = get_transitions(state);
    
    // Find matching transition (first-match order)
    for (int i = 0; i < state->transition_count; i++) {
        if (trans[i].character == DFA_CHAR_EOS) continue;
        
        if (trans[i].character == DFA_CHAR_ANY || 
            trans[i].character == c) {
            // Process special markers
            if (trans[i].character == DFA_CHAR_CAPTURE_START) {
                // Push capture ID from next transition
            }
            if (trans[i].character == DFA_CHAR_CAPTURE_END) {
                // Pop capture ID, record capture
            }
            current_state_offset = trans[i].next_state_offset;
            break;
        }
    }
    
    // No transition found - pattern doesn't match
    if (!transition_found) {
        result->matched = false;
        return;
    }
}

// EOS handling at end of input
const dfa_state_t* final_state = get_state(current_state_offset);
if (final_state->eos_target != 0) {
    const dfa_state_t* eos_state = get_state(final_state->eos_target);
    if (eos_state->flags & DFA_STATE_ACCEPTING) {
        result->matched = true;
        result->category_mask = DFA_GET_CATEGORY_MASK(eos_state->flags);
    }
}
```

#### 5.4 Capture Stack Management
- On capture start: push capture ID to stack
- On capture end: pop from stack, record positions
- At EOS: complete pending captures

## Debugging Guidelines

### NFA Construction
1. Verify exact character symbols for first character
2. Check `is_eos_target` flag on accepting states
3. Verify instant transition chains for quantifiers

### NFA-to-DFA Conversion
1. Trace epsilon closure computation
2. Verify only EOS target states are marked accepting
3. Check transition resolution for each symbol

### Binary DFA Writing
1. Verify initial_state is correct byte offset
2. Check transition offsets point to correct locations
3. Validate transition count matches actual transitions

### DFA Evaluation
1. Trace state transitions character by character
2. Verify EOS handling at end of input
3. Check capture stack management

## Testing Strategy

### Unit Tests
1. Simple literal patterns ("cat", "git")
2. Quantifier patterns ("cat *", "git log +")
3. Character classes ("[a-z]", "[0-9]")
4. EOS matching ("cat" matches "cat", not "catx")
5. Capture patterns ("cat <file>")
6. Edge cases (empty input, partial matches)

### Integration Tests
1. Pattern → NFA → DFA → Binary → Evaluate
2. Large pattern sets (100+ patterns)
3. Performance benchmarks
4. Memory mapping verification

### Security Tests
1. Ensure unsafe commands don't match
2. Verify boundary conditions
3. Test with malicious input patterns

## Summary of Changes

| Stage | File | Change |
|-------|------|--------|
| 1 (Parse) | nfa_builder.c | Add subgraph return structure, instant transitions, capture syntax |
| 2 (NFA) | nfa_builder.c | Enhanced state structure, EOS target marking, instant transitions |
| 3 (NFA→DFA) | nfa2dfa.c | Fix accepting mask computation, epsilon closure with instant transitions |
| 4 (Binary) | nfa2dfa.c | Enhanced binary format, byte offsets, capture markers |
| 5 (Eval) | dfa_eval.c | Byte offset computation, capture stack, EOS target handling |
