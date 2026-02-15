# Quantifier Category Fix - Implementation Plan

## Overview

This document outlines the implementation plan to fix the quantifier category mixing bug in the NFA builder. The bug causes incorrect category propagation when multiple patterns with different categories share prefixes (e.g., `(a)+`, `(a)*`, `(a)?`).

## Root Cause

When processing input like "aa":
1. Each pattern creates separate NFA paths from state 0
2. After consuming 'a', different patterns are at different NFA states
3. Only SOME of those states can reach their respective fork states
4. This causes category loss in the DFA conversion

## 7 Core Constraints

### 1. Fork State Convergence Constraint
All NFA states reachable after consuming the same input MUST have EPSILON paths to ALL fork states for ALL patterns.

### 2. Fork State Visibility Constraint
Fork states must be globally visible from every state that represents "matched X where X could continue".

### 3. Self-Loop Handling Constraint
Self-loops (EPSILON from X to X) must be EXCLUDED from "has_outgoing" calculation.

### 4. Fragment Reference Anchor Constraint
Fragment references with quantifiers must produce identical NFA structure to parenthesized literals.

### 5. Category Mask Propagation Constraint
Category must be set on the FORK state itself, not delegated to the accepting state.

### 6. State 0 Isolation Constraint
The initial DFA state must NEVER include any accepting fork state.

### 7. Quantifier Type Semantic Constraint
Each quantifier (+, *, ?) requires different fork state topology.

---

## Implementation Phases

### Phase 1: Fork State Infrastructure Changes

#### 1.1 Add Global Fork State Registry

Add tracking for globally reusable fork states:

```c
typedef struct {
    int fork_state;           // The fork state ID
    uint8_t category_mask;    // Category for this fork
    int quantifier_type;       // '+', '*', or '?'
    int pattern_id;           // Which pattern this belongs to
    int exit_state;           // The exit state that reaches this fork
} fork_state_info_t;

static fork_state_info_t global_forks[MAX_STATES];
static int global_fork_count = 0;
```

#### 1.2 Modify Fork State Creation

Before creating a new fork state, check if an identical one exists:

```c
// Check for existing fork with same parameters
int existing_fork = find_global_fork(anchor_state, cat_mask, quant_type);
if (existing_fork >= 0) {
    // Reuse existing fork
    nfa_add_transition(end_state, global_forks[existing_fork].fork_state, epsilon_sid);
    return;
}
```

---

### Phase 2: Self-Loop Handling (Constraint 3)

Fix `has_outgoing` detection to exclude self-loops:

```c
// Check EPSILON transitions EXCLUDING self-loops
int eps_cnt = 0;
int* eps_targets = mta_get_target_array(&nfa[end_state].multi_targets, 257, &eps_cnt);
for (int i = 0; i < eps_cnt; i++) {
    if (eps_targets[i] != end_state) {  // Exclude self-loop
        has_outgoing = true;
        break;
    }
}
```

---

### Phase 3: Category Propagation Fix (Constraint 5)

Set category on the FORK state, not the accepting state:

```c
// On fork state creation:
nfa[eos_target_state].is_eos_target = true;
nfa[eos_target_state].category_mask = cat_mask;  // Fork gets category

// Accepting state gets pattern only, NOT category
int accepting = nfa_add_state_with_category(cat_mask);
nfa[accepting].is_eos_target = true;
nfa[accepting].pattern_id = current_pattern_index + 1;
// Note: NOT setting category_mask on accepting
```

---

### Phase 4: Quantifier-Specific Fork Topology (Constraint 7)

Track quantifier type and build appropriate topology:

```c
// Function signature changes to include quantifier type
int nfa_finalize_state(int end_state, uint8_t cat_mask, char quant_type);

// Build different fork structures:
// - '+': No skip path (requires 1+ matches)
// - '*': Skip path to accepting (allows 0 matches)
// - '?': Single match path only
```

---

### Phase 5: Global Fork Visibility (Constraint 2)

After all patterns built, connect prefix states to relevant forks:

```c
void connect_global_forks(void) {
    for (int state = 0; state < nfa_state_count; state++) {
        if (nfa[state].is_eos_target) continue;
        
        int eps_cnt = 0;
        int* eps_targets = mta_get_target_array(&nfa[state].multi_targets, 257, &eps_cnt);
        
        if (eps_cnt > 1) {  // Divergence point
            for (int f = 0; f < global_fork_count; f++) {
                if (!has_epsilon_to(state, global_forks[f].fork_state)) {
                    nfa_add_transition(state, global_forks[f].fork_state, VSYM_EPS);
                }
            }
        }
    }
}
```

---

### Phase 6: State 0 Isolation (Constraint 6)

In nfa2dfa.c, exclude fork states from initial DFA state:

```c
for (int i = 0; i < tc; i++) {
    int ns = temp[i];
    if (ns == 0) continue;
    
    // Exclude fork states from initial state
    if (nfa[ns].is_eos_target && nfa[ns].category_mask != 0) {
        continue;
    }
    // Process normally...
}
```

---

## Implementation Order

1. **Phase 2** - Self-Loop Fix (Lowest risk)
2. **Phase 3** - Category on Fork (Medium risk)
3. **Phase 4** - Quantifier Types (Medium risk)
4. **Phase 1** - Global Fork Registry (Higher complexity)
5. **Phase 5** - Global Fork Visibility (Highest complexity)
6. **Phase 6** - State 0 Isolation (Simple if Phases 1-5 done correctly)

---

## Testing Strategy

1. Isolated single-pattern tests
2. Multi-pattern with same prefix (e.g., `(a)+`, `(a)*`, `(a)?`)
3. Category propagation for `aa`, `aaa`
4. Fragment references with quantifiers
5. Empty matching for `*` and `?`

---

## Risk Assessment

- **Phase 5** (Global Fork Visibility): High risk - potential NFA state explosion
- **Phase 4** (Quantifier Types): Medium risk - changes fork topology
- **Phases 2, 3, 6**: Low risk - targeted fixes
