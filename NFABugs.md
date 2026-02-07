# NFA Construction Bug Report

## Overview

The NFA builder (`c-dfa/tools/nfa_builder.c`) has critical bugs that cause incorrect NFA construction, resulting in orphaned states and missing accepting states. These bugs cause many valid patterns to not be recognized by the DFA-based pattern matcher.

## Bugs Found

### Bug 1: Orphaned States - "cat" Pattern

**Severity**: Critical

**Description**: States 1-6, which should represent the "cat" pattern, are completely disconnected from the NFA start state (state 0).

**Expected Behavior**: When parsing `[safe:file:read] cat file.txt`, the NFA should create states:
- State 0 -> 'c' -> State 1
- State 1 -> 'a' -> State 2
- State 2 -> 't' -> State 3
- State 3 -> ' ' -> State 4
- State 4 -> 'f' -> State 5
- ...
- Final state should be accepting

**Actual Behavior**:
```
State 0:
  Accepting: no
  Transitions: 96
    'a' -> 424
    'c' -> 741      # 'c' goes to state 741, NOT state 1
    'd' -> 329
    ...

State 1:            # ORPHAN - not reachable from state 0
  Accepting: no
  Transitions: 2
    'a' -> 1
    't' -> 2

State 2:            # ORPHAN
  Accepting: no
  Transitions: 3
    0x04 -> 2
    'f' -> 3

State 6:            # ORPHAN - should be accepting
  Accepting: yes
  Tags: safe file read allow
```

**Impact**: The pattern "cat file.txt" is never matched because states 1-6 are unreachable from state 0.

**Root Cause**: The NFA builder appears to reset or use incorrect state numbering when starting new patterns. State 0's transition for 'c' goes to 741 (the start of a DIFFERENT "cat"-related pattern), while the intended states 1-6 are created but never connected.

### Bug 2: Non-Accepting States - Multiple Patterns

**Severity**: Critical

**Description**: Many patterns have NFA states that should be accepting but are marked as non-accepting.

**Affected Patterns**:

| Pattern | NFA State | Expected | Actual |
|---------|-----------|----------|--------|
| `head file.txt` | 338 | Accepting | Not Accepting |
| `tail file.txt` | 485 | Accepting | Not Accepting |
| `ps aux` | 801 | Accepting | Not Accepting |
| `pwd` | 326 | Accepting | Not Accepting |
| `whoami` | 326 | Accepting | Not Accepting |
| `wc -l file.txt` | 158 | Accepting | Not Accepting |

**Example - "head file.txt"**:
```
State 338:                    # Should be accepting
  Accepting: no               # BUG: Should be yes
  Transitions: 2
    'h' -> 326
    'e' -> 338
```

**Impact**: These patterns are never matched despite being in the input pattern file.

### Bug 3: State 0 Transitions Don't Lead to Accepting States

**Severity**: High

**Description**: State 0 has 96 transitions for different starting characters, but the target states don't always lead to accepting states.

**Analysis**:
```
State 0 transitions:
  'a' -> 424  (not accepting)
  'c' -> 741  (not accepting)
  'd' -> 329  (date is accepting, but not properly connected)
  'e' -> 684  (env should be accepting)
  'f' -> 781  (find should be accepting)
  'g' -> 825  (git should be accepting)
  'h' -> 338  (head should be accepting)
  'i' -> 342  (id IS accepting - working correctly)
  'j' -> 449  (join should be accepting)
  'l' -> 796  (ls should be accepting)
  'm' -> 45   (more should be accepting)
  'p' -> 801  (ps/pwd should be accepting)
  's' -> 406  (stat/sed/sort should be accepting)
  't' -> 485  (tail/tar should be accepting)
  'u' -> 388  (uptime/uname should be accepting)
  'w' -> 326  (wc/whoami should be accepting)
  'z' -> 506  (zipinfo should be accepting)
```

**Problem**: The NFA states that state 0 transitions to are often intermediate states that don't have the final accepting state flag set.

## Test Results

### Working Patterns (Correctly Built)
- `i` -> MATCH (state 342 is accepting)
- `id` -> MATCH
- `date` -> MATCH

### Broken Patterns (NFA Bugs)
- `cat file.txt` -> no match (orphaned states 1-6)
- `git diff HEAD` -> no match (state 825 not accepting)
- `ps aux` -> no match (state 801 not accepting)
- `ls -la` -> no match (state 796 not accepting)
- `head file.txt` -> no match (state 338 not accepting)
- `tail file.txt` -> no match (state 485 not accepting)
- `pwd` -> no match (state 326 not accepting)

## Evidence

### NFA File Analysis
```bash
# Count accepting states in NFA
grep "Accepting: yes" /home/panz/osrc/lms-test/readonlybox/c-dfa/readonlybox.nfa | wc -l
# Output: 96 (all patterns should have accepting states)

# Check if states are reachable
awk '/^State [0-9]+:$/{state=$2; gsub(/:/,"",state)} /-> [0-9]+/{gsub(/.*-> /,"",$0); if($0=="1") print "State " state " -> 1"}' /home/panz/osrc/lms-test/readonlybox/c-dfa/readonlybox.nfa
# Output: State 1 -> 1 (only self-loop, no incoming transitions from state 0)
```

### DFA Analysis
```bash
# Convert NFA to DFA and check accepting states
./nfa2dfa_advanced readonlybox.nfa readonlybox.dfa
# Output: Created DFA with 76 states (only 7 accepting)
# Expected: ~76 states with ~96 accepting (one per pattern)
```

## Root Cause Analysis

### Bug 1: Orphaned States
The NFA builder uses `nfa_add_state_with_minimization()` which may return an existing equivalent state instead of creating a new one. When processing the "cat" pattern:

1. Pattern parsing starts at state 0
2. 'c' transition should go to a new state
3. Instead, it goes to state 741 (from a previous pattern)
4. States 1-6 are created but never connected to state 0

### Bug 2: Non-Accepting States
The `parse_advanced_pattern()` function at line 470 sets:
```c
nfa[current_state].accepting = true;
```

However, if `nfa_add_state_with_minimization()` returns an equivalent state (line 484-490), the current_state variable is updated but the accepting flag may not be properly propagated.

### Bug 3: State 0 Transitions
The NFA builder appears to use a shared initial state (state 0) with transitions to pattern-specific start states. However, these transitions point to intermediate states rather than properly structured pattern automata.

## Recommended Fixes

### Fix 1: Fix Orphaned States
Ensure that when starting a new pattern, the builder properly connects the initial state to the pattern's first character state. The issue may be in the minimization logic that reuses states incorrectly.

### Fix 2: Fix Accepting State Propagation
When `find_equivalent_state()` returns an existing state, ensure that:
1. The accepting flag is correctly transferred
2. Tags are properly merged
3. The pattern doesn't lose its acceptance property

### Fix 3: Add NFA Validation
Add a validation pass after NFA construction that:
1. Verifies all states are reachable from state 0
2. Verifies all pattern final states are marked accepting
3. Reports orphaned states for debugging

Example validation code:
```c
void validate_nfa(void) {
    // BFS from state 0 to find all reachable states
    bool reachable[MAX_STATES] = {false};
    int queue[MAX_STATES];
    int q_start = 0, q_end = 0;
    
    reachable[0] = true;
    queue[q_end++] = 0;
    
    while (q_start < q_end) {
        int s = queue[q_start++];
        for (int c = 0; c < MAX_CHARS; c++) {
            int t = nfa[s].transitions[c];
            if (t >= 0 && !reachable[t]) {
                reachable[t] = true;
                queue[q_end++] = t;
            }
        }
    }
    
    // Report unreachable states
    for (int i = 0; i < nfa_state_count; i++) {
        if (!reachable[i]) {
            fprintf(stderr, "WARNING: NFA state %d is unreachable from start\n", i);
        }
    }
    
    // Verify accepting states are reachable
    for (int i = 0; i < nfa_state_count; i++) {
        if (nfa[i].accepting && !reachable[i]) {
            fprintf(stderr, "ERROR: Accepting state %d is unreachable!\n", i);
        }
    }
}
```

## Files Affected

- `c-dfa/tools/nfa_builder.c` - Main NFA builder (primary bug location)
- `c-dfa/tools/nfa_builder_minimized.c` - Alternative builder with same issues
- `c-dfa/tools/nfa_builder_no_min.c` - Non-minimizing version

## Testing

To verify the bugs, run:
```bash
cd /home/panz/osrc/lms-test/readonlybox

# Build the project
mage Build

# Test DFA evaluation
gcc -I. -o /tmp/test_dfa /tmp/test_dfa.c \
    internal/client/dfa.c bin/libreadonlybox_client.so -Wl,--no-as-needed
/tmp/test_dfa

# Expected output should show only "i", "id", "date" matching
# All other safe patterns should match but currently don't
```

## Conclusion

The NFA builder has fundamental bugs in state management, particularly around:
1. State reuse/minimization logic
2. Accepting state flag propagation
3. Pattern start state connection

These bugs prevent the DFA-based pattern matcher from recognizing most of the intended safe patterns. The DFA converter itself is working correctly - it only converts the reachable, accepting portion of the NFA as intended.
