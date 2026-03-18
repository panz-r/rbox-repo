---
title: Design Proposal (Not Implementation Doc)
description: Generic DFA engineering guidelines. See README.md and PIPELINE.md for current implementation.
---

Yes, absolutely. You have hit the nail on the head.

Formally, a Mealy Machine is a finite-state automaton where the output values are determined both by the current state and the current input (the transition). This is distinct from a Moore Machine, where output depends only on the current state.

Your insight—that capture markers are "output-producing transitions"—is the exact definition of a Mealy machine applied to regex.

Here is why this formalism is critical for your industrial-strength design, and how to apply it practically:

1. Why Mealy, not Moore?
In a standard DFA (Moore machine) for regex:

Input: Character
State: Configuration of the automaton
Output: "Accept" or "Reject" (determined only when you land in the final state).
This works for matching, but fails for capturing because:

Capture groups ((...)) are boundaries. The "output" (the capture start/end offset) happens during the transition, not when you arrive at a state.
If you wait for the state to output the capture, you lose the precise byte position where the ( or ) was encountered.
Your Mealy Approach:

Transition: State_A --[Byte='(' + Action: Push Capture 1]--> State_B
Output: The action (recording the byte offset) happens immediately as the transition is taken.
2. The "Tagged DFA" (Mealy Implementation)
In industrial regex literature (like in RE2 or Hyperscan), this is often called a Tagged DFA or a Transducer.

You don't need to build a pure academic Mealy machine. Instead, you augment your DFA transition table to carry a "side effect" list.

Data Structure Representation
Instead of a transition table being just NextState, it becomes:

c
typedef struct {
    uint32_t next_state;
    uint8_t  byte_consumed; // The byte that triggers this (0 for epsilon/captures)
    
    // MEALY OUTPUT SECTION
    uint8_t  num_actions;
    Action   actions[MAX_ACTIONS_PER_TRANSITION]; 
} MealyTransition;
The Action Union
The "Output" of the Mealy machine is a discriminated union of side effects:

c
typedef enum {
    ACTION_NONE,
    ACTION_CAPTURE_START,  // Arg: group_id
    ACTION_CAPTURE_END,    // Arg: group_id
    ACTION_RECORD_POS,     // Arg: slot_id (for lookarounds/tags)
    ACTION_FAIL            // Cut transition (for backrefs/lookaheads)
} ActionType;

typedef struct {
    ActionType type;
    uint32_t   arg; // Group ID or Position
} Action;
3. How this Solves Your Two-Pass Problem
Your current plan is:

Pass 1: Run DFA (Moore style) to find match end.
Pass 2: Re-run to collect captures.
The Mealy Optimization (Single Pass):
If you treat the DFA as a Mealy machine, you can technically do it in one pass. However, because capture history (especially for quantifiers like (a)*) requires remembering past states, a pure Mealy machine isn't enough—you need Memory.

This leads to a Pushdown Automaton (PDA) or a DFA with Register Context:

The State: (DFA_State_ID, Capture_Stack_Snapshot)
Problem: This causes state explosion. You can't have infinite stack depth in a DFA table.
The Solution (Your Two-Pass is actually smarter for now):
Pass 1 (Moore): Run the DFA ignoring Mealy outputs. Just track Current_State. When you hit an accepting state, save the Input_Position.
Pass 2 (Mealy Trace): Re-run the DFA from the start. This time, execute the Actions attached to the transitions.
When you hit ACTION_CAPTURE_START, push the current input position to a user-provided stack.
When you hit ACTION_CAPTURE_END, pop and record.
4. Advanced: The "Tagged NFA" (RE2 Style)
If you want to avoid the second pass entirely (for performance), you adopt the Tagged NFA approach used by Google's RE2 (which is industrial state-of-the-art).

Concept: Instead of a Mealy output on the transition, you attach a "Tag" (an integer ID) to the NFA state.
Propagation: When converting NFA to DFA (Subset Construction), you don't just merge states; you merge the set of active tags.
Evaluation: As you run the DFA, you maintain a simple array Tag_Positions[MAX_TAGS].
When you enter a DFA state with Tag_5 active, you write the current byte offset to Tag_Positions[5].
Benefit: No second pass. No re-scanning. O(1) capture recording.
Drawback: The DFA states are larger because they must track which tags are active.
Summary for Your Guideline Document
Add this section to your architecture document:

3.5 Formalism: Mealy Transducer Model
The capture mechanism shall be implemented as a Mealy Finite State Transducer.

Input Alphabet: Byte values (0-255) and Epsilon transitions.
Output Alphabet: Capture actions (Start_Group_N, End_Group_N).
Transition Function: δ(State, Input) -> (NextState, {Actions})
Implementation Strategy:

Compile-Time: During NFA-to-DFA conversion, annotate transitions crossing capture boundaries (( or )) with CaptureAction metadata.
Runtime (Pass 2): The evaluator acts as a Mealy interpreter. It maintains a CaptureStack (user-allocated array). For every transition taken, it iterates the Actions list and mutates the CaptureStack immediately.
Rationale: This decouples acceptance (State reachability) from side-effects (Capture recording), allowing for deterministic match latency and simplifying debugging.

You are on the exact right track. Thinking in terms of Transitions with Side Effects (Mealy) rather than just State Reachability (Moore) is the key differentiator between a toy regex engine and a production one.
