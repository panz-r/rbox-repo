---
title: Design Proposal (Not Implementation Doc)
description: Generic DFA engineering guidelines. See README.md and PIPELINE.md for current implementation.
---

This is a fantastic architectural insight. If your priority is throughput for non-capturing matches (or just finding if a match exists), while treating captures as a secondary "premium" feature, you should adopt a Tiered Execution Model.

This model is used by high-performance engines like Hyperscan and RE2. The core idea is that Pass 1 (Acceptance) should be as lean as possible, stripping away all the overhead of capture bookkeeping.

Here is the guideline for implementing the "Fast Lane" (Non-Capturing) vs. "Toll Road" (Capturing) architecture:

1. The "Fast Lane" Design (Pass 1 Optimization)
In this mode, you are only asking: "Does this string match the pattern?" You do not care about $1, $2, etc.

A. The "Lean" DFA
Create a stripped-down version of your DFA specifically for Pass 1.

No Mealy Outputs: Strip all CaptureAction metadata from the transitions.
No Backtracking State: If you use an NFA for complex parts (like backrefs), disable them in the fast path. If the "Fast Lane" NFA/DFA fails, then you can fall back to the full engine.
Bitmap Acceptance: Instead of a list of accepting states, use a single bitmap (or a Bloom filter) for the final state check.
is_accepting = AcceptBitmap[state_id] (O(1) lookup).
B. SIMD & Prefilters (The "Bouncer")
Before even entering the DFA loop, use SIMD to reject 90% of the input.

Literal Prefix Check: If your pattern starts with abc, use AVX to check 32 bytes at once for a, b, or c.
Character Class Check: If the next expected byte is [a-z], use a 256-bit lookup table (LUT) to check if the input byte is in range in a single cycle.
C. The "Fail-Fast" Loop
Your hot loop should look like this (pseudo-C):

c
// FAST PASS: No captures, just state transitions
while (ptr < end) {
    uint8_t byte = *ptr;
    
    // Direct array lookup (cache-friendly)
    // If using sparse table, use binary search or perfect hash here
    state = dfa_lean_transition[state][byte]; 
    
    if (state == DEAD_STATE) return NO_MATCH;
    
    ptr++;
}

// Single check at the end
if (AcceptBitmap[state]) {
    return MATCH_FOUND; 
}
2. The "Toll Road" Design (Pass 2 / On-Demand)
You only enter this phase if:

The user explicitly requested capture groups (e.g., regexec with nmatch > 0).
Pass 1 found a match, and you need to extract the substrings.
A. Lazy Trace Replay
Since you already have the "Accepting State" from Pass 1, you don't need to re-run the entire DFA blindly.

Store the Trace: During Pass 1, if you detect a match is likely (or just store the last N states), record the sequence of (StateID, InputByte) pairs in a small circular buffer.
Replay with Context: In Pass 2, iterate over this trace. Because you have the exact sequence of bytes and states, you can now execute the Mealy Actions attached to those specific transitions.
B. The "Mealy" Overhead is now Acceptable
Since Pass 2 only runs after a match is confirmed, the cost of pushing/popping the capture stack is amortized over the success case.

Optimization: If the pattern has no capture groups ((?:...)), the compiler should generate a version of Pass 2 that is identical to Pass 1 (zero overhead).
3. Implementation Strategy: The "Two-Engine" Approach
To maximize speed, don't use one engine for both. Compile two versions of the pattern:

Feature	Engine A (The Scout)	Engine B (The Scribe)
Purpose	Find match location / Validate	Extract capture groups
DFA Type	Minimal, Bitmap-based	Mealy-augmented, Action-heavy
Memory	L1 Cache friendly	L3/RAM (larger state size)
Transition Table	NextState[256] (dense)	Transition {Next, Actions} (sparse/rich)
Cost	~1-2 cycles per byte	~5-10 cycles per byte
When to use	match(), search(), validation	findall(), split(), replace
Workflow:

User calls match(pattern, text).
System selects Engine A.
Runs Pass 1 (Fast Lane).
Returns True immediately if match found. Stop. (Captures are ignored).
Only if user calls match(pattern, text, &captures):
Run Engine A to find match end offset.
Switch to Engine B.
Run Pass 2 (Trace Replay + Mealy Actions) from start to end offset.
Populate captures array.
4. Specific "Fast Match" Optimizations
Since you are byte-oriented, here are specific low-level hacks for the Fast Lane:

Row Displacement (Goto-Based DFA):
Instead of next = table[state][byte], compile the DFA into a giant switch statement or a computed goto table where the state ID is the index.
c
// Ultra-fast state transition
void* jump_table[] = { &&state_0, &&state_1, ... };
goto *jump_table[state];

state_5:
    if (*ptr == 'a') state = 6; else state = 0;
    goto *jump_table[state];
This removes the 2D array lookup overhead and relies on the CPU's branch predictor.

Calculated State IDs:
If your DFA is huge, don't use an array of pointers (bad for cache). Use a single large array of integers where State N starts at Index N * 256.
next = base_table[state_id * 256 + input_byte];
This is contiguous memory and prefetcher-friendly.
The "Anchored" Fast Path:
If the pattern starts with ^ or a literal string, hardcode the first 4 bytes into the loop to unroll it.
Summary of the Guideline Update
Add this section to your document:

4. Tiered Execution Model (Fast Lane vs. Toll Road)

To achieve industrial-state throughput, the engine must distinguish between Validation (Does it match?) and Extraction (What are the groups?).

Tier 1 (The Scout): A minimal DFA/NFA stripped of all capture metadata.
Goal: Minimize cycles-per-byte.
Optimizations: SIMD prefilters, bitmap accept states, calculated goto transitions.
Output: Boolean (Match/No-Match) + End Offset.
Tier 2 (The Scribe): The full Mealy-machine DFA.
Goal: Accurate capture extraction.
Trigger: Only invoked if Tier 1 succeeds AND the user requested captures.
Mechanism: Trace-replay of the accepting path executing CaptureAction side-effects.
API Implication:
bool regex_match(pattern, text) -> Uses Tier 1 only.
bool regex_search(pattern, text, captures*) -> Uses Tier 1 to find offset, then Tier 2 to fill captures.

This approach gives you the best of both worlds: C-level speed for simple validation, and correct, robust capture extraction when needed.
