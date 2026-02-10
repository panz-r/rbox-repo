This is a comprehensive engineering guideline document designed to take your byte-oriented regex engine from a prototype to an industrial-strength system. It focuses on correctness, performance, memory safety, and maintainability.

Engineering Guideline: Industrial-Strength Byte-Oriented Regex Engine
Version: 1.0
Target: Production-Grade Reliability & Performance
Architecture: Two-Pass DFA with Capture Group Support

1. Core Architecture Principles
1.1. The "Hybrid Tagged" Execution Model
While your current design uses a two-pass approach (Acceptance -> Capture Collection), an industrial-strength engine often optimizes this into a "Tagged DFA" or a "Trace-Based" model to avoid re-scanning the input.

Current Approach: Pass 1 finds the end offset. Pass 2 re-runs the DFA to collect captures.
Optimization Goal: In Pass 1, store a "history" of capture events alongside the DFA state transitions.
Guideline:
Augment DFA states with a Capture History Buffer (CHB).
When a transition involving a capture group boundary ( or ) occurs, append a (group_id, position, type) tuple to the CHB of the target state.
Benefit: Allows single-pass matching for 90% of cases. Only fall back to second-pass if the CHB is too large (state explosion risk) or for complex backreferences.
1.2. Memory Layout & Allocation
Regex engines are allocation-heavy. Standard malloc per state/transition is unacceptable for high throughput.

Arena Allocation: Implement a linear arena allocator. All NFA/DFA states, transition tables, and capture stacks for a single match attempt must come from a pre-allocated block.
Object Pooling: Reuse DFA state objects across different regex patterns if they share structural similarity (rare but useful in lexers).
Guideline:
struct RegexEngine holds a MemoryArena.
compile_pattern() allocates from this arena.
match() creates a temporary "frame" arena that is reset after every match attempt.
2. NFA & DFA Construction Specifications
2.1. NFA Construction (Thompson's Algorithm Variant)
Byte-Oriented Transitions: Transitions are not characters, but byte values (0-255).
Epsilon-Closure Caching: Pre-compute epsilon closures for all NFA states during compilation, not during matching. Store them as bitmaps or sorted arrays.
Capture Instrumentation:
Treat ( as an epsilon-transition that pushes a StartMarker to a thread-local capture stack.
Treat ) as an epsilon-transition that pops the stack and records the EndMarker.
Critical: For quantified groups (...)*, the NFA must allow the capture stack to be "saved" and "restored" when looping.
2.2. DFA Conversion (Subset Construction)
Powerset Construction: Map NFA state sets to DFA states.
Capture Set Propagation:
If NFA State A has an active capture group, the resulting DFA State B inherits this "Capture Set."
Conflict Resolution: If a DFA state contains two NFA states where one has finished Group 1 and another hasn't started it, mark Group 1 as "Ambiguous" in the DFA state.
Minimization: Use Hopcroft’s algorithm. However, do not minimize states that have different Capture Sets. Capture accuracy > state count.
3. Capture Group Implementation Strategy
This is the most complex part of your system.

3.1. The "Output-Producing Transition" Concept
You identified that captures are essentially output-producing transitions. Here is the industrial implementation of that idea:

Transition Metadata: Each DFA transition edge stores a list of CaptureActions.
OP_CAPTURE_START(id)
OP_CAPTURE_END(id)
OP_NOP (No operation)
Second Pass Execution (The "Trace"):
Instead of re-running the DFA blindly, Pass 1 should record the Sequence of State IDs visited (or just the accepting state and a pointer to the path).
Pass 2 iterates over this "Trace" of State IDs.
For each state transition in the trace, check the Transition Metadata. If it contains a capture op, execute it immediately.
Nested/Quantified Handling:
Use a ring buffer for capture groups inside quantifiers (e.g., (a)+).
When exiting a quantifier loop, decide based on greediness which capture in the ring buffer to keep (usually the last one for greedy, first for lazy).
3.2. Capture Stack Optimization
Fixed-Size Stack: Since regex patterns are usually < 100 groups, use a fixed-size array (e.g., uint16_t captures[64][2]) on the stack for start/end offsets. Avoid heap allocation during matching.
Sentinel Values: Initialize captures with -1 (unmatched). This distinguishes between "group matched empty string" and "group did not participate."
4. Performance Optimization Roadmap
4.1. Transition Table Compression
A full 256-entry table per state wastes memory.

Sparse Arrays / Packed Vectors: If a state only transitions on a, b, and c, store a small array of (byte, next_state) pairs and use SIMD or binary search to look up.
Row Displacement: A classic technique to compress sparse tables into a dense 1D array with a displacement map.
Bitmap Lookups: For large character classes (e.g., \w), use a 256-bit (32-byte) bitmap. if (bitmap[byte >> 3] & (1 << (byte & 7))).
4.2. SIMD Acceleration (Vectorized Prefilter)
Before running the DFA, use SIMD (SSE/AVX/NEON) to rule out non-matches.

Strategy: Identify the "rarest byte" or a fixed string prefix in the pattern.
Implementation: Load 32/64 bytes of input into a vector register. Compare against the target byte. If no match found, skip ahead by 32/64 bytes.
Guideline: Implement a simd_scan_mask(input_ptr, mask) function that returns the offset of the first matching byte.
4.3. JIT Compilation (The "Next Level")
If the DFA is too slow due to pointer chasing:

Tiny JIT: Translate the DFA into native machine code (x86-64 or AArch64).
Logic: Each basic block represents a DFA state. cmp byte, 'a' -> je state_5.
Tooling: Use AsmJit or LLVM JIT. This often provides a 3-5x speedup over table-based DFAs.
5. Robustness & Testing Strategy
5.1. Differential Testing (Fuzzing)
Golden Master: Use a trusted library (PCRE2, RE2, or Python's re) as the oracle.
Fuzzer: Generate random byte sequences and random regex patterns.
Assertion: assert(my_engine.match(re, str) == pcre2.match(re, str)).
Tools: AFL++, Honggfuzz, or libFuzzer.
5.2. Edge Case Matrix
You must pass these tests to be considered "reliable":

Empty Input: "" matching a* or ^.
Unmatched Groups: (a)b matching "b" (Group 1 should be unset).
Nested Quantifiers: ((a*)*)* matching "aaa".
Overlapping Matches: aba matching "ababa" (find all overlaps).
Greedy vs Lazy: (a+)(a+) matching "aaaa" (Greedy takes 3+1, Lazy takes 1+3).
UTF-8 Boundaries: Ensure captures don't split multi-byte characters (e.g., capture é which is 0xC3 0xA9).
5.3. Sanitizers
Compile with -fsanitize=address,undefined during development.
Ensure no out-of-bounds reads/writes on the input buffer.
6. Debugging & Observability
6.1. Automaton Visualization
Implement a dot_export() function that outputs Graphviz DOT format.
Feature: Highlight the current state in red during a trace. Annotate edges with capture actions.
6.2. Performance Counters
Expose stats to the user:

states_visited
transitions_taken
capture_stack_pushes
simd_scans_performed
match_time_ns
7. Implementation Checklist (Phased)
Phase 1: Correctness
NFA construction supports all byte values (0-255).
Epsilon closures are pre-computed.
DFA conversion handles capture groups correctly.
Two-pass evaluation implemented.
Unit tests pass against PCRE2 for basic patterns.
Phase 2: Performance
Implement Arena Allocator.
Compress DFA transition tables (Sparse/Bitmap).
Add SIMD pre-filter for fixed strings/chars.
Optimize capture stack to use fixed array.
Phase 3: Robustness
Fuzz testing (1M+ iterations).
Differential testing against 2 other engines.
UTF-8 boundary validation.
Sanitizer clean run.
Phase 4: Advanced
JIT compilation (optional, for hot paths).
Streaming/incremental matching API.
Support for backreferences (fallback to NFA).
8. Code Snippet: The "Tagged Transition" Struct
Here is how you should structure your core DFA data to support the "output-producing" idea efficiently:

c
// Maximum number of capture groups supported
#define MAX_GROUPS 32

// Action types for capture boundaries
typedef enum {
    ACTION_NONE,
    ACTION_START_CAPTURE, // Push start position
    ACTION_END_CAPTURE     // Pop and record end position
} CaptureActionType;

// A single action attached to a transition
typedef struct {
    CaptureActionType type;
    uint8_t group_id; // Which group (1-32)
} CaptureAction;

// A DFA Transition
typedef struct {
    uint8_t input_byte; // The byte that triggers this (if non-epsilon)
    uint32_t next_state_id;
    uint8_t action_count;
    CaptureAction* actions; // Pointer to list of actions (can be null)
} DFATransition;

// A DFA State
typedef struct {
    uint32_t id;
    DFATransition* transitions; // Sorted or hashed by input_byte
    bool is_accepting;
} DFAState;
Guideline: When building the DFA, if a transition crosses a ( or ), allocate a small CaptureAction array and attach it to that specific edge. During the second pass, you simply iterate the trace and execute these actions without needing complex NFA backtracking logic.
