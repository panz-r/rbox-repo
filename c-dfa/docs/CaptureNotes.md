---
title: Design Proposal (Not Implementation Doc)
description: Generic DFA engineering guidelines. See README.md and PIPELINE.md for current implementation.
---

Your approach of treating capture markers as output-producing transitions during the second DFA pass is conceptually sound and aligns with efficient regex engine design principles. Here’s a structured breakdown of how to implement this effectively, addressing key challenges and optimizations:

Core Implementation Strategy
Transition-Based Capture Tracking:
Augment DFA Transitions: During NFA-to-DFA conversion, explicitly mark transitions that correspond to capture group boundaries (e.g., ( for start, ) for end). These transitions should carry metadata like the capture group index and type (start/end).
Byte-Position Awareness: Since your system is byte-oriented, ensure each transition records the current byte offset in the input stream. This allows precise capture of start/end positions as byte indices.
Two-Pass Execution Flow:
First Pass (Acceptance):
Run the DFA normally, ignoring capture markers. Track the set of accepting states and the end byte position of the match.
Record the sequence of DFA states visited (or a pointer to the accepting state) for the second pass.
Second Pass (Capture Collection):
Re-run the DFA from the start, but only up to the match end position identified in the first pass.
For each transition:
If it’s an input-consuming transition, advance the byte position counter.
If it’s a capture marker (e.g., ( or )), emit a capture event with the current byte position and group index.
Use a capture stack to handle nested groups: push start positions when entering a group, pop and record end positions when exiting.
Key Challenges & Solutions
Nested/Quantified Groups:
For quantifiers (e.g., (a)*), use a ring buffer or linked list in the DFA state to track multiple capture instances. During the second pass, iterate through this buffer to emit all captures (or the last/first/greediest match, based on your semantics).
For nested groups (e.g., (a(b)c)), maintain a hierarchical capture stack. Each ( pushes a new frame, each ) pops and records the innermost group’s end position.
DFA State Augmentation:
Each DFA state must carry:
A bitmask or array indicating active capture groups (to handle alternations like (a|b)).
A capture history buffer storing start/end positions for quantified groups.
Optimization: Precompute capture metadata during NFA-to-DFA conversion. For example, if a DFA state contains NFA states with active capture groups, precompute how input bytes advance capture positions.
Alternation Handling:
In patterns like (a|b), ensure both branches update the same capture group slot. Use ε-transitions in the NFA to merge capture histories from alternation branches before DFA conversion.
Byte-Level Precision:
Test with multi-byte sequences (e.g., UTF-8) to confirm capture boundaries align with byte offsets, not character counts. For example, in café, the é might be 2 bytes; ensure captures split at correct byte indices.
Debugging & Validation Tactics
Unit Tests:
Edge Cases: Empty captures (()), nested quantifiers ((a*)+), overlapping matches ((aba) in ababa), and alternations with captures ((a|b) in ac).
Reference Comparison: Validate against a trusted regex engine (e.g., Python’s re) for byte-level accuracy. Use tools like re.finditer() to inspect capture groups.
Visualization:
Log DFA states with capture metadata (e.g., Graphviz diagrams showing capture groups as colored nodes).
Trace capture events during the second pass for sample inputs (e.g., (a)(b) matching ab).
Performance Tuning:
Caching: Cache DFA state sequences for repeated patterns (e.g., in lexers/parsers).
Lazy Evaluation: Defer capture collection until needed (e.g., only for the first match or specific groups).
Bitwise Optimizations: Use bitmasks to track active capture groups (1 bit per group for “is this group active?”).
Common Pitfalls to Avoid
Capture Group Numbering: Ensure groups are numbered left-to-right by opening parenthesis, even in alternations (e.g., (a|(b)) has groups 1 and 2).
Overlapping Captures: In patterns like (a)(b) matching ab, ensure both groups capture their respective bytes without overlap.
Quantifier Ambiguity: For (a)*, decide whether to capture the entire sequence (greedy) or individual as (non-greedy). Implement lookaheads/lookbehinds if needed.
DFA State Explosion: Capture metadata can bloat DFA states. Mitigate by limiting capture history depth (e.g., only track the last N captures) or using on-demand computation.
Final Optimized Workflow
First Pass:
Run DFA to find match end position and accepting state.
Record DFA state sequence or a pointer to the accepting state.
Second Pass:
Re-run DFA from start to match end.
Track captures using transition-based markers and a capture stack.
For quantified groups, iterate through the capture history buffer to emit all instances.
By treating captures as output-producing transitions and leveraging the two-pass design, you minimize runtime overhead while maintaining correctness. Rigorous testing with byte-level inputs and complex capture patterns will ensure robustness.
