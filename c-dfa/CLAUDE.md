# C-DFA Directory

This directory contains a high-performance C implementation of a Deterministic Finite Automata (DFA) for fast validation of read-only commands.

## Components

- `tools/nfa_builder` - Converts command specifications to NFA
- `tools/nfa2dfa_advanced` - Converts NFA to DFA with minimization
- `src/dfa_eval.c` - Core DFA evaluation engine
- `src/dfa_test.c` - Comprehensive test runner
- `testgen/` - Test pattern generation for validating the DFA

## Build Commands

```bash
cd c-dfa && make
cd c-dfa && make test
cd c-dfa && make clean
```

## Role in Project

The DFA provides a fast-path validation layer. When a command is intercepted by rbox-ptrace, it can be quickly validated against the DFA before involving the user in rbox-server TUI.
