# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ReadOnlyBox** is a ptrace-based command interceptor that sends commands to rbox-server for user decisions. The rbox-server TUI presents each command, and the user allows or denies execution with various time-limited permissions.

### Components

- **rbox-ptrace**: ptrace-based command interceptor
- **rbox-server**: Go server with TUI for user decisions
- **c-dfa**: DFA for fast command validation
- **shellsplit**: Shell command tokenizer
- **rbox-protocol**: Binary protocol for client-server communication

### Build System

This project uses **Mage** for Go build orchestration.

```bash
# Build all tools
mage build

# Clean artifacts
mage clean

# Run tests
mage test

# Install to /usr/local/bin
mage install
```

### Architecture

```
User Command → rbox-ptrace → DFA Validation → rbox-server TUI → User Decision
                                      ↓
                              (Fast path for safe commands)
```

## General Coding Principles

### Single Source of Truth

**When implementing any feature, there must be ONE canonical implementation - not multiple implementations of the same logic.**

### Buffer Capacity - MANDATORY for All Write Functions

**Every function that writes to a buffer MUST take a capacity/size parameter and MUST NOT write beyond it.**

### Protocol Field Placement

When working with protocols or data formats:
- The protocol defines WHERE fields go (header vs body, offset X vs offset Y)
- This placement is FIXED - do not create alternative encoders that put same data in different places
- All code must use canonical encoding functions

### Testing

- Tests should validate the canonical functions, not reimplement logic
- Tests use the same functions the production code uses

## C-DFA Subproject

The `c-dfa/` subproject is a high-performance C implementation of a Deterministic Finite Automata (DFA) for fast validation of read-only commands.

### Build Commands

```bash
cd c-dfa && make
cd c-dfa && make test
cd c-dfa && make clean
```

### Key Components

| Component | Purpose |
|-----------|---------|
| `tools/cdfatool` | Unified CLI for all DFA operations |
| `src/dfa_eval.c` | Core DFA evaluation engine |
| `src/dfa_test.c` | Comprehensive test runner |

## Shellsplit Subproject

The `shellsplit/` subproject provides shell command tokenization and environment variable screening.

### Key Files

- `include/shell_tokenizer.h` - Fast zero-copy parser
- `include/env_screener.h` - Environment variable screening for secrets
- `tools/env_screener_demo.c` - Demo tool for env screening


