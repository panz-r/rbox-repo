# ARCHITECTURE Skill

**Scope:** rbox-ptrace and c-dfa subprojects

---
name: architecture
description: Understand ReadOnlyBox architecture - ptrace interception, DFA validation, client-server communication
license: MIT
compatibility: opencode
metadata:
  project: readonlybox
  scope: full-project
---

## What I do

Explain the architecture of ReadOnlyBox components and how they interact.

## Project Structure

```
readonlybox/
├── rbox-ptrace/           # ptrace-based command interceptor (C)
├── rbox-server/           # Go TUI server for user decisions
├── c-dfa/                 # DFA tools for pattern matching
├── shellsplit/            # Shell command tokenizer
├── rbox-protocol/         # Binary protocol library
└── bin/
    ├── readonlybox-server # Compiled TUI server
    └── readonlybox-ptrace # Compiled ptrace interceptor
```

## Components

### rbox-ptrace

ptrace-based command interceptor that:
1. Uses ptrace to intercept execve syscalls
2. Validates commands against embedded DFA
3. Sends decisions to rbox-server via Unix socket
4. Applies sandbox restrictions (Landlock, seccomp, memory limits)

### rbox-server

Go TUI server that:
1. Receives command requests from clients
2. Displays commands to user with risk indicators
3. Accepts allow/deny decisions with time limits
4. Caches decisions for pattern matching

### c-dfa

DFA tools for fast pattern validation:
- `nfa_builder` - Converts patterns to NFA
- `nfa2dfa_advanced` - Converts NFA to minimized DFA
- `dfa2c_array` - Embeds DFA as C array

### rbox-protocol

Binary protocol over Unix socket:
- Client UUID for identification
- Request UUID for matching
- Time-limited decision caching

## Data Flow

```
Command → ptrace intercept → DFA fast-path → rbox-server TUI → User decision
                                              ↓
                                    Unix socket (/run/readonlybox/)
```

## When to Use Me

Use this skill when:
- Understanding component interactions
- Debugging client-server communication
- Understanding DFA embedding process
