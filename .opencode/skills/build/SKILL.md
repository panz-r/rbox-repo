# BUILD Skill

**Scope:** Full project

---
name: build
description: Build ReadOnlyBox components - rbox-ptrace, rbox-server, c-dfa, shellsplit
license: MIT
compatibility: opencode
metadata:
  project: readonlybox
  scope: full-project
---

## What I do

Provide build instructions for ReadOnlyBox components.

## Project Structure

```
readonlybox/
├── rbox-ptrace/           # ptrace client (C, uses make)
├── rbox-server/           # TUI server (Go, uses mage)
├── c-dfa/                 # DFA tools (C, uses make)
├── shellsplit/            # Shell tokenizer (C, uses make)
├── rbox-protocol/         # Protocol library (C, uses make)
├── bin/
│   ├── readonlybox-server
│   └── readonlybox-ptrace
└── Magefile.go
```

## Build Commands

### All Components (Mage)

```bash
mage build        # Build all components
mage clean        # Clean all build artifacts
mage install      # Install to /usr/local/bin
mage test         # Run tests
```

### rbox-ptrace (C)

```bash
cd rbox-ptrace
make              # Build
make clean        # Clean
make test         # Run unit tests
```

### rbox-server (Go)

```bash
cd rbox-server
go build          # Build
go test           # Run tests
```

### c-dfa (C)

```bash
cd c-dfa
make              # Build tools and libraries
make test         # Run tests
make clean        # Clean
```

### shellsplit (C)

```bash
cd shellsplit
make              # Build library
make clean        # Clean
```

### rbox-protocol (C)

```bash
cd rbox-protocol
make              # Build library
make test         # Run tests
```

## Build Dependencies

- Go 1.21+
- gcc
- make
- Mage

## When to Use Me

Use this skill when:
- Building components from source
- Running tests
- Debugging build issues
