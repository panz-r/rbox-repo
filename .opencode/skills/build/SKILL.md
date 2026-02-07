# BUILD Skill

**Scope:** Full project + c-dfa subproject

---
name: build
description: Build and test ReadOnlyBox project including c-dfa subproject
license: MIT
compatibility: opencode
metadata:
  project: readonlybox
  component: build
  scope: full-project
---

## What I do

Provide complete reference for building and testing ReadOnlyBox and the **c-dfa subproject**. Cover Makefile targets, Mage commands, and validation steps.

## Scope: Full Project + c-dfa Subproject

This skill covers **both** the full project and the c-dfa subproject:

```
readonlybox/                    ← FULL PROJECT SCOPE
├── c-dfa/                      ← c-dfa SUBPROJECT (see c-dfa/.opencode/skills/)
│   ├── patterns_safe_commands.txt
│   ├── Makefile
│   ├── tools/
│   └── src/
├── cmd/readonlybox/
├── Magefile.go                 ← Full project orchestration
└── bin/
```

## c-dfa Subproject Skills

For c-dfa-specific build tasks, use these skills:

- **dfa-building-cdfa** - Build DFA from patterns
- **dfa-testing-cdfa** - Run DFA tests
- **dfa-debugging-cdfa** - Debug DFA issues
- **patterns-cdfa** - Write patterns

## Key Distinction

| Command | Scope | Description |
|---------|-------|-------------|
| `cd c-dfa && make test` | c-dfa | Run DFA tests (36 pattern files) |
| `mage test` | full-project | Runs `make test` + Go tests |
| `mage build` | full-project | Builds c-dfa (via make) + Go binaries |

mage orchestrates the full project by invoking make for c-dfa subproject.

## c-dfa Build Commands

All commands run from `c-dfa/` directory.

### Validation

```bash
make validate-patterns
```

Validates all patterns in `patterns_safe_commands.txt` before any build. **Always run this first.**

### Building DFA

```bash
make dfa
```

Builds NFA from patterns, converts to DFA:
1. Validates patterns
2. Generates NFA from patterns
3. Converts NFA to DFA
4. Outputs: `build/readonlybox.dfa`

### Building Tests

```bash
make dfa_test          # Build test binary (single test runner)
```

### Running Tests

```bash
make test              # Run all tests (validates and builds first)
make quick             # Quick test run
```

### Clean Build

```bash
make clean             # Remove build artifacts
```

## Mage Build Commands

Run from project root (`/`).

### Full Build

```bash
mage build
```

Does:
1. Validates patterns
2. Builds nfa_builder, nfa2dfa tools
3. Generates DFA from patterns
4. Converts DFA to C array
5. Builds readonlybox binary
6. Builds libreadonlybox_client.so

### Full Test Suite

```bash
mage test
```

mage runs:
1. `make test` in c-dfa (313 DFA test cases)
2. Go unit tests
3. Integration tests

### Individual Test Targets

```bash
mage unitTest          # Go unit tests
mage integrationTest  # Integration tests only
mage quickTest        # Quick DFA test (via make test)
```

Runs all c-dfa tests (36 pattern files, 313 test cases).

### Individual Test Targets

```bash
mage unitTest          # Go unit tests
mage integrationTest  # Integration tests
mage quickTest        # Quick DFA test
```

### Code Quality

```bash
mage fmt               # Format code
mage coverage         # Generate coverage report
```

## Pattern File Locations

| File | Purpose |
|------|---------|
| `patterns_safe_commands.txt` | Production safe patterns |
| `patterns_quantifier_test.txt` | Quantifier tests |
| `patterns_quantifier_comprehensive.txt` | 40+ pattern groups |
| `patterns_acceptance_category_test.txt` | Category isolation |
| `patterns_with_captures.txt` | Capture tag tests |
| `patterns_dangerous_commands.txt` | Negative tests |

## Build Dependencies

### C Tools (c-dfa)

```bash
gcc -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2
```

Dependencies: `libc`, `math library (-lm)`

### Go Tools

```bash
go build
```

Dependencies: Go 1.19+, Mage

## Common Issues

### Validation Fails

```bash
# Fix: Add missing fragments
[fragment:missing_name] pattern_value

# Fix: Use correct category format
[safe::readonly:git] git status  # NOT [safe path matching:...]
```

### Build Fails

```bash
# Ensure tools are built
mage build

# Clean and rebuild
mage clean
mage build
```

### Tests Fail

```bash
# Check which test group failed
mage test 2>&1 | grep "Failed Test Groups"

# Validate patterns first
cd c-dfa && make validate-patterns

# Rebuild DFA
cd c-dfa && make dfa
```

## Build Flags

### nfa_builder

```bash
NFA_BUILDER_DEBUG=1   # Enable debug output
NFA_BUILDER_VERBOSE=1 # Verbose output
```

### nfa2dfa

```bash
NFA2DFA_DEBUG=1       # Enable debug output
NFA2DFA_VERBOSE=1    # Verbose output
```

Example:
```bash
NFA_BUILDER_VERBOSE=1 make dfa
```

## Output Files

After successful build:

| File | Description |
|------|-------------|
| `bin/readonlybox` | Main binary |
| `bin/libreadonlybox_client.so` | LD_PRELOAD library |
| `c-dfa/build/readonlybox.dfa` | Production DFA (built from patterns) |
| `c-dfa/build/*.dfa` | All 36 DFA files for testing |

## When to Use Me

Use this skill when:
- Building ReadOnlyBox from source
- Running tests after pattern changes
- Debugging build issues
- Adding new build targets
- Understanding build pipeline
