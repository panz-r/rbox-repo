# DFA Building (c-dfa)

**Scope:** c-dfa subproject only

---
name: dfa-building-cdfa
description: Build NFA and DFA files in the c-dfa subproject, understand the pattern-to-DFA pipeline
license: MIT
兼容性: opencode
metadata:
  project: readonlybox
  component: c-dfa
  workflow: build
  scope: c-dfa-subproject
---

## What I do

Build DFA files from pattern specifications in the **c-dfa subproject**. Explain the NFA/DFA build pipeline and how patterns become executable state machines.

## Scope: c-dfa Subproject

All commands run from `c-dfa/` directory:

```
readonlybox/c-dfa/
├── patterns_*.txt       # Pattern files (36 total)
├── tools/
│   ├── nfa_builder           # Pattern → NFA
│   └── nfa2dfa_advanced      # NFA → DFA
├── src/
│   ├── dfa_eval.c            # Runtime matching
│   └── dfa_test.c            # Test runner
├── include/
│   └── dfa_types.h           # Type definitions
└── Makefile
```

## Build Pipeline

```
Pattern File
    ↓ nfa_builder (auto alphabet construction)
    ↓
NFA (build/*.nfa) - intermediate, deleted after DFA build
    ↓ nfa2dfa_advanced
    ↓
DFA (build/*.dfa) - binary format, ready for evaluation
```

## Build Commands

### Full Build (NFA + DFA)

```bash
cd c-dfa
make dfa
```

This:
1. Validates all pattern files
2. Builds NFA for each pattern file
3. Converts NFA to DFA
4. Outputs: `build/readonlybox.dfa` + 35 other DFA files

### Build Single Pattern File

```bash
cd c-dfa
./tools/nfa_builder patterns_safe_commands.txt build/readonlybox.nfa
./tools/nfa2dfa_advanced build/readonlybox.nfa build/readonlybox.dfa
```

### Build All Test DFAs

```bash
cd c-dfa
make dfa  # Builds all 36 DFA files
```

### Clean Build Artifacts

```bash
cd c-dfa
make clean
rm -rf build/
```

## nfa_builder Tool

Located: `c-dfa/tools/nfa_builder`

### Usage

```bash
./tools/nfa_builder <pattern_file> <output.nfa>
```

### Options

| Option | Description |
|--------|-------------|
| `--validate-only` | Only validate pattern file, don't build NFA |
| `--verbose` | Enable verbose output |
| `--verbose-alphabet` | Show alphabet construction details |
| `--verbose-validation` | Show validation details |
| `--verbose-nfa` | Show NFA building details |

### Examples

```bash
# Validate a pattern file
./tools/nfa_builder --validate-only patterns_safe_commands.txt

# Build NFA with verbose output
./tools/nfa_builder --verbose patterns_safe_commands.txt build/readonlybox.nfa
```

### Key Feature: Automatic Alphabet Construction

**IMPORTANT:** The nfa_builder automatically constructs the alphabet from pattern files:
- No external alphabet file needed
- Parses all characters used in patterns
- Assigns symbol IDs (0=ANY, 1=EPSILON, 2=EOS, 3+=characters)
- Handles special symbols (space, tab, captures)

## nfa2dfa_advanced Tool

Located: `c-dfa/tools/nfa2dfa_advanced`

### Usage

```bash
./tools/nfa2dfa_advanced <input.nfa> <output.dfa>
```

### What It Does

1. Reads NFA from text file
2. Applies subset construction algorithm
3. Generates DFA states
4. Assigns acceptance categories
5. Outputs binary DFA file

## Pattern File Locations

| File | Purpose |
|------|---------|
| `patterns_safe_commands.txt` | Production safe patterns |
| `patterns_expanded_*.txt` | Edge case tests |
| `patterns_command_*.txt` | Category tests (admin, caution, etc.) |
| `patterns_capture_*.txt` | Capture group tests |

## Output Files

After `make dfa`:

| File | Description |
|------|-------------|
| `build/patterns_*.dfa` | 36 DFA files (one per pattern file) |
| `build/patterns_*.nfa` | Deleted after DFA conversion |

## Debug Build Output

### Verbose NFA Building

```bash
cd c-dfa
NFA_BUILDER_VERBOSE=1 make dfa
```

### Verbose DFA Conversion

```bash
cd c-dfa
NFA2DFA_VERBOSE=1 make dfa
```

## Common Build Errors

### Validation Error

```
Error: Fragment 'x' not defined
```

**Fix:** Add fragment definition before patterns that use it.

### Missing Tool

```
make: *** No rule to make target 'dfa'
```

**Fix:** Ensure you're in c-dfa directory and tools are built.

## When to Use Me

Use this skill when:
- Building DFA from patterns
- Debugging build failures
- Understanding the NFA/DFA pipeline
- Adding new pattern files
- Rebuilding after pattern changes
