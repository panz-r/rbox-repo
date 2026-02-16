# ReadOnlyBox C DFA Layer

## Overview

This directory contains a high-performance C implementation of a Deterministic Finite Automata (DFA) for quick validation of read-only commands. The DFA is designed to be:

- **Fast**: Compiled C code with direct memory access
- **Safe**: 100% safe command validation
- **Compact**: Binary DFA structure loaded directly into memory
- **Portable**: Works on any platform with a C compiler

## Architecture

```
Command String → DFA Evaluator → Command Category
                          ↓
                   Binary DFA (static data)
```

### Components

1. **DFA Builder Tools** (`tools/`)
   - `nfa_builder`: Converts command specifications to NFA
   - `nfa2dfa_advanced`: Converts NFA to DFA with minimization (Moore, Hopcroft, Brzozowski)
   - `nfa2dfa_sat`: SAT-based minimal DFA construction (requires CaDiCaL)

2. **DFA Library** (`src/`)
   - `dfa_eval.c`: Core DFA evaluation engine
   - `dfa_loader.c`: DFA loading and initialization
   - `dfa_test.c`: Comprehensive test runner

3. **Tests** (`tests/`)
   - `test_sat_encoding.cpp`: SAT encoding unit tests

## Build System

This project uses **GNU Make**:

```bash
# Build all tools and tests
make

# Run full test suite
make test

# Run specific algorithm tests
make test-moore      # Moore minimization algorithm
make test-hopcroft   # Hopcroft algorithm (recommended)
make test-brzozowski # Brzozowski algorithm

# Run SAT minimization tests (requires CaDiCaL)
make build-sat
make test-sat

# Run minimization integrity tests
make test-integrity

# Clean
make clean
make clean-all       # Also cleans vendor builds
```

## Minimization Algorithms

Three minimization algorithms are available:

| Algorithm | Complexity | Description |
|-----------|------------|-------------|
| **Moore** | O(n²) | Simple table-filling algorithm |
| **Hopcroft** | O(n log n) | Efficient partition refinement (recommended) |
| **Brzozowski** | O(2ⁿ) worst | Double-reversal, produces canonical minimal DFA |
| **SAT** | NP-hard | Provably minimal using CaDiCaL SAT solver |

### SAT-Based Minimization

The SAT minimization uses the CaDiCaL SAT solver to find the provably minimal DFA:

```bash
# Build with SAT support (builds CaDiCaL automatically)
make build-sat

# Run SAT encoding tests
make test-sat
```

The SAT approach:
1. Uses Hopcroft's result as an upper bound
2. Binary searches for the minimum partition count
3. Encodes DFA state merging as SAT constraints
4. Guarantees optimal minimization (though slower for large DFAs)

## Command Specification Format

The DFA is built from a command specification file:

```
# Comments start with #
# Format: [category] command_pattern
# Categories: safe, caution, modifying, dangerous, network, admin

[safe] cat *
[safe] grep * *
[dangerous] rm *
[network] curl *
```

### Pattern Syntax

- `*` - Matches any sequence of characters
- `+` - Matches one or more characters
- `?` - Matches any single character
- `[...]` - Character classes
- `{a,b}` - Alternation
- `[category]` - Command category (optional, defaults to safe)

## Building the DFA

```bash
# Build the tools
make

# Generate DFA using Hopcroft minimization (recommended)
./tools/nfa_builder patterns_combined.txt readonlybox.nfa
./tools/nfa2dfa_advanced --minimize-hopcroft readonlybox.nfa readonlybox.dfa

# Or use SAT-based minimal DFA construction
./tools/nfa2dfa_sat readonlybox.nfa readonlybox.dfa
```

## Using the DFA in Applications

```c
#include "dfa.h"
#include "dfa_types.h"

// Load DFA from file
void* dfa_data = load_dfa_from_file("readonlybox.dfa");
dfa_init(dfa_data, size);

// Evaluate a command
dfa_result_t result;
if (dfa_evaluate("cat file.txt", 0, &result)) {
    if (result.category == DFA_CMD_READONLY_SAFE) {
        // Command is safe
    }
}

// Cleanup
dfa_reset();
```

## Test Organization

The test suite is organized into three sets:

| Test Set | Description |
|----------|-------------|
| **A** | Core tests: basic patterns, quantifiers, fragments, alternation |
| **B** | Expanded tests: complex patterns with nested quantifiers |
| **C** | Command tests: admin, caution, modifying, dangerous, network commands |

Run specific test sets:
```bash
./dfa_test --minimize-hopcroft --test-set A
./dfa_test --minimize-hopcroft --test-set BC
```

## Performance Characteristics

- **Evaluation Time**: <1μs per command (typical)
- **Memory Usage**: ~10-100KB for typical DFAs
- **Initialization**: <10μs
- **Throughput**: 1M+ commands/second

### Minimization Performance

| Algorithm | 100 states | 1000 states |
|-----------|------------|-------------|
| Moore | ~1ms | ~100ms |
| Hopcroft | ~0.5ms | ~10ms |
| Brzozowski | ~5ms | ~500ms |
| SAT | ~50ms | varies |

## File Structure

```
c-dfa/
├── include/              # Public headers
│   ├── dfa.h             # Main DFA API
│   ├── dfa_types.h       # DFA data types
│   ├── nfa.h             # NFA structures
│   └── multi_target_array.h
├── src/                  # Library source code
│   ├── dfa_eval.c        # DFA evaluation engine
│   ├── dfa_loader.c      # DFA loading and I/O
│   └── dfa_test.c        # Comprehensive test runner
├── tools/                # Build-time utilities
│   ├── nfa_builder.c     # Pattern → NFA compiler
│   ├── nfa2dfa.c         # NFA → DFA converter
│   ├── dfa_minimize.c    # Moore & Hopcroft algorithms
│   ├── dfa_minimize_brzozowski.c
│   ├── dfa_minimize_sat.cpp  # SAT-based minimization
│   └── multi_target_array.c
├── tests/                # Test files
│   └── test_sat_encoding.cpp
├── fuzz/                 # LibFuzzer fuzzers
│   ├── dfa_eval_fuzzer.cpp
│   ├── pattern_parse_fuzzer.cpp
│   └── corpus/
├── vendor/               # External dependencies
│   └── cadical/          # CaDiCaL SAT solver
├── patterns_*.txt        # Pattern specifications
├── Makefile              # Main build system
└── README.md             # This file
```

## Command Categories

| Category | Description | Examples |
|----------|-------------|----------|
| `safe` | 100% read-only, no side effects | `cat`, `grep`, `git log` |
| `caution` | Read-only but may have side effects | `find -exec`, `xargs` |
| `modifying` | Modifies filesystem | `mv`, `cp`, `rm` |
| `dangerous` | Potentially destructive | `rm -rf`, `dd` |
| `network` | Network operations | `curl`, `wget`, `ssh` |
| `admin` | Requires privileges | `sudo`, `chmod`, `chown` |

## Integration with ReadOnlyBox

The C DFA layer integrates with the main ReadOnlyBox system:

1. **First Layer (C DFA)**: Quick validation of obviously safe commands
2. **Second Layer (Go Parsers)**: Detailed semantic analysis for complex commands
3. **Fallback**: Conservative blocking for unknown commands

### Benefits

- **Performance**: C layer handles 90%+ of common read-only commands
- **Safety**: DFA provides 100% safe validation for known patterns
- **Efficiency**: Reduces load on Go parsers for simple commands

## Fuzzing

This project includes LibFuzzer-based fuzzers for continuous testing:

```bash
# Build fuzzers
make fuzz-build

# Run DFA evaluation fuzzer
make fuzz-run-dfa

# Run pattern parser fuzzer
make fuzz-run-pattern
```

See `fuzz/README.md` for details.

## Security Considerations

- **Memory Safety**: All memory access is bounds-checked
- **Input Validation**: All inputs are validated before processing
- **No Allocation**: DFA evaluation uses no dynamic memory
- **Deterministic**: Same input always produces same output

## License

This code is part of the ReadOnlyBox project and follows the same licensing terms.
