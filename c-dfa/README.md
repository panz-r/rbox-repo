# ReadOnlyBox C DFA Layer

A high-performance C implementation of a Deterministic Finite Automata (DFA) for fast command validation.

## Quick Start

```bash
# Configure and build
cmake -B build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure
```

## Build Options

| Option | Description |
|--------|-------------|
| `-DENABLE_SAT=ON/OFF` | Enable SAT-based minimization (requires CaDiCaL) |
| `-DENABLE_COVERAGE=ON/OFF` | Enable coverage instrumentation |
| `-DENABLE_FUZZ=ON/OFF` | Enable LibFuzzer harnesses (requires clang) |

### Building with Fuzzers

```bash
cmake -B build -DENABLE_FUZZ=ON \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build
```

## Architecture

```
Pattern Input → Validation → Ordering → NFA Build + Parsing → NFA Pre-Minimize → DFA Construct → Flatten → Minimize → Re-Flatten → Compress → Layout → Binary DFA
```

## Build Outputs

| Output | Location | Purpose |
|--------|----------|---------|
| `libreadonlybox_dfa.a` | `build/tools/` | Full library (building + evaluating) |
| `libreadonlybox_dfa.so` | `build/tools/` | Shared library |
| `nfa_builder` | `build/tools/` | Pattern file to NFA |
| `nfa2dfa_advanced` | `build/tools/` | NFA to DFA with minimization |
| `dfa_eval_wrapper` | `build/tools/` | Command-line DFA evaluation |
| `dfa2c_array` | `build/tools/` | DFA to C array converter |

## Minimization Algorithms

| Algorithm | Complexity | Description |
|-----------|------------|-------------|
| **Hopcroft** | O(n log n) | Recommended - efficient partition refinement |
| **Moore** | O(n²) | Simple table-filling |
| **Brzozowski** | O(2ⁿ) | Double-reversal |
| **SAT** | NP-hard | Provably minimal (requires CaDiCaL) |

## Pattern Syntax

| Syntax | Meaning |
|--------|---------|
| `git status` | Literal bytes |
| `[abc]` | Byte class |
| `[^abc]` | Negated byte class |
| `a*` | Zero or more |
| `a+` | One or more |
| `a?` | Optional |
| `a\|b` | Alternation |
| `((FRAGMENT))` | Fragment reference |
| `<cap>pattern</cap>` | Capture tag |
| `\*` | Wildcard argument |

## Categories

The DFA uses an 8-bit category mask - the meaning of each bit is defined by the library user. The ReadOnlyBox project uses:

| Bit | ReadOnlyBox Usage |
|-----|-------------------|
| 0x01 | safe - Read-only, no side effects |
| 0x02 | caution - Minor side effects |
| 0x04 | modifying - Modifies files |
| 0x08 | dangerous - Destructive |
| 0x10 | network - Network operations |
| 0x20 | admin - Requires privileges |

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

### Fragments

Fragments are reusable pattern components with namespace support:

```
# Define a fragment in a namespace
[fragment:safe::digit] 0|1|2|3|4|5|6|7|8|9
[fragment:caution::word] a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z

# Reference fragments
[safe] ((digit))+        → Looks for safe::digit
[caution] ((word))+       → Looks for caution::word
[test] ((safe::digit))+   → Cross-namespace reference (looks for safe::digit)
```

**Namespace Semantics:**
- `((a::b))` - References fragment 'b' in namespace 'a' (explicit)
- `((c))` - References fragment 'c' in the **same namespace** as the pattern

## Building the DFA

```bash
# Build the tools
cmake -B build && cmake --build build

# Generate DFA using Hopcroft minimization (recommended)
./build/tools/nfa_builder patterns/commands/safe_commands.txt readonlybox.nfa
./build/tools/nfa2dfa_advanced --minimize-hopcroft readonlybox.nfa readonlybox.dfa
```

## Test Organization

### Fast Tests (CTest)
```bash
ctest --test-dir build --output-on-failure
```
Runs: `test_library_api`, `test_eval_only`, `testgen_test` (~3 seconds)

### Full Test Suite
```bash
cmake --build build --target test-full
```
Runs the complete test suite via `tests/run_test_suite.py` (~5-10 minutes):
- Moore algorithm on test-set A with SAT compression
- Hopcroft algorithm on test-set B with SAT compression
- Stress tests on test-set C with SAT compression
- Minimization integrity tests
- Library API tests
- Eval-only library tests
- DFA2C array tool tests
- Binary format edge case tests
- Capture system tests
- Pattern regression tests

Output includes:
- Per-suite timing table
- Per-suite failure details (if any)
- Aggregated summary line: `AGGREGATE SUMMARY: X/Y tests`

### Manual Test Runner
Run individual test sets manually:

```bash
./build/tests/dfa_test --minimize-moore --compress-sat --test-set A
./build/tests/dfa_test --minimize-hopcroft --compress-sat --test-set B
./build/tests/dfa_test --minimize-moore --compress-sat --test-set C
```

Test sets:
| Set | Description |
|-----|-------------|
| **A** | Core tests: basic patterns, quantifiers, fragments, alternation |
| **B** | Expanded tests: complex patterns with nested quantifiers |
| **C** | Command tests: admin, caution, modifying, dangerous, network commands |

## Performance Characteristics

- **Evaluation Time**: <1μs per command (typical)
- **Memory Usage**: ~10-100KB for typical DFAs
- **Initialization**: <10μs
- **Throughput**: 1M+ commands/second

## File Structure

```
c-dfa/
├── include/          # Public headers
├── src/              # Library (eval, loader, machine, test)
├── lib/              # Pipeline implementation
├── tools/            # Build tools (nfa_builder, nfa2dfa, etc.)
├── tests/            # Test code
├── testgen/          # Test pattern generator
├── fuzz/             # LibFuzzer fuzzers
├── patterns/         # Test pattern files
├── cmake/            # CMake modules
└── CMakeLists.txt    # CMake build configuration
```

## Fuzzing

This project includes LibFuzzer-based fuzzers for continuous testing. See `fuzz/README.md` for details.

```bash
# Build fuzzers (requires clang)
cmake -B build -DENABLE_FUZZ=ON \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build

# Fuzzers are in build/fuzz/
./build/fuzz/dfa_eval_fuzzer ...
```

## Security Considerations

- **Memory Safety**: All memory access is bounds-checked
- **Input Validation**: All inputs are validated before processing
- **No Allocation**: DFA evaluation uses no dynamic memory
- **Deterministic**: Same input always produces same output
