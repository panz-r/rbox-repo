# ReadOnlyBox C DFA Layer

A high-performance C implementation of a Deterministic Finite Automata (DFA) for fast validation of read-only commands.

## Quick Start

```bash
# Build
make

# Test
make test

# Build DFA from patterns
./tools/nfa_builder patterns/commands/safe_commands.txt readonlybox.nfa
./tools/nfa2dfa_advanced --minimize-hopcroft readonlybox.nfa readonlybox.dfa
```

## Architecture

```
Pattern Input → Validation → Ordering → NFA Build + Parsing → NFA Pre-Minimize → DFA Construct → Flatten → Minimize → Re-Flatten → Compress → Layout → Binary DFA
```

See [docs/PIPELINE.md](docs/PIPELINE.md) for detailed pipeline documentation.

## Build Commands

| Command | Description |
|---------|-------------|
| `make` | Build all tools and tests |
| `make test` | Run full test suite |
| `make test-moore` | Test Moore minimization |
| `make test-hopcroft` | Test Hopcroft algorithm (recommended) |
| `make test-brzozowski` | Test Brzozowski algorithm |
| `make build-sat` | Build with SAT solver support |
| `make test-sat` | Run SAT minimization tests |
| `make test-integrity` | Run minimization integrity tests |
| `make clean` | Clean build artifacts |
| `make fuzz-build` | Build fuzzers |

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

Other projects can define their own category meanings.

## File Structure

```
c-dfa/
├── include/          # Public headers
├── src/              # Library (eval, loader, test)
├── tools/            # Build tools (nfa_builder, nfa2dfa, etc.)
├── tests/            # Test code
├── fuzz/             # LibFuzzer fuzzers
├── vendor/           # CaDiCaL SAT solver
├── patterns/         # Test pattern files
├── docs/             # Documentation
└── Makefile
```

## Documentation

Key documentation files in `docs/`:

| File | Description |
|------|-------------|
| [docs/PIPELINE.md](docs/PIPELINE.md) | Full pipeline overview |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | Terminology definitions |
| [docs/LAYOUT_OPTIMIZATION.md](docs/LAYOUT_OPTIMIZATION.md) | Cache optimization |
| [docs/TRANSITION_COMPRESSION.md](docs/TRANSITION_COMPRESSION.md) | Rule compression |

## Integration

The C DFA layer is the first line of defense in ReadOnlyBox:

1. **C DFA** - Fast validation of safe commands (90%+ of cases)
2. **Go Parsers** - Detailed semantic analysis
3. **Fallback** - Conservative blocking for unknown commands

## Performance

- **Evaluation**: <1μs per command
- **Memory**: ~10-100KB for typical DFAs
- **Throughput**: 1M+ commands/second

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

## Recent Fixes

### NFA Builder Crash Fixes (2026-02-21)

Fixed multiple segmentation fault vulnerabilities discovered through fuzzing in the nfa_builder tool:

1. **Input Validation**: Added validation for NULL/empty patterns at entry points
2. **Bounds Checking**: Added checks before accessing alphabet array with symbol IDs
3. **Pattern Parsing**: Added bounds check in parse_rdp_element to prevent accessing past end of pattern string

### Start State Preservation (2026-02-19)

A critical bug was fixed in the DFA minimization and layout optimization code. The issue was that the start state (state 0) was not being preserved at position 0 during:

1. **DFA Minimization** (`dfa_minimize.c`): The `build_minimized_dfa()` function now explicitly finds and processes the partition containing state 0 first, ensuring the start state remains at position 0.

2. **Layout Optimization** (`dfa_layout.c`): The `build_state_order_bfs()` function now ensures state 0 stays at position 0 after cache-optimized reordering.

This fix resolved a major test regression where approximately 240 tests were failing due to the DFA evaluator starting from the wrong state.

## License

This code is part of the ReadOnlyBox project and follows the same licensing terms.
