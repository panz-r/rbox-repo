# ReadOnlyBox C DFA Layer

A high-performance C implementation of a Deterministic Finite Automata (DFA) for fast command validation.

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
| `make` | Build all tools, tests, and libraries |
| `make test` | Run full test suite |
| `make test-moore` | Test Moore minimization |
| `make test-hopcroft` | Test Hopcroft algorithm (recommended) |
| `make test-brzozowski` | Test Brzozowski algorithm |
| `make build-sat` | Build with SAT solver support |
| `make test-sat` | Run SAT minimization tests |
| `make test-integrity` | Run minimization integrity tests |
| `make clean` | Clean build artifacts |
| `make fuzz-build` | Build fuzzers |

**Libraries produced:**

| Library | Size | Purpose |
|---------|------|---------|
| `libdfa_eval.a` | ~8KB | Eval-only (loading + evaluation). For pre-built DFAs. |
| `libreadonlybox_dfa.a` | ~235KB | Full library (building + evaluating). For dynamic pattern sets. |

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
[caution] ((word))+      → Looks for caution::word
[test] ((safe::digit))+  → Cross-namespace reference (looks for safe::digit)
```

**Namespace Semantics:**
- `((a::b))` - References fragment 'b' in namespace 'a' (explicit)
- `((c))` - References fragment 'c' in the **same namespace** as the pattern

### Validation

The NFA builder performs automatic validation:

1. **Duplicate Detection**: Warns and removes duplicate patterns
2. **Fragment Reference Validation**: Errors on undefined fragment references
3. **Namespace Validation**: Ensures fragments are looked up in correct namespace

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

There are two types of users:

### Eval-Only Users (Recommended)

If you only need to evaluate strings against a pre-built binary DFA, link against `libdfa_eval.a` (17KB). No setup, no allocations, zero overhead.

```c
#include "dfa.h"
#include <stdlib.h>
#include <stdio.h>

// Load DFA binary - however you want (you own the memory)
FILE* f = fopen("readonlybox.dfa", "rb");
fseek(f, 0, SEEK_END);
size_t dfa_size = ftell(f);
fseek(f, 0, SEEK_SET);
void* dfa_data = malloc(dfa_size);
fread(dfa_data, 1, dfa_size, f);
fclose(f);

// Optional: verify this is the right DFA
dfa_eval_validate_id(dfa_data, dfa_size, "readonlybox-v2");

// Evaluate - pass DFA pointer and size directly
dfa_result_t result;
if (dfa_eval(dfa_data, dfa_size, "cat file.txt", 12, &result)) {
    if (result.category == DFA_CMD_READONLY_SAFE) {
        // Command is safe
    }
}

// Free when done
free(dfa_data);
```

Link with:
```bash
gcc -o myapp myapp.c -ldfa_eval -Iinclude
```

### Machine Builders

If you need to build DFAs dynamically from pattern sets, link against `libreadonlybox_dfa.a` (235KB). See [docs/PIPELINE.md](docs/PIPELINE.md).

```c
#include "dfa.h"
#include "pipeline.h"

pipeline_t* p = pipeline_create();
pipeline_set_patterns_file(p, "patterns.txt");
pipeline_run(p);
dfa_result_t result = pipeline_evaluate(p, "cat file.txt");
pipeline_destroy(p);
```

Link with:
```bash
gcc -o builder builder.c -lreadonlybox_dfa -Iinclude -lstdc++
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
| [docs/LAYOUT_OPTIMIZATION.md](docs/LAYOUT_OPTIMIZATION.md) | SCC-based cache optimization |
| [docs/TRANSITION_COMPRESSION.md](docs/TRANSITION_COMPRESSION.md) | Rule compression |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | Terminology definitions |

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

### Pattern Ordering Memory Fix (2026-02-22)

A double-free bug was fixed in the pattern ordering code. The issue was that `pattern_order_optimize()` compacts the pattern array (removing duplicates), but the caller was still using the original `pattern_count` when freeing memory.

**Fix**: The caller now uses `pattern_order_get_stats()` to get the correct count after optimization:

```c
pattern_order_optimize(patterns, pattern_count, &opts);
pattern_order_stats_t stats;
pattern_order_get_stats(&stats);
pattern_count = stats.original_count - stats.duplicates_found;
```

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
