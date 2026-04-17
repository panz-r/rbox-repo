# C-DFA Directory

High-performance C implementation of a Deterministic Finite Automata (DFA) for fast 
matching of inputs to sets of patterns.

## Components

### Core Library (`lib/`)
- `pipeline.c` - Pipeline orchestration for NFA→DFA conversion, minimization, compression
- `dfa_loader.c` - Binary DFA file loading with header validation
- `dfa_machine.c` - DFA machine lifecycle (init, validate, query)

### Evaluation Engine (`src/`)
- `dfa_eval.c` - Side-effect-free DFA evaluation (zero allocation, no stderr writes)

### Tools (`tools/`)
- `cdfatool` - **Unified CLI for all DFA operations** (use this instead of individual tools)
  - Subcommands: `validate`, `compile`, `embedd`, `verify`, `eval`
- `nfa_builder.h`, `nfa_construct.c`, `nfa_parser.c` - NFA construction from patterns
- `dfa_minimize.c`, `dfa_compress.c`, `pattern_order.c` - DFA optimization
- `nfa_preminimize.c` - NFA pre-minimization (epsilon bypass, prefix merge)

### Headers (`include/`)
- `cdfa_defines.h` - Canonical constants, VSYM_*, VERBOSE_PRINT macro
- `dfa_format.h` - Binary format accessors (dfa_fmt_*), dfa_fmt_verify_checksums()
- `dfa_types.h` - Core types (dfa_minimize_algo_t, dfa_result_t, CAT_MASK_0-7)
- `pipeline.h` - Pipeline API
- `dfa_errors.h` - Error handling macros (ERROR, FATAL, FATAL_SYS)

### Tests
- `tests/test_library_api.c` - Library API tests
- `tests/test_eval_only.c` - Evaluation-only tests
- `tests/regression_test.c` - Pattern regression tests
- `testgen/` - Test pattern generation

## Build Commands

```bash
# Build
cd c-dfa/build && cmake .. && cmake --build .

# Test
cd c-dfa/build && ctest --output-on-failure

# Run specific test
cd c-dfa/build && ./tests/test_library_api

# Generate test patterns
cd c-dfa/build && ./testgen/testgen

# Fuzz (requires fuzzing headers)
cd c-dfa/fuzz && <fuzzer_binary>
```

## Binary Format

- **Version**: V11
- **Magic**: 0xDFABinary
- **Checksums**: CRC32-C + FNV-1a in header
- **Encoding**: Compact state encoding (DFA_RULE_ENC_COMPACT, DFA_RULE_ENC_DIRECT)

## Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `VSYM_EPS` | 257 | Epsilon transition (non-consuming) |
| `VSYM_EOS` | 258 | End-of-string marker |
| `CAT_MASK_0-7` | 0x01-0x80 | Category bitmasks (generic, pattern-defined) |
| `DFA_MAX_CAPTURES` | 16 | Maximum capture groups |

## Key Patterns

- **Format Accessors**: Use `dfa_fmt_*()` functions, not struct field access
- **Error Handling**: Library returns error codes; tools use `FATAL()`/`exit()`
- **Verbose Output**: `VERBOSE_PRINT(module, "format\n", args...)` - module declares `{module}_verbose`
- **Type Naming**: snake_case_t (e.g., `state_signature_t`, `fragment_result_t`)

## Architecture

```
Pattern File → NFA Builder → NFA → Subset Construction → DFA
                                                        ↓
                                                  Minimization
                                                        ↓
                                                  Compression
                                                        ↓
                                               Binary DFA Layout
                                                       (cache-friendly,
                                                        compact encoding)
                                                        ↓
                                            Evaluation (eval library)
```

The pipeline library (`lib/pipeline.c`) orchestrates the full build flow.
The eval library (`src/dfa_eval.c`) operates directly on the binary format,
which uses layout optimizations for cache efficiency and memory bandwidth.

## Binary DFA Layout

The binary format (V11) includes:
- **Header**: magic, version, encoding, state count, checksums
- **States**: Compact encoding (variable stride based on encoding type)
- **EOS section**: End-of-string transitions
- **PID section**: Pattern identifier data
- **Rules**: Encoded transition tables optimized for the evaluation loop

## Important Notes

- Eval path is side-effect free - no ERROR() calls, no stderr writes
- Always use `dfa_fmt_*` accessors for binary data access (V10 struct layout differs)
- Pipeline library depends on tools/ modules (minimize, compress, etc.) - architectural coupling
