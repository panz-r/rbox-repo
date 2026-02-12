# Fuzzing Infrastructure for c-dfa

This directory contains LibFuzzer-based fuzzers for testing the DFA and pattern parser components of ReadOnlyBox.

## Fuzzers

### 1. dfa_eval_fuzzer

Fuzzes the `dfa_evaluate()` function with random command strings.

**Target:** `c-dfa/src/dfa_eval.c` and `dfa_loader.c`

**Corpus:** `corpus/seed/dfa_eval/` - seed inputs (real commands, edge cases)

**Dictionary:** `cmd_dict.txt` - common command tokens to guide mutation

**Build:**
```bash
make dfa_eval_fuzzer
```

**Run:**
```bash
./dfa_eval_fuzzer corpus/dfa_eval -max_len=4096 -jobs=4 -workers=4
```

**What it tests:**
- DFA evaluation correctness
- Capture extraction
- Boundary conditions
- Memory safety (ASan)
- Undefined behavior (UBSan)

### 2. pattern_parse_fuzzer

Fuzzes the pattern file parser by invoking `nfa_builder --validate-only` as a separate process.

**Target:** `c-dfa/tools/nfa_builder` pattern validation

**Corpus:** `corpus/seed/pattern_parser/` - pattern specification files

**Build:**
```bash
make pattern_parse_fuzzer
```

**Run:**
```bash
./pattern_parse_fuzzer corpus/pattern_parser -max_len=8192 -jobs=4
```

**What it tests:**
- Pattern file parsing
- Syntax validation
- Resource handling (memory limits, timeouts)
- Crashes in nfa_builder

**Caveats:**
- Out-of-process (forks/execs nfa_builder)
- Slower than in-process fuzzing
- Each input spawns a new process

## Build Requirements

- clang with LibFuzzer support (libfuzzer-21-dev)
- AddressSanitizer (ASan)
- UndefinedBehaviorSanitizer (UBSan)

On Ubuntu/Debian:
```bash
sudo apt install libfuzzer-21-dev
```

## Integration with Main Build

From the `c-dfa` directory:
```bash
# Build fuzzers
make fuzz-build

# Run DFA fuzzer
make fuzz-run-dfa

# Run pattern parser fuzzer
make fuzz-run-pattern

# Run both sequentially
make fuzz-run

# Clean fuzzing artifacts
make fuzz-clean
```

## Generating Additional Corpus

The initial corpus is generated from existing pattern files and common commands:
```bash
cd fuzz
./generate_corpus.sh
```

This creates seed files in `corpus/dfa_eval/` and `corpus/pattern_parser/`.

## OSS-Fuzz Integration

These fuzzers are designed to be OSS-Fuzz compatible. To submit to OSS-Fuzz:

1. Create `project.yaml` in OSS-Fuzz's `projects/readonlybox/` directory
2. Write a `build.sh` that builds the fuzzers and copies them to `$OUT`
3. Ensure all dependencies are statically linked or available in OSS-Fuzz environment

## Expected Findings

- **dfa_eval_fuzzer:** Buffer overflows, out-of-bounds reads, invalid state transitions
- **pattern_parse_fuzzer:** Crashes in parser, infinite loops (timed), memory exhaustion, integer overflows

## Crash Triage

When a crash is found, LibFuzzer writes a crash artifact to the current directory:
- `crash-*` - the input that caused the crash
- `stacktrace` - backtrace (if ASan enabled)

Reproduce:
```bash
./dfa_eval_fuzzer crash-xxxxxxxx
```

Then fix the underlying bug and re-run fuzzing.

## Notes

- The DFA used by `dfa_eval_fuzzer` is `../readonlybox.dfa`. Rebuild this if patterns change.
- `pattern_parse_fuzzer` uses resource limits (100MB memory, 1s CPU) to prevent runaway processes.
- Both fuzzers use ASan + UBSan for maximum bug detection.

## Performance

- **dfa_eval_fuzzer:** ~100K+ execs/sec on modern CPU
- **pattern_parse_fuzzer:** ~1K-5K execs/sec (out-of-process overhead)

## Current Status

- ✅ dfa_eval_fuzzer: Initialized and running
- ✅ pattern_parse_fuzzer: Initialized and running (found crash on pattern `[safe:test] (a)+`)
- ⏳ Continuous fuzzing recommended to find additional bugs
