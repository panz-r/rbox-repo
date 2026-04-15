# Fuzzing Infrastructure for c-dfa

LibFuzzer-based fuzzers for testing the DFA and pattern parser components of ReadOnlyBox.

## Building

Fuzzers require clang with LibFuzzer support. Build with CMake:

```bash
# Configure with fuzzers enabled (must use clang)
cmake -B build -DENABLE_FUZZ=ON \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++

# Build all (including fuzzers)
cmake --build build
```

Fuzzers are output to `build/fuzz/`:
- `dfa_eval_fuzzer`
- `pattern_parse_fuzzer`
- `nfa_build_fuzzer`
- `pipeline_fuzzer`
- `dfa_loader_fuzzer`

## Running Fuzzers

Run from the c-dfa source directory:

```bash
# DFA evaluation fuzzer
./build/fuzz/dfa_eval_fuzzer fuzz/corpus/seed/dfa_eval \
    -merge=fuzz/corpus/interesting/dfa_eval \
    -artifact_prefix=fuzz/crashes/dfa_eval_ \
    -max_len=4096 -jobs=4 -workers=4

# Pattern parser fuzzer
./build/fuzz/pattern_parse_fuzzer fuzz/corpus/seed/pattern_parser \
    -merge=fuzz/corpus/interesting/pattern_parser \
    -artifact_prefix=fuzz/crashes/pattern_parse_ \
    -max_len=8192 -jobs=4 -workers=4

# NFA build fuzzer
./build/fuzz/nfa_build_fuzzer fuzz/corpus/seed/pattern_parser \
    -merge=fuzz/corpus/interesting/nfa_build \
    -artifact_prefix=fuzz/crashes/nfa_build_ \
    -max_len=32768 -jobs=2 -workers=2

# Pipeline fuzzer (full build pipeline)
./build/fuzz/pipeline_fuzzer fuzz/corpus/seed/pattern_parser \
    -merge=fuzz/corpus/interesting/pipeline \
    -artifact_prefix=fuzz/crashes/pipeline_ \
    -max_len=4096 -jobs=2 -workers=2

# DFA loader fuzzer
./build/fuzz/dfa_loader_fuzzer fuzz/corpus/seed/dfa_binary \
    -merge=fuzz/corpus/interesting/loader \
    -artifact_prefix=fuzz/crashes/loader_ \
    -max_len=65536 -jobs=2 -workers=2
```

## Fuzzers

### dfa_eval_fuzzer

Fuzzes `dfa_eval()` with random command strings.

**Target:** `src/dfa_eval.c`

**What it tests:**
- DFA evaluation correctness
- Capture extraction
- Boundary conditions
- Memory safety (ASan)
- Undefined behavior (UBSan)

### pattern_parse_fuzzer

Fuzzes pattern validation via `cdfatool validate`.

**Target:** `tools/cdfatool validate` pattern validation

**What it tests:**
- Pattern file parsing
- Syntax validation
- Resource handling

### nfa_build_fuzzer

Fuzzes DFA construction by running `cdfatool compile` as subprocess.

**Target:** `tools/cdfatool compile` (full pattern to DFA compilation)

**What it tests:**
- Pattern file parsing
- DFA state construction
- Memory allocation during build

### pipeline_fuzzer

Fuzzes the full build pipeline with various configurations.

**Target:** Full NFA→DFA pipeline including SAT-based optimization

**What it tests:**
- End-to-end build pipeline
- SAT solver integration
- All minimization algorithms

### dfa_loader_fuzzer

Fuzzes binary and text DFA loading.

**Target:** `src/dfa_loader.c`

**What it tests:**
- Binary DFA format parsing
- Text DFA format parsing
- Loading error handling

## Crash Replay

Replay crashes to verify fixes:

```bash
# Run single crash
./build/fuzz/dfa_eval_fuzzer fuzz/crashes/dfa_eval_<id> -runs=1

# Run all crashes of a type
for crash in fuzz/crashes/dfa_eval_*; do
    echo "=== Replaying $crash ==="
    ./build/fuzz/dfa_eval_fuzzer "$crash" -runs=1
done
```

## Memory Protection

Three layers of protection prevent OOM crashes:

| Layer | Mechanism | Limit |
|-------|-----------|-------|
| Per-process | `RLIMIT_AS` | 8 GB per child |
| Per-fuzzer | `-rss_limit_mb` | 4 GB LibFuzzer limit |
| Session | `systemd-run` | 8 GB total |

**Note:** The 8 GB per-process limit is required because `cdfatool` is compiled with `-mcmodel=medium` which requires larger address space.

## Build Requirements

- clang with LibFuzzer support (`-fsanitize=fuzzer`)
- AddressSanitizer (ASan)
- UndefinedBehaviorSanitizer (UBSan)

On Ubuntu/Debian with clang:
```bash
sudo apt install clang
```

## File Structure

```
fuzz/
  CMakeLists.txt              # CMake build configuration
  dfa_eval_fuzzer.cpp         # DFA eval fuzzer source
  pattern_parse_fuzzer.cpp     # Pattern parse fuzzer source
  nfa_build_fuzzer.cpp        # NFA build fuzzer source
  pipeline_fuzzer.cpp          # Pipeline fuzzer source
  dfa_loader_fuzzer.cpp       # DFA loader fuzzer source
  cmd_dict.txt                # Fuzzing dictionary
  crashes/                    # Crash artifacts
  corpus/
    seed/                     # Seed corpus
      dfa_eval/
      pattern_parser/
      dfa_binary/
    interesting/              # Coverage-increasing inputs
  logs/                       # Session logs
```

## Legacy Makefile

A legacy Makefile exists for reference. The CMake build is the supported method:

```bash
# Old way (deprecated)
cd fuzz && make all

# New way (CMake)
cmake -B build -DENABLE_FUZZ=ON \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build
```
