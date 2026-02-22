# Fuzzing Infrastructure for c-dfa

LibFuzzer-based fuzzers for testing the DFA and pattern parser components of ReadOnlyBox.

## Quick Reference (Common Tasks)

```bash
# Build all fuzzers
make all

# List found crashes
make list-crashes

# Clear all crash artifacts (after fixing bugs)
make clean-crashes

# Replay all crashes (verify fixes)
make replay-all-crashes

# Replay crashes for specific fuzzer
make replay-all-nfa-build-crashes
make replay-all-dfa-crashes
make replay-all-pattern-crashes

# Replay specific crash files
make replay-crashes-nfa-build CRASHES="crashes/nfa_build_*"

# Run 4-hour fuzzing session with memory protection
./run_fuzzing_4h.sh nfa-build
./run_fuzzing_4h.sh dfa
./run_fuzzing_4h.sh pattern
```

## Fuzzers

### 1. nfa_build_fuzzer

Fuzzes NFA construction by running `nfa_builder` as a subprocess.

**Target:** `c-dfa/tools/nfa_builder` (full NFA construction, not just validation)

**Corpus:** `corpus/seed/pattern_parser/` - pattern specification files

**Build:**
```bash
make nfa_build_fuzzer
```

**Run:**
```bash
./nfa_build_fuzzer corpus/seed/pattern_parser -max_len=32768 -jobs=2 -workers=2
```

**What it tests:**
- Pattern file parsing
- NFA state construction
- Memory allocation during build
- Crash detection in builder

**Performance:** ~1K-5K execs/sec (subprocess overhead)

### 2. dfa_eval_fuzzer

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
./dfa_eval_fuzzer corpus/seed/dfa_eval -max_len=4096 -jobs=4 -workers=4
```

**What it tests:**
- DFA evaluation correctness
- Capture extraction
- Boundary conditions
- Memory safety (ASan)
- Undefined behavior (UBSan)

**Performance:** ~100K+ execs/sec on modern CPU

### 3. pattern_parse_fuzzer

Fuzzes pattern validation by invoking `nfa_builder --validate-only` as a subprocess.

**Target:** `c-dfa/tools/nfa_builder` pattern validation

**Corpus:** `corpus/seed/pattern_parser/` - pattern specification files

**Build:**
```bash
make pattern_parse_fuzzer
```

**Run:**
```bash
./pattern_parse_fuzzer corpus/seed/pattern_parser -max_len=8192 -jobs=4
```

**What it tests:**
- Pattern file parsing
- Syntax validation
- Resource handling (memory limits, timeouts)

**Performance:** ~1K-5K execs/sec (subprocess overhead)

## Memory Protection

Three layers of protection prevent OOM crashes:

| Layer | Mechanism | Limit |
|-------|-----------|-------|
| Per-process | `RLIMIT_AS` | 2 GB per child |
| Per-fuzzer | `-rss_limit_mb` | 4 GB LibFuzzer limit |
| Session | `systemd-run` | 8 GB total |

The `run_fuzzing_4h.sh` script applies all three layers automatically.

## Build Requirements

- clang with LibFuzzer support (`libfuzzer-21-dev`)
- AddressSanitizer (ASan)
- UndefinedBehaviorSanitizer (UBSan)

On Ubuntu/Debian:
```bash
sudo apt install libfuzzer-21-dev
```

## Running Fuzzing Sessions

### Quick Run (No Protection)

```bash
make run-nfa-build       # NFA build fuzzer
make run-dfa             # DFA eval fuzzer
make run-pattern         # Pattern parse fuzzer
```

### Protected 4-Hour Session

```bash
./run_fuzzing_4h.sh nfa-build   # Recommended for extended fuzzing
./run_fuzzing_4h.sh dfa
./run_fuzzing_4h.sh pattern
```

Logs are saved to `logs/<timestamp>/`:
- `fuzzer.log` - LibFuzzer output
- `watchdog.log` - Memory watchdog output

### With Cgroup Memory Limits

```bash
make run-nfa-build-cgroup
make run-dfa-cgroup
make run-pattern-cgroup
```

## Crash Management

### List Crashes

```bash
make list-crashes
```

### Replay Crashes

```bash
# Replay all crashes from all fuzzers
make replay-all-crashes

# Replay by fuzzer type
make replay-all-nfa-build-crashes
make replay-all-dfa-crashes
make replay-all-pattern-crashes

# Replay specific crash files
make replay-crashes-nfa-build CRASHES="crashes/nfa_build_abc123"
```

### Clear Crashes

After fixing bugs and verifying with replay:

```bash
make clean-crashes
```

## Generating Corpus

Initial corpus from existing pattern files:

```bash
./generate_corpus.sh
./generate_multiline_corpus.sh
```

This creates seed files in `corpus/seed/` directories.

## Crash Artifacts

When a crash is found, LibFuzzer saves artifacts to `crashes/`:
- `crashes/nfa_build_*` - NFA builder crashes
- `crashes/dfa_eval_*` - DFA evaluation crashes
- `crashes/pattern_parse_*` - Pattern parser crashes

Files are named with LibFuzzer's artifact prefix convention.

## Expected Findings

| Fuzzer | Typical Bugs |
|--------|--------------|
| nfa_build_fuzzer | Parser segfaults, invalid input handling, NFA construction failures |
| dfa_eval_fuzzer | Buffer overflows, out-of-bounds reads, invalid state transitions |
| pattern_parse_fuzzer | Parser crashes, syntax validation failures |

## Known Issues

See `bug_report_nfa_builder.md` for documented crashes in `nfa_builder`:
- Single-byte inputs (`$`, `[`, `*`, `\xFF`) cause segfaults
- Root cause: Insufficient input validation
- Status: Unfixed (regression confirmed)

## File Structure

```
fuzz/
  Makefile                    # Build and run targets
  README.md                   # This file
  dfa_eval_fuzzer.cpp         # DFA eval fuzzer source
  pattern_parse_fuzzer.cpp    # Pattern parse fuzzer source
  nfa_build_fuzzer.cpp        # NFA build fuzzer source
  run_fuzzing_4h.sh           # 4-hour session runner
  run_in_cgroup.sh            # Cgroup memory limit wrapper
  memory_watchdog.sh          # Memory monitor (95% kill)
  generate_corpus.sh          # Corpus generator
  crashes/                    # Crash artifacts
  corpus/
    seed/                     # Seed corpus
      dfa_eval/
      pattern_parser/
    interesting/              # Coverage-increasing inputs
  logs/                       # Session logs
  bug_report_nfa_builder.md   # Documented bugs
```
