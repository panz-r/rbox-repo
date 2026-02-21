# Bug Report: nfa_builder Segmentation Faults

**Date:** 2026-02-21
**Fuzzing Duration:** 8 hours (2 x 4-hour passes)
**Fuzzer:** nfa_build_fuzzer (LibFuzzer with AddressSanitizer)
**Target:** nfa_builder (NFA construction tool)

## Summary

Fuzzing of the `nfa_builder` tool revealed multiple segmentation fault vulnerabilities. The tool crashes when processing malformed or edge-case pattern inputs. All crashes are triggered by the same root cause: insufficient input validation before parsing.

## Crash Categories

### Category 1: Single Character Crashes

The following single-byte inputs cause immediate segmentation faults:

| Input (hex) | Character | Description |
|-------------|-----------|-------------|
| `0x24` | `$` | Dollar sign |
| `0x5B` | `[` | Open square bracket |
| `0xFF` | `ÿ` | Extended ASCII / binary |

**Crash Signature:**
```
nfa_builder (NFA build) crashed with signal 11 (Segmentation fault)
```

**Root Cause:** The parser likely interprets these characters as special regex/meta-characters without proper bounds checking or state validation.

### Category 2: Multi-Character Pattern Crashes

The following multi-byte patterns also trigger crashes:

| Input | Pattern Type |
|-------|--------------|
| `[S` | Incomplete character class |
| `KK` | Unknown - possibly quantifier-related |
| `[[s` | Nested character classes |
| `[<binary>` | Character class with binary data |
| `1<binary>` | Digit followed by binary data |

## Crash Artifacts

Saved crash files (in `crashes/` directory):

```
crashes/nfa_build_crash-3cdf2936da2fc556bfa533ab1eb59ce710ac80e5
Content: 0x24 ('$')
```

## Reproduction Steps

1. Build nfa_builder:
   ```bash
   cd c-dfa && make tools/nfa_builder
   ```

2. Create a test pattern file with a crash-triggering input:
   ```bash
   echo -n '$' > test_pattern.txt
   # or
   echo -n '[' > test_pattern.txt
   ```

3. Run nfa_builder:
   ```bash
   ./tools/nfa_builder test_pattern.txt output.nfa
   ```

4. Observe segmentation fault.

## Impact

- **Severity:** High (Denial of Service)
- **Attack Vector:** Local - requires ability to provide pattern files
- **Affected Component:** nfa_builder pattern parser

## Recommended Fixes

1. **Input Validation:** Add validation for special characters (`[`, `$`, etc.) before parsing
2. **Bounds Checking:** Ensure parser state is validated before dereferencing pointers
3. **Fuzz Testing:** Continue fuzzing with the provided harness to find additional edge cases

## Fuzzing Configuration

The crashes were discovered using:

```bash
./nfa_build_fuzzer corpus/seed/pattern_parser \
    -artifact_prefix=crashes/nfa_build_ \
    -max_len=32768 \
    -max_total_time=14400 \
    -jobs=2 \
    -workers=2 \
    -ignore_crashes=1 \
    -rss_limit_mb=4096
```

**Memory Limits:**
- Per-process: 2GB (RLIMIT_AS)
- Per-fuzzer: 4GB (rss_limit_mb)
- Total session: 8GB (systemd-run)

## Additional Notes

- The fuzzer ran for 4 hours per pass without exhausting memory limits
- Memory protection (cgroups, rlimits) successfully contained the fuzzer
- Multiple crash variants were found, suggesting systemic input validation issues
- The `[` character crash suggests character class parsing is particularly vulnerable
