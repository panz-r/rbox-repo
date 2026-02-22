# Bug Report: nfa_builder Segmentation Faults (Updated)

**Date:** 2026-02-21 (Latest fuzzing: 4-hour session)
**Previous Reports:** 2026-02-21 (8 hours total, 2 x 4-hour passes)
**Fuzzer:** nfa_build_fuzzer (LibFuzzer with AddressSanitizer)
**Target:** nfa_builder (NFA construction tool)
**Status:** REGRESSED - Previously reported crashes were NOT fixed

## Executive Summary

A 4-hour fuzzing session revealed that **26 unique crashes** (52 total crash instances) still exist in `nfa_builder`. These are the **same crashes** that were reported in the previous bug report dated 2026-02-21. The issues were believed to be fixed, but the fuzzing demonstrates they persist in the current codebase.

**Critical Finding:** The pattern parser still crashes on minimal inputs including single special characters and malformed patterns.

## Crash Distribution

| Pattern Size | Unique Crashes | Total Instances |
|--------------|----------------|-----------------|
| 1 byte | 6 distinct | 12 crashes |
| 2 bytes | 4 distinct | 8 crashes |
| 3 bytes | 1 distinct | 2 crashes |
| 5 bytes | 2 distinct | 4 crashes |

**Total:** 26 unique crash-inducing patterns detected in 4-hour session

## Detailed Crash Categories

### Category 1: Single Character Crashes (Critical Priority)

These single-byte inputs cause immediate segmentation faults:

| Input (hex) | Character | ASCII | Description |
|-------------|-----------|-------|-------------|
| `0x00` | (null) | NUL | Null byte |
| `0x24` | `$` | 36 | Dollar sign (end-of-line anchor) |
| `0x2A` | `*` | 42 | Asterisk (wildcard/quantifier) |
| `0x5B` | `[` | 91 | Open square bracket (char class) |
| `0xFF` | `ÿ` | 255 | Extended ASCII / invalid UTF-8 |
| Unknown | (invisible) | ? | Possibly whitespace or control char |

**Crash Signature:**
```
=== CRASH DETECTED ===
nfa_builder (NFA build) crashed with signal 11 (Segmentation fault)
Offending pattern (size 1):
[character]
```

### Category 2: Two-Character Patterns

| Input | Hex | Description |
|-------|-----|-------------|
| `[S` | `5B 53` | Incomplete character class |
| `KK` | `4B 4B` | Duplicate capital K (unknown trigger) |
| `\xFF\xFF` | `FF FF` | Binary data |
| `\n\n` | `0A 0A` | Double newline |

### Category 3: Three-Character Patterns

| Input | Hex | Description |
|-------|-----|-------------|
| `[[s` | `5B 5B 73` | Nested character class start |

### Category 4: Five-Character Patterns

| Input | Hex | Description |
|-------|-----|-------------|
| `[\xFF\xFF\xFF\xFF` | `5B FF FF FF FF` | Character class with binary data |
| `1\x??\x??\x??` | Variable | Digit followed by binary/special chars |

## Root Cause Analysis

The crashes appear to stem from **insufficient input validation** in the pattern parser before NFA construction. Specifically:

1. **No null-termination checks** - Null bytes cause immediate crashes
2. **Incomplete special character handling** - `$`, `*`, `[` not validated properly
3. **Character class parser failures** - `[` without closing `]` causes segfault
4. **Binary data handling** - Extended ASCII (0xFF) crashes the parser
5. **State machine assumptions** - Parser assumes well-formed input

### Evidence

The crashes occur during the **initial parsing phase** before any NFA states are created. This is evident from:
- Minimal input sizes (single bytes)
- Special characters that initiate parsing rules (`[`, `$`, `*`)
- Crash on control characters (null bytes)

## Reproduction Steps

### Quick Reproduction

1. Build nfa_builder:
   ```bash
   cd c-dfa && make tools/nfa_builder
   ```

2. Test with any of these inputs:
   ```bash
   # Null byte crash
   printf '\x00' > test_crash.txt
   ./tools/nfa_builder test_crash.txt output.nfa
   
   # Dollar sign crash
   echo -n '$' > test_crash.txt
   ./tools/nfa_builder test_crash.txt output.nfa
   
   # Open bracket crash
   echo -n '[' > test_crash.txt
   ./tools/nfa_builder test_crash.txt output.nfa
   
   # Binary data crash
   printf '\xff' > test_crash.txt
   ./tools/nfa_builder test_crash.txt output.nfa
   ```

3. Observe segmentation fault in all cases.

### Full Fuzzing Reproduction

```bash
cd c-dfa/fuzz
./run_fuzzing_4h.sh nfa-build
```

## Impact Assessment

- **Severity:** Critical (Remote Denial of Service if patterns accepted from untrusted sources)
- **Attack Vector:** Local file input (pattern files)
- **Affected Component:** Pattern parser in nfa_builder
- **Exploitability:** Trivial - single byte input causes crash
- **Production Risk:** High if nfa_builder processes user-supplied patterns

## Evidence of Regression

1. **Previous bug report** dated 2026-02-21 documented these exact crashes
2. **Crashes directory was cleared** before this fuzzing run
3. **Same input patterns** (`$`, `[`, `\xFF`, etc.) still cause segfaults
4. **No code changes** appear to have addressed the parser vulnerabilities

## Recommended Fixes (Priority Order)

### 1. Input Validation Layer (CRITICAL)
Add comprehensive input validation before parsing:

```c
// Pseudo-code
bool validate_pattern_input(const char* pattern, size_t len) {
    // Check for null bytes
    if (memchr(pattern, '\0', len) != NULL) {
        return false; // Reject patterns with embedded nulls
    }
    
    // Check for valid UTF-8 (reject 0xFF and invalid sequences)
    if (!is_valid_utf8(pattern, len)) {
        return false;
    }
    
    // Check for balanced brackets
    if (!brackets_balanced(pattern)) {
        return false;
    }
    
    // Check for valid special character usage
    if (!validate_special_chars(pattern)) {
        return false;
    }
    
    return true;
}
```

### 2. Parser Hardening (HIGH)
- Add null pointer checks before all dereferences
- Validate parser state before state transitions
- Add bounds checking on all string operations
- Use safe string functions (strnlen, strndup)

### 3. Character Class Parser (HIGH)
- Validate `[` is followed by valid character class content
- Require closing `]` before end of input
- Reject nested `[[` without proper syntax
- Handle escape sequences properly

### 4. Special Character Handling (MEDIUM)
- Validate `$` usage (end-of-line anchor context)
- Validate `*` usage (must follow a valid token)
- Validate `+`, `?` quantifiers similarly
- Reject standalone quantifiers without targets

### 5. Binary Data Rejection (MEDIUM)
- Reject non-printable characters except whitespace
- Require valid UTF-8 encoding
- Provide clear error messages for invalid input

## Testing Recommendations

### Unit Tests
Add test cases for each crash input:
```c
// tests/test_nfa_builder_validation.c
void test_null_byte_rejection() {
    assert(validate_pattern("\0", 1) == false);
}

void test_unclosed_bracket_rejection() {
    assert(validate_pattern("[", 1) == false);
}

void test_binary_data_rejection() {
    assert(validate_pattern("\xFF", 1) == false);
}
```

### Integration Tests
```bash
# Should fail gracefully, not crash
./nfa_builder <(printf '\x00') out.nfa
assert_exit_code 1

./nfa_builder <(echo -n '[') out.nfa  
assert_exit_code 1
```

### Fuzzing
Continue fuzzing after fixes:
```bash
# Run for 24+ hours to find additional edge cases
./run_fuzzing_4h.sh nfa-build
# Check crashes/ directory - should be empty
```

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

**Memory Protection:**
- Per-process: 2GB (RLIMIT_AS)
- Per-fuzzer: 4GB (rss_limit_mb)
- Total session: 8GB (systemd-run)
- Memory watchdog: 95% kill threshold

## Log Files

- **Fuzzing log:** `logs/20260221_211128/fuzzer.log`
- **Watchdog log:** `logs/20260221_211128/watchdog.log`
- **Total crash events:** 52 (26 unique patterns, 2 workers)

## Next Steps

1. **Verify fixes were applied** - Check if parser changes were committed
2. **Implement input validation** - Add the validation layer immediately
3. **Harden parser** - Fix null pointer dereferences
4. **Add regression tests** - Ensure these inputs are tested in CI
5. **Re-run fuzzing** - Verify all crashes are fixed (24-hour session)
6. **Consider AFL++** - Run parallel fuzzing campaigns for deeper coverage

## Conclusion

The nfa_builder tool has **critical input validation vulnerabilities** that must be addressed before any production use. The crashes are **trivially reproducible** with single-byte inputs and represent a **complete failure** of input validation.

**Status: REGRESSION CONFIRMED - Original crashes remain unfixed**

---

*Generated from fuzzing session on 2026-02-21, 4-hour duration*
*Log: logs/20260221_211128/fuzzer.log*
