# TEST-SUITE Skill

**Scope:** Full project + c-dfa subproject

---
name: test-suite
description: Understand ReadOnlyBox test architecture and run specific test groups in c-dfa
license: MIT
compatibility: opencode
metadata:
  project: readonlybox
  component: testing
  workflow: testing
  scope: full-project
---

## What I do

Explain the test architecture of the **full ReadOnlyBox project**, mapping pattern files to test groups in the c-dfa subproject.

## Scope: Full Project + c-dfa Subproject

This skill covers **both** the full project test suite and individual c-dfa tests:

```
readonlybox/                    ← FULL PROJECT SCOPE
├── c-dfa/                      ← c-dfa SUBPROJECT (see c-dfa/.opencode/skills/)
│   ├── patterns_safe_commands.txt     # Pattern file 1
│   ├── patterns_quantifier_*.txt      # Pattern files 2-34
│   ├── Makefile                      # c-dfa test commands
│   └── src/dfa_test.c                # DFA test code
├── test/                     ← FULL PROJECT TESTS
│   └── integration_test.go
└── Magefile.go                ← Full project orchestration
```

## c-dfa Subproject Skills

For c-dfa-specific testing tasks, use these skills:

- **dfa-testing-cdfa** - Run DFA tests, understand 36 pattern files
- **dfa-debugging-cdfa** - Debug test failures
- **patterns-cdfa** - Understand pattern syntax

## Key Distinction

| Command | Scope | Runs |
|---------|-------|------|
| `cd c-dfa && make test` | c-dfa | All 36 pattern files, 313 test cases |
| `mage test` | full-project | Runs `make test` in c-dfa + Go tests |

mage delegates to `make test` for c-dfa testing.

## Running Tests

### Run DFA Tests (c-dfa)

```bash
cd c-dfa
make test          # Runs all 36 pattern files with 313 test cases
```

### Run Full Project Tests (mage)

```bash
mage test          # Delegates to `make test` in c-dfa, then runs Go tests
mage unitTest      # Go unit tests only
mage integrationTest  # Integration tests only
```

### Check Test Results

```bash
make test 2>&1 | grep -E "SUMMARY:|passed|failed"
```

### Run Full Project Tests

```bash
mage test
```

## Test Architecture Overview

```
make test (in c-dfa/)
├── Validates all pattern files (36 files)
├── Builds NFA/DFA for each pattern file
└── Runs dfa_test binary with 313 test cases
```

## Pattern Files Tested (36 total)

| # | Category | Pattern File | Tests |
|---|----------|--------------|-------|
| 1 | Safe Commands | `patterns_safe_commands.txt` | Core safe patterns |
| 2 | Quantifier | `patterns_quantifier_comprehensive.txt` | Quantifier patterns |
| 3 | Fragments | `patterns_frag_quant.txt` | Fragment quantifiers |
| 4 | Focused | `patterns_focused.txt` | Alternation tests |
| 5 | Simple | `patterns_simple.txt` | Boundary tests |
| 6 | Category | `patterns_acceptance_category_test.txt` | Category isolation |
| 7 | Frag Plus | `patterns_frag_plus.txt` | Fragment + patterns |
| 8 | Digit Test | `patterns_digit_test.txt` | Digit patterns |
| 9 | Space Test | `patterns_space_test.txt` | Whitespace handling |
| 10 | Quantifier Test | `patterns_quantifier_test.txt` | Basic quantifiers |
| 11 | Expanded Quant | `patterns_expanded_quantifier.txt` | Extended quantifiers |
| 12 | Expanded Alt | `patterns_expanded_alternation.txt` | Alternation patterns |
| 13 | Expanded Nested | `patterns_expanded_nested.txt` | Nested patterns |
| 14 | Expanded Frag | `patterns_expanded_fragment.txt` | Fragment interactions |
| 15 | Expanded Boundary | `patterns_expanded_boundary.txt` | Boundary conditions |
| 16 | Expanded Interact | `patterns_expanded_interactions.txt` | Quantifier interactions |
| 17 | Expanded Mixed | `patterns_expanded_mixed.txt` | Literal/fragment mix |
| 18 | Expanded Hard | `patterns_expanded_hard.txt` | Edge cases |
| 19 | Expanded Perf | `patterns_expanded_perf.txt` | Performance stress |
| 20 | Admin Commands | `patterns_admin_commands.txt` | Admin patterns |
| 21 | Caution Commands | `patterns_caution_commands.txt` | Caution patterns |
| 22 | Modifying | `patterns_modifying_commands.txt` | File modification |
| 23 | Dangerous | `patterns_dangerous_commands.txt` | Dangerous ops |
| 24 | Network | `patterns_network_commands.txt` | Network operations |
| 25 | Combined | `patterns_combined.txt` | Multi-category |
| 26 | Minimal | `patterns_minimal.txt` | Basic patterns |
| 27 | Quant Simple | `patterns_quantifier_simple.txt` | Simple quantifiers |
| 28 | Simple Quant | `patterns_simple_quant.txt` | Quantifier tests |
| 29 | Step 1-3 | `patterns_step1.txt`, `patterns_step2.txt`, `patterns_step3.txt` | Step patterns |
| 30 | Test | `patterns_test.txt` | Test patterns |
| 31 | Debug | `patterns_debug.txt` | Debug patterns |
| 32 | With Captures | `patterns_with_captures.txt` | Capture groups |
| 33 | Capture Simple | `patterns_capture_simple.txt` | Simple captures |
| 34 | Capture Test | `patterns_capture_test.txt` | Capture tests |

## Pattern File to Test Mapping

### patterns_safe_commands.txt

Used by: **Main Safe Commands** test group

Contains: Production safe patterns

```bash
[safe:readonly:git] git status
[safe:readonly:file] cat *
[safe] git log --oneline
```

Expected tests:
- `which socat` - system binary lookup
- `git status` - git status
- `cat *` - file reading with wildcard
- `git log --oneline` - git log variant

### patterns_quantifier_test.txt

Used by: **Quantifier Tests** group

Contains: Basic quantifier patterns

```bash
[safe:quantifier:group1] a((b))+
[caution:network:quant2] abc((b))+
```

Tests: Plus quantifier on single-char fragments

### patterns_quantifier_comprehensive.txt

Used by: **Comprehensive Quantifier** group

Contains: 40+ pattern groups covering:
- Quantifiers: `+`, `*`, `?`
- Character classes
- POSIX classes
- Alternation
- Escape sequences
- Wildcards
- Nested patterns

### patterns_with_captures.txt

Used by: **Capture Patterns** group

Contains: Patterns with capture tags

```bash
[safe] cat <filename>((FILENAME))</filename>
[safe] git log -n <count>((DIGIT))+</count>
```

### patterns_dangerous_commands.txt

Used by: **Dangerous Commands** (negative tests)

Contains: Patterns that should NOT match

```bash
[unsafe] rm -rf *
[unsafe] chmod 777
```

### patterns_space_test.txt

Used by: **Space Handling** group

Contains: Whitespace normalization tests

### patterns_digit_test.txt

Used by: **Digit Specificity** group

Contains: Digit pattern tests

### patterns_acceptance_category_test.txt

Used by: **Acceptance Categories** group

Contains: Category isolation tests

```bash
[safe:readonly:quant1] a((b))+
[caution:network:quant2] abc((b))+
```

Tests: Different categories don't interfere

## Running Specific Tests

### Run Only DFA Tests (c-dfa)

```bash
cd c-dfa
make test          # Runs all 36 pattern files with 313 test cases
```

### Check Test Results

```bash
make test 2>&1 | grep -E "SUMMARY:|passed|failed"
```

## Expected Test Counts

| Category | Pattern Files | Test Cases |
|----------|---------------|------------|
| Core Patterns | 5 | ~77 |
| Quantifiers | 6 | ~60 |
| Expanded Tests | 8 | ~80 |
| Command Categories | 6 | ~50 |
| Captures | 3 | ~20 |
| Steps/Debug | 8 | ~26 |
| **Total** | **36** | **313** |

## Test Output Interpretation

### Passing Test

```
Test: Git Log Variants
  [PASS] git log --oneline matches
  [PASS] git log --graph matches
  [PASS] git log -n 10 matches
```

### Failing Test

```
Test: Git Log Variants
  [FAIL] git log --oneline matches
```

**Action:** Pattern may be missing from patterns_safe_commands.txt

### Validation Error (Stops Test Group)

```
Validating: patterns_safe_commands.txt
[FAIL] Line 50: Fragment 'x' not defined
Skipping Main Safe Commands due to pattern validation error
```

**Action:** Fix validation error first

## Expected Test Counts

| Test Group | Expected Passing |
|------------|-----------------|
| Main Safe Commands | 77/77 |
| Quantifier Tests | 16/16 |
| Comprehensive Quantifier | Varies |
| Negative Patterns | 14/14 |
| Space Handling | 13/13 |
| Digit Specificity | 12/12 |
| Acceptance Categories | 25/25 |

## Debugging Test Failures

### 1. Check Which Tests Failed

```bash
make test 2>&1 | grep -E "FAIL|Result:"
```

### 2. Validate Pattern File

```bash
cd c-dfa
./tools/nfa_builder --validate-only <failing_pattern_file>
```

### 3. Check Pattern Exists

```bash
grep "expected_pattern" patterns_safe_commands.txt
```

### 4. Rebuild DFA

```bash
cd c-dfa
make clean
make dfa
```

### 5. Re-run Tests

```bash
make test
```

## Test File Locations

```
readonlybox/
├── c-dfa/
│   ├── patterns_safe_commands.txt       # Production
│   ├── patterns_quantifier_test.txt      # Quantifier tests
│   ├── patterns_quantifier_comprehensive.txt  # Comprehensive
│   ├── patterns_with_captures.txt       # Captures
│   ├── patterns_dangerous_commands.txt   # Negative
│   ├── patterns_space_test.txt          # Whitespace
│   ├── patterns_digit_test.txt           # Digits
│   ├── patterns_acceptance_category_test.txt  # Categories
│   └── src/dfa_test.c                   # Test code
└── test/
    └── integration_test.go               # Integration tests
```

## When to Use Me

Use this skill when:
- Understanding test structure
- Running specific test groups
- Debugging test failures
- Adding new test patterns
- Mapping patterns to tests
