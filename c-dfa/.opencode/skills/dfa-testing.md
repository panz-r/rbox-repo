# DFA Testing (c-dfa)

**Scope:** c-dfa subproject only

---
name: dfa-testing-cdfa
description: Run and understand DFA tests in the c-dfa subproject, 36 pattern files with 313 test cases
license: MIT
兼容性: opencode
metadata:
  project: readonlybox
  component: c-dfa
  workflow: testing
  scope: c-dfa-subproject
---

## What I do

Run and understand DFA tests in the **c-dfa subproject**. Execute the test suite, interpret results, and debug test failures.

## Scope: c-dfa Subproject

All commands run from `c-dfa/` directory:

```
readonlybox/c-dfa/
├── patterns_*.txt       # 36 pattern files
├── src/
│   └── dfa_test.c       # Test runner (313 test cases)
└── Makefile
```

## Test Command

### Run All Tests

```bash
cd c-dfa
make test
```

This:
1. Validates all 36 pattern files
2. Builds DFA for each pattern file
3. Runs `dfa_test` binary with 313 test cases
4. Reports results per test group

### Test Output Example

```
=== CORE TESTS ===
Patterns: patterns_safe_commands.txt
  [PASS] git status matches
  [PASS] git log --oneline matches
  [FAIL] cat test.txt - got 'NO MATCH'
Result: 2/3 passed

=== QUANTIFIER TESTS ===
Patterns: patterns_quantifier_comprehensive.txt
  [PASS] a+ matches 'a'
  [PASS] a+ matches 'aa'
  [PASS] a* matches empty
Result: 3/3 passed

=================================================
SUMMARY: 131/313 passed
=================================================
```

## Pattern Files Tested (36 total)

| # | Category | File | Tests |
|---|----------|------|-------|
| 1 | Safe Commands | `patterns_safe_commands.txt` | Core patterns |
| 2 | Quantifier | `patterns_quantifier_comprehensive.txt` | Quantifier variants |
| 3 | Frag Quant | `patterns_frag_quant.txt` | Fragment quantifiers |
| 4 | Focused | `patterns_focused.txt` | Alternation |
| 5 | Simple | `patterns_simple.txt` | Boundary |
| 6 | Category | `patterns_acceptance_category_test.txt` | Category isolation |
| 7 | Frag Plus | `patterns_frag_plus.txt` | Fragment + patterns |
| 8 | Digit Test | `patterns_digit_test.txt` | Digits |
| 9 | Space Test | `patterns_space_test.txt` | Whitespace |
| 10 | Quantifier Test | `patterns_quantifier_test.txt` | Basic quantifiers |
| 11 | Exp Quant | `patterns_expanded_quantifier.txt` | Extended quantifiers |
| 12 | Exp Alternation | `patterns_expanded_alternation.txt` | Alternation |
| 13 | Exp Nested | `patterns_expanded_nested.txt` | Nested |
| 14 | Exp Fragment | `patterns_expanded_fragment.txt` | Fragment mix |
| 15 | Exp Boundary | `patterns_expanded_boundary.txt` | Boundary |
| 16 | Exp Interact | `patterns_expanded_interactions.txt` | Quantifier interactions |
| 17 | Exp Mixed | `patterns_expanded_mixed.txt` | Literal/fragment |
| 18 | Exp Hard | `patterns_expanded_hard.txt` | Edge cases |
| 19 | Exp Perf | `patterns_expanded_perf.txt` | Performance |
| 20 | Admin | `patterns_admin_commands.txt` | Admin commands |
| 21 | Caution | `patterns_caution_commands.txt` | Caution commands |
| 22 | Modifying | `patterns_modifying_commands.txt` | File modification |
| 23 | Dangerous | `patterns_dangerous_commands.txt` | Dangerous ops |
| 24 | Network | `patterns_network_commands.txt` | Network |
| 25 | Combined | `patterns_combined.txt` | Multi-category |
| 26 | Minimal | `patterns_minimal.txt` | Basic patterns |
| 27 | Quant Simple | `patterns_quantifier_simple.txt` | Simple quantifiers |
| 28 | Simple Quant | `patterns_simple_quant.txt` | Quantifier tests |
| 29 | Step 1-3 | `patterns_step*.txt` | Step patterns |
| 30 | Test | `patterns_test.txt` | Test patterns |
| 31 | Debug | `patterns_debug.txt` | Debug patterns |
| 32 | With Captures | `patterns_with_captures.txt` | Captures |
| 33 | Capture Simple | `patterns_capture_simple.txt` | Simple captures |
| 34 | Capture Test | `patterns_capture_test.txt` | Capture tests |

**Total: 36 pattern files, 313 test cases**

## Interpreting Results

### Passing Test

```
[PASS] git status matches
```

Test matched correctly.

### Failing Test

```
[FAIL] cat test.txt - got 'NO MATCH' (len=0, cat=0x00)
```

Test did not match as expected. Format:
- `[FAIL]` - test failed
- Description
- `got 'MATCH'` or `got 'NO MATCH'`
- `(len=X, cat=0xXX)` - matched length and category mask

### Category Mask Values

| Value | Category |
|-------|----------|
| 0x01 | safe |
| 0x02 | caution |
| 0x04 | modifying |
| 0x08 | dangerous |
| 0x10 | network |
| 0x20 | admin |

## Debugging Test Failures

### 1. Find Failing Tests

```bash
make test 2>&1 | grep -E "FAIL|Result:"
```

### 2. Validate Pattern File

```bash
./tools/nfa_builder --validate-only <failing_pattern_file>
```

### 3. Check Pattern Exists

```bash
grep "expected_pattern" patterns_safe_commands.txt
```

### 4. Rebuild and Re-test

```bash
make clean
make test
```

### 5. Verbose DFA Evaluation

Modify `src/dfa_eval.c` to enable `DFA_EVAL_DEBUG`:

```c
#define DFA_EVAL_DEBUG 1
```

Then rebuild and run tests.

## Test Categories

### Pattern Matching Tests

Verify patterns match expected inputs:
```bash
[safe] git status  # Should match "git status"
```

### Category Tests

Verify correct category assignment:
```bash
[safe] git status  # Should have cat=0x01
[caution] curl *   # Should have cat=0x02
```

### Boundary Tests

Verify edge cases:
```bash
[a]+ matches 'a'      # Single match
[a]+ matches 'aaa'    # Multiple matches
[a]+ should NOT match empty
```

### Quantifier Tests

Verify quantifier behavior:
```bash
a((b))+ matches 'ab'      # Plus quantifier
a((b))* matches ''        # Star quantifier (empty)
a((b))? matches 'a'       # Question quantifier
```

## When to Use Me

Use this skill when:
- Running DFA tests in c-dfa
- Debugging test failures
- Understanding test coverage
- Adding new test cases
- Verifying pattern changes
