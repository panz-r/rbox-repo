# Test Organization for ReadOnlyBox DFA

## Core Principle

**`patterns_safe_commands.txt` is for PRODUCTION patterns ONLY.**

This file contains patterns that will be deployed to readonlybox clients. It must only contain real, usable command patterns.

## Pattern File Organization

### Production Patterns (DEPLOYED)
- **File**: `patterns_safe_commands.txt`
- **Purpose**: Patterns for production deployment
- **Must contain**: Only real, usable command whitelisting patterns
- **Examples**: `git status`, `git log -n ((safe::digit))`, `ls *`

### Test Patterns (LOCAL TESTING ONLY)
- **Files**:
  - `patterns_quantifier_comprehensive.txt` - Quantifier testing
  - `patterns_quantifier_test.txt` - Basic quantifier tests
  - `patterns_acceptance_category_test.txt` - Category isolation tests
  - `patterns_focused.txt` - Focused test cases
- **Purpose**: NFA/DFA functionality testing
- **Never deployed**: These files are for local development/testing only

## Test Categories

### Core Tests (Production DFA)
- Test patterns that exist in `patterns_safe_commands.txt`
- Run against `readonlybox.dfa` (built from production patterns)
- **Must all pass** before deployment
- Located: `dfa_test.c` - functions prefixed with `test_dfa_init`, `test_simple_*`, etc.

### Expanded Tests (Test DFA Required)
- Test NFA/DFA functionality with edge cases
- Require building a separate DFA from test pattern files
- Located: `dfa_test.c` - functions `test_expanded_*`, `test_nfa_dfa_comprehensive`
- **Expected behavior**: These tests will FAIL against production DFA

### Tripled Tests (Stress Testing)
- Extensive edge case coverage (1000+ tests)
- Require test DFA
- Located: `dfa_test_tripled.c`
- **Expected behavior**: Will FAIL against production DFA

## Building Test DFAs

### Build Test DFA for Quantifier Testing
```bash
cd c-dfa
mkdir -p build_test
cd build_test
../tools/nfa_builder ../patterns_quantifier_comprehensive.txt test.nfa
../tools/nfa2dfa_advanced test.nfa test.dfa
cp test.dfa ../src/test_quantifier.dfa
```

### Build Test DFA for All Tests
```bash
cd c-dfa
mkdir -p build_all
cd build_all
# Create a combined pattern file with all test patterns
cat ../patterns_*.txt > all_test_patterns.txt
../tools/nfa_builder all_test_patterns.txt test.nfa
../tools/nfa2dfa_advanced test.nfa test.dfa
```

## Running Tests

### Production Tests Only (Should Pass)
```bash
cd c-dfa
make dfa
cp build/readonlybox.dfa .
./dfa_test
```

### All Tests (Includes Expected Failures)
```bash
cd c-dfa
# Build test DFA first
mkdir -p build_test
cd build_test
../tools/nfa_builder ../patterns_quantifier_comprehensive.txt test.nfa
../tools/nfa2dfa_advanced test.nfa test.dfa

# Copy to src as test.dfa
cp test.dfa ../src/test_quantifier.dfa

# Build and run with test DFA
cd ..
gcc -Iinclude -O2 -o test_with_dfa src/test_with_quantifier_dfa.c src/dfa_loader.c src/dfa_eval.c -lm
./test_with_dfa
```

## Summary

| Test Type | Pattern Source | Expected Result |
|-----------|---------------|-----------------|
| Core | `patterns_safe_commands.txt` | ALL PASS |
| Expanded | Test pattern files | FAIL (requires test DFA) |
| Tripled | Test pattern files | FAIL (requires test DFA) |

## Never Add to `patterns_safe_commands.txt`

- Test patterns like `(a|b)+`, `a+`, `a*`
- Debug patterns like `alpha`, `beta`
- Edge case patterns for stress testing
- Patterns with comments like "This is for testing"

If you need a pattern for testing, add it to an appropriate `patterns_*.txt` file, NOT to `patterns_safe_commands.txt`.
