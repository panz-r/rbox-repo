# C-DFA Tests

This directory contains all test-related files for the C-DFA project.

## Directory Structure

### test_data/
Generated test artifacts:
- `.nfa` files - NFA representations
- `.dfa` files - Compiled DFA binaries
- `.txt` files - Pattern test inputs

### scripts/
Test execution scripts:
- `run_tests.sh` - Main test runner
- `run_quantifier_tests.sh` - Quantifier-specific tests
- `trace_structure.sh` - Structure debugging

### Root
Test source code:
- `test_sat_encoding.cpp` - SAT encoding tests
- `test_capture_e2e.c` - End-to-end capture tests
- `test_minimize_integrity.c` - Minimization integrity tests

## Running Tests

```bash
# From c-dfa root directory
make test

# Run specific test set
./dfa_test --test-set A patterns/stress_test.txt

# Run with specific minimization algorithm
./dfa_test --test-set A --minimize-hopcroft
```

## Test Sets

- **A**: Core tests (basic patterns, quantifiers, fragments, alternation)
- **B**: Expanded tests (complex patterns with nested quantifiers)
- **C**: Command tests (admin, caution, modifying, dangerous, network commands)

## Adding New Tests

1. Create pattern file in `patterns/` directory
2. Add test case to `src/dfa_test.c`
3. Run `make test` to verify
