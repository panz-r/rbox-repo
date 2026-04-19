# C-DFA Tests

This directory contains all test-related files for the C-DFA project.

## Running Tests

```bash
# Configure and build
cmake -B build
cmake --build build

# Run all tests via CTest
ctest --test-dir build --output-on-failure

# Run specific tests
ctest --test-dir build -R dfa_test --output-on-failure
ctest --test-dir build -R test_library_api --output-on-failure
ctest --test-dir build -R test_eval_only --output-on-failure
```

## Test Executables

| Test | Description |
|------|-------------|
| `dfa_test` | Comprehensive test suite |
| `test_library_api` | Library API tests |
| `test_eval_only` | Eval-only functionality tests |
| `test_minimize_integrity` | Minimization integrity tests |
| `regression_test` | Regression tests |

## Test Sets

The `dfa_test` executable supports multiple test sets (A through U):

| Set | Name | Description |
|-----|------|-------------|
| A | Core Tests | Basic patterns, quantifiers, fragments, alternation |
| B | Expanded Tests | Complex patterns with nested quantifiers |
| C | Command Tests | Command categorization (admin, caution, modifying, dangerous, network) |
| D | Complex Patterns | Character classes, tripled patterns, hard edges |
| E | Command Core | caution, modifying, network command tests |
| F | Category Isolation | SAFE, CAUTION, NETWORK isolation tests |
| G | Edge Cases | Long chains, deep nesting, overlapping prefixes |
| H | Build Commands | Build tool commands (IDEs, compilers) |
| I | Container Commands | Container/runtime commands |
| J | Combined Patterns | Combined and minimal pattern tests |
| K | Simple Patterns | Simple quantifiers, step patterns, test patterns |
| L | SAT/Optimization | SAT-based optimization coverage |
| M | Minimization Comparison | Moore vs Hopcroft vs Brzozowski equivalence |
| N | Large-Scale Stress | Large pattern set stress testing |
| O | Binary Format Robustness | Corruption and invalid format handling |
| P | Limit/Boundary Config | max_states, max_symbols, preminimize settings |
| Q | Incremental Stage API | Individual pipeline stage functions and stats |
| R | Memory Failure Handling | Error handling for invalid inputs |
| S | Pattern Ordering Verification | Reordering effects and stats retrieval |
| T | Category Isolation | MODIFYING, BUILD, CONTAINER isolation tests |
| U | Category Isolation | DANGEROUS, ADMIN isolation tests |

Run specific test sets:
```bash
./build/tests/dfa_test --test-set A
./build/tests/dfa_test --test-set A --minimize-hopcroft
```

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
- `test_minimize_integrity.c` - Minimization integrity tests
- `test_library_api.c` - Library API tests
- `test_eval_only.c` - Eval-only tests
- `regression_test.c` - Regression tests
