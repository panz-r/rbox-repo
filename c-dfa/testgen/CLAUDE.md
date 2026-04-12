# Testgen - Test Pattern Generation

Generates test patterns for validating the DFA. Uses coordinated seeds + patterns to detect edge cases in pattern matching implementations.

## Build Commands

```bash
cd c-dfa/testgen && make
cd c-dfa/testgen && make test
cd c-dfa/testgen && make clean
```

## Architecture

```
TestCase → PatternNode AST → Pattern String → DFA Validator
                ↓
        Factorization (AST rewriting)
                ↓
        Validation (pattern matching)
```

## Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `testgen.cpp` | 2172 | Core TestGenerator class |
| `pattern_strategies.cpp` | 2989 | 30 pattern generation strategies |
| `pattern_factorization.cpp` | 2182 | Pattern AST rewriting |
| `edge_case_gen.cpp` | 280 | Edge case seed generation |
| `expectation_gen.cpp` | 564 | Expectation generation |
| `inductive_builder.cpp` | 191 | Constraint-propagating builder |
| `validation_helpers.cpp` | 196 | Pattern matching validators |
| `pattern_serializer.cpp` | 114 | PatternNode serialization |
| `command_utils.cpp` | 49 | Command execution utilities |

## Test Files

| File | Tests | Purpose |
|------|-------|---------|
| `testgen_test.cpp` | 14 | Main test runner |
| `testgen_factorization_test.cpp` | 20 | Factorization tests |
| `testgen_validation_test.cpp` | 48 | Validation helper tests |
| `testgen_strategies_test.cpp` | 30 | Strategy tests |
| `testgen_expectation_test.cpp` | 27 | Expectation tests |
| `testgen_inductive_builder_test.cpp` | 13 | Inductive builder tests |
| `testgen_serializer_test.cpp` | 21 | Serializer tests |

**Total: 173 passing unit tests**

## Key Types

### PatternNode
AST node with type, value, children, quantified child, matched_seeds, counter_seeds, and capture tags.

### PatternType
- `LITERAL` - Plain string
- `OPTIONAL` - X?
- `PLUS_QUANTIFIER` - X+
- `STAR_QUANTIFIER` - X*
- `ALTERNATION` - X|Y|Z
- `FRAGMENT_REF` - Fragment reference
- `SEQUENCE` - Concatenation

### TestCase
Contains pattern, category, matching/counter inputs, fragments, complexity, proof, and expectations.

## Extracted Modules

### PatternFactorization (pattern_factorization.cpp)
AST rewriting operations:
- `factorPattern` - Factor alternations by common prefix/suffix
- `applyRandomStars` - Insert random * quantifiers
- `applyComplexRewrites` - Complex pattern rewrites
- `copyPatternNode` - Deep copy AST

### ValidationHelpers (validation_helpers.cpp)
Pattern matching validators:
- `patternMatchesLiteral`
- `patternMatchesOptional`
- `patternMatchesPlus`
- `patternMatchesStar`
- `patternMatchesCharClass`
- `createQuantified*` factory functions

### PatternSerializer (pattern_serializer.cpp)
- `serializePattern` - Convert PatternNode to string

### CommandUtils (command_utils.cpp)
- `runCommand` - Execute command and capture output
- `getToolsDir` - Find tools directory

### EdgeCaseGen (edge_case_gen.cpp)
Edge case generators:
- `RANGE_BOUNDARY` - Consecutive chars at boundaries
- `PARTIAL_MATCH_FAIL` - Prefix matches, then fails
- `QUANTIFIER_EDGE` - Empty, single, multiple
- `ALTERNATION_EDGE` - Some alternatives match
- `NESTED_QUANTIFIER` - Nested quantifiers

## Refactoring History

1. Extracted `pattern_factorization.cpp/h` (~2200 lines)
2. Extracted `validation_helpers.cpp/h` (~200 lines)
3. Extracted `pattern_serializer.cpp/h` (~120 lines)
4. Extracted `command_utils.cpp/h` (~50 lines)
5. Extracted `edge_case_gen.cpp/h` (~280 lines)
6. Removed dead `generated_tests` member
7. Removed dead static constants (COMMANDS, FLAGS, FILE_EXTS, FRAGMENTS)
8. Removed unused `PatternComponent` struct

## Remaining Large Files

- `pattern_strategies.cpp` (2989 lines) - 30 strategies with high cross-dependency, difficult to split further without significant redesign
- `pattern_factorization.cpp` (2182 lines) - Already extracted, contains 12 related factorization operations
