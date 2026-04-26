# Testgen - Test Pattern Generation

Generates test patterns for validating the DFA. Uses coordinated seeds + patterns to detect edge cases in pattern matching implementations.

## Build Commands

```bash
cd c-dfa/build && cmake --build . --target testgen
cd c-dfa/build && cmake --build . --target testgen_test
cd c-dfa/build && ./testgen/testgen_test
```

## Architecture

```
TestCase → PatternNode AST → Pattern String → DFA Validator
                ↓                                     ↓
        Factorization (AST rewriting)    PatternMatcher (NFA simulation)
                ↓                                     ↓
        Validation (pattern matching)    Pipeline API (in-process build+eval)
```

## Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `testgen.cpp` | 2700 | Core TestGenerator class, pattern validation cache, pipeline integration |
| `pattern_strategies.cpp` | 2989 | 23 pattern generation strategies |
| `pattern_factorization.cpp` | 2182 | Pattern AST rewriting |
| `edge_case_gen.cpp` | 280 | Edge case seed generation |
| `expectation_gen.cpp` | 564 | Expectation generation |
| `inductive_builder.cpp` | 740 | Constraint-propagating builder (prefix/suffix/length/char-class splitting) |
| `validation_helpers.cpp` | 196 | Pattern matching validators |
| `pattern_serializer.cpp` | 120 | PatternNode serialization |
| `command_utils.cpp` | 60 | Command execution utilities |
| `pattern_matcher.cpp` | 200 | NFA-based AST pattern matcher (replaces string-based `wouldInputMatchPattern`) |
| `testgen_core.cpp` | 90 | TestCaseCore with InputGraph |
| `testgen_operators.cpp` | 1700 | 15 coordinated mutation operators |
| `testgen_mutation_tree.cpp` | 230 | Mutation tree with coverage tracker |

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
| `testgen_pattern_matcher_test.cpp` | 40 | PatternMatcher NFA simulation tests |
| `testgen_pattern_matcher_fuzz.cpp` | 2500+ | Fuzz & regression tests |

**Total: 2720+ tests (213 unit + 2507 fuzz/regression)**

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

### TestCaseCore
New-style test case with InputGraph, ExpectationSet, and AST. Convertible to/from old TestCase.

## Key Components

### PatternMatcher (pattern_matcher.cpp/h)
NFA-based pattern matcher using set-of-positions tracking:
- `matches(pattern, input)` - Full-input match check
- `validate(pattern, matching, counter)` - Validate separating property
- `validateWithFragments(...)` - Validate with fragment definitions
- `explainFailure(...)` - Diagnostic failure explanation

### InductiveBuilder (inductive_builder.cpp)
Seven-strategy constraint-propagating builder:
1. Distinguishing prefix (multi-char)
2. Distinguishing char class
3. Single distinguishing char
4. Distinguishing suffix (multi-char)
5. Length-based partition
6. First-char partition
7. Fallback: flat alternation

### CoordinatedMutationEngine (testgen_operators.cpp)
15 mutation operators with PatternMatcher validation gate:
- CharSubstitute, AddAlternative, NestQuantifier, ExtendSequence
- DeepenNesting, SplitAlternation, ExtendAlternation, RemoveQuantifier
- AlterAlternative, FlattenQuantifiedAlt, UnwrapFragmentRef
- SequenceToAlternation, QuantifyAlternation, PrefixSuffixAlternation, CutBased

### Pipeline Integration
Uses `pipeline.h` API for in-process DFA build+eval instead of forking `cdfatool`:
- `validatePatternWithPipeline()` - Build DFA in-process and evaluate
- Eliminates process overhead for pattern validation

## Validation Cache
LRU-style cache (max 1024 entries) keyed by serialized pattern + inputs.
Avoids redundant NFA simulation for repeated validation of the same pattern.
