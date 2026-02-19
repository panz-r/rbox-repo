# C-DFA Pattern Test Files

This directory contains pattern files used for testing the C-DFA system.

## Directory Structure

### basic/
Simple patterns for fundamental functionality testing:
- Minimal patterns for basic DFA construction
- Simple quantifiers and literals
- Step-by-step construction tests

### quantifiers/
Quantifier-related patterns (`+`, `*`, `?`):
- Isolated quantifier tests
- Quantifier combinations
- Edge cases with quantifiers

### alternation/
Alternation patterns (`|`):
- Simple alternations
- Complex multi-branch alternations
- Overlapping prefix tests

### captures/
Capture group patterns (`(...)`):
- Simple captures
- Nested captures
- HTTP-style captures

### commands/
Command category patterns:
- Safe commands
- Caution commands
- Modifying commands
- Dangerous commands
- Network commands
- Admin commands

### edge/
Edge cases and boundary conditions:
- Whitespace handling
- Deep nesting
- Long chains
- Character classes

### fragments/
Fragment definition and expansion tests:
- Fragment references
- Fragment interactions

## Pattern File Format

```
IDENTIFIER "test_name"

[fragment:name] value
[characterset:name] value
[category:subcategory:operations] pattern -> action

#ACCEPTANCE_MAPPING [category:subcategory:operations] -> N
```

## Usage

Patterns are processed by the test runner:

```bash
./dfa_test --test-set A patterns/stress_test.txt
```
