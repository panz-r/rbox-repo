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
# Comments start with #

[fragment:name] pattern definition

[category] command pattern
```

## Categories

| Category | Description |
|----------|-------------|
| safe | Read-only, no side effects |
| caution | Minor side effects |
| modifying | Modifies files |
| dangerous | Destructive |
| network | Network operations |
| admin | Requires privileges |

## Example Pattern File

```
[safe] cat *
[safe] grep * *
[dangerous] rm *
[network] curl *
```

## Building a DFA from Patterns

```bash
# Build tools first
cmake -B build && cmake --build build

# Build NFA from patterns
./build/tools/nfa_builder patterns/commands/safe_commands.txt readonlybox.nfa

# Convert to minimized DFA
./build/tools/nfa2dfa_advanced --minimize-hopcroft readonlybox.nfa readonlybox.dfa
```
