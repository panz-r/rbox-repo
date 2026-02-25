# TestGen - Grammar-based Test Case Generator for c-dfa

Generates pattern files with expectations from an abstract grammar. Works backwards from expectations to create testable patterns.

## How It Works

The generator uses a **backwards synthesis** approach:

1. **Select expectations**: Choose what the pattern should match
2. **Generate counter inputs**: Create 10 inputs that should NOT match  
3. **Build pattern backwards**: Create a pattern that matches the expected input but not the counter inputs
4. **Add variability**: Apply random transformations (fragments, character classes, quantifiers) for complexity

## Building

```bash
cd testgen
make
```

## Usage

```bash
# Generate test cases
./testgen -n 100 -c mixed

# Generate and run tests
./testgen -n 100 -c mixed -r
```

### Options

| Option | Description |
|--------|-------------|
| `-n N` | Number of test cases (default: 100) |
| `-o DIR` | Output directory (default: output) |
| `-s SEED` | Random seed for reproducibility |
| `-c LEVEL` | Complexity: simple, medium, complex, mixed |
| `-r` | Run tests through c-dfa after generating |
| `-k` | Keep generated files after test |
| `-h` | Show help |

## Complexity Levels

| Level | Description |
|-------|-------------|
| simple | Basic command + argument patterns |
| medium | Patterns with fragments and flags |
| complex | Patterns with character classes, alternation, quantifiers |

## Output Files

- `patterns.txt` - Pattern file in c-dfa format
- `expectations.json` - Expected inputs and counter-inputs

## Pattern Format

```
[fragment:NAME] pattern definition

[category] pattern
```

Categories: safe, caution, modifying, dangerous, network, admin, build, container
