# DFA Debugging (c-dfa)

**Scope:** c-dfa subproject only

---
name: dfa-debugging-cdfa
description: Debug DFA building and evaluation issues in the c-dfa subproject
license: MIT
兼容性: opencode
metadata:
  project: readonlybox
  component: c-dfa
  workflow: debugging
  scope: c-dfa-subproject
---

## What I do

Debug DFA building and evaluation issues in the **c-dfa subproject**. Diagnose validation errors, build failures, and test mismatches.

## Scope: c-dfa Subproject

This skill applies to files in `c-dfa/` directory:

```
readonlybox/c-dfa/
├── patterns_*.txt           # Pattern files
├── tools/
│   ├── nfa_builder             # Pattern validation + NFA building
│   └── nfa2dfa_advanced        # NFA to DFA conversion
├── src/
│   ├── dfa_eval.c              # DFA evaluation
│   └── dfa_test.c              # Test runner
└── Makefile
```

## Validation

### Run Validation

```bash
cd c-dfa
./tools/nfa_builder --validate-only patterns_safe_commands.txt
```

### Validation Output

```
Validation passed: 0 errors, 0 warnings
```

Or with errors:

```
Error: Line 50: Fragment 'x' not defined
Error: Line 75: Invalid category format
```

## Common Errors

### Error: "Fragment 'name' not defined"

**Cause:** Pattern uses a fragment that wasn't defined.

```bash
# FAILS - 'middle' not defined
[safe] prefix((middle))*suffix
```

**Fix:** Add fragment definition before patterns that use it:

```bash
[fragment:namespace::middle] middle

[safe] prefix((namespace::middle))*suffix
```

### Error: "Invalid category format"

**Cause:** Category doesn't match expected format.

```bash
# FAILS - empty first component
[]pattern
```

**Fix:** Ensure category has at least one component:

```bash
[safe] git status
[safe::readonly:git] git status
```

### Error: "Unknown character in pattern"

**Cause:** Invalid escape sequence or character.

```bash
# FAILS - invalid escape
[safe] cat \x
```

**Fix:** Use valid escape sequences:

```bash
[safe] cat \*.txt    # Literal asterisk
[safe] hello\ world  # Literal space
```

### Test Failure: "NO MATCH"

**Cause:** Pattern doesn't match expected input.

```
[FAIL] git status matches - got 'NO MATCH' (len=0, cat=0x00)
```

**Debug steps:**
1. Check pattern exists in file
2. Validate pattern file
3. Rebuild DFA
4. Check pattern syntax

### Test Failure: Wrong Category

**Cause:** Pattern has incorrect category mask.

```
[FAIL] git status matches - got 'MATCH' (len=10, cat=0x00)
```

Expected `cat=0x01` (safe) but got `cat=0x00`.

**Debug:**
1. Check category in pattern definition
2. Verify category mask values

## Debug Commands

### Check Fragment Usage

```bash
grep -n "((namespace::" patterns_safe_commands.txt
```

### Find Missing Fragments

```bash
# Get list of all fragments referenced
grep -oE '\(\([a-zA-Z0-9_::]+\)\)' patterns_safe_commands.txt | sort | uniq

# Get list of fragments defined
grep "^\[fragment:" patterns_safe_commands.txt
```

### Validate Specific Line

```bash
sed -n '50p' patterns_safe_commands.txt
```

### Verbose NFA Building

```bash
cd c-dfa
NFA_BUILDER_VERBOSE=1 make dfa
```

### Verbose DFA Conversion

```bash
cd c-dfa
NFA2DFA_VERBOSE=1 make dfa
```

### Debug DFA Evaluation

Enable debug in `src/dfa_eval.c`:

```c
#define DFA_EVAL_DEBUG 1
```

Then rebuild and run:

```bash
make clean && make dfa_test && ./dfa_test 2>&1 | grep DEBUG
```

## Build Debugging

### NFA Builder Fails

```bash
# Check for validation errors
./tools/nfa_builder --verbose patterns_safe_commands.txt build/readonlybox.nfa
```

### nfa2dfa Fails

```bash
# Check NFA file format
cat build/readonlybox.nfa | head -20

# Rebuild NFA
./tools/nfa_builder patterns_safe_commands.txt build/readonlybox.nfa

# Retry DFA conversion
./tools/nfa2dfa_advanced build/readonlybox.nfa build/readonlybox.dfa
```

## Test Debugging

### Find Failing Test Group

```bash
make test 2>&1 | grep -B5 "Result:.*passed"
```

### Run Single Pattern File Test

```bash
cd c-dfa
# Build DFA for specific pattern
./tools/nfa_builder patterns_safe_commands.txt build/readonlybox.nfa
./tools/nfa2dfa_advanced build/readonlybox.nfa build/readonlybox.dfa

# Run test
./dfa_test 2>&1 | grep -A10 "CORE TESTS"
```

### Check DFA Binary

```bash
cd c-dfa/build
# Dump DFA states
../../tools/dump_dfa_states patterns_safe_commands.dfa
```

## When to Use Me

Use this skill when:
- Pattern validation fails
- DFA build fails
- Tests fail unexpectedly
- Debugging pattern matching issues
- Adding new patterns
- Understanding error messages
