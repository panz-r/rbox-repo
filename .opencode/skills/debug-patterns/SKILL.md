# DEBUG-PATTERNS Skill

**Scope:** c-dfa subproject only

---
name: debug-patterns
description: Debug pattern validation errors and fix common issues in ReadOnlyBox c-dfa pattern files
license: MIT
compatibility: opencode
metadata:
  project: readonlybox
  component: patterns
  workflow: debugging
  scope: c-dfa-subproject
---

## What I do

Diagnose and fix pattern validation errors in the **c-dfa subproject**. Walk through common issues and their solutions.

## Scope: c-dfa Subproject

This skill applies to files in `c-dfa/` directory:

```
readonlybox/
├── c-dfa/                              ← THIS SCOPE
│   ├── patterns_safe_commands.txt       # Production patterns
│   ├── patterns_quantifier_*.txt        # Test patterns
│   ├── patterns_acceptance_*.txt        # Category tests
│   └── tools/
│       └── nfa_builder                 # Validation tool
└── cmd/readonlybox/           # Different scope
```

## c-dfa Subproject Skills

For c-dfa-specific debugging tasks, use:

- **dfa-debugging-cdfa** - Comprehensive DFA debugging guide
- **dfa-building-cdfa** - Build pipeline debugging
- **dfa-testing-cdfa** - Test debugging
- **patterns-cdfa** - Pattern syntax debugging

## Validation Script

Located at: `c-dfa/tools/nfa_builder --validate-only`

### Running Validation

```bash
cd c-dfa
./tools/nfa_builder --validate-only patterns_safe_commands.txt
```

### Understanding Output

```
[PASS] [safe] git status              # Pattern valid
[FAIL] Line 50: Fragment 'x' not defined  # Error - fix required
[WARN] Line 75: + quantifier on character class  # Warning - may cause issues
```

## Common Errors

### Error: "Fragment 'name' not defined"

**Cause:** Pattern uses a fragment that wasn't defined.

```bash
# FAILS - 'middle' not defined
[safe] prefix((middle))*suffix
```

**Fix:** Add fragment definition before patterns:

```bash
[fragment:namespace::middle] middle

[safe] prefix((namespace::middle))*suffix
```

### Error: "Unknown category: safe path matching"

**Cause:** Category format has spaces or invalid characters.

```bash
# FAILS - "safe path matching" not valid
[safe path matching:quant:group] pattern
```

**Fix:** Use valid category format:

```bash
[safe::quant::group] pattern
```

Valid: lowercase alphanumeric with colons and single hyphens only.

### Error: "Invalid category format"

**Cause:** Category doesn't start with valid category name.

```bash
# FAILS - empty first component
[safe::readonly:git] git status  # OK
[]pattern  # FAILS
```

**Fix:** Ensure category has at least one component:

```bash
[safe] git status
```

### Warning: "+ quantifier on character class"

**Cause:** Using `+` on character class `[0-9]+` without fragment.

```bash
# Works but warning
[safe] tail -n [0-9]+
```

**Fix:** Use fragment reference with `+`:

```bash
[fragment:safe::digit] [0-9]

[safe] tail -n ((safe::digit))+
```

### Warning: "Fragment 'X' is defined but never used"

**Cause:** Fragment defined but no pattern uses it.

```bash
[fragment:unused] some_pattern

# No pattern uses ((unused))
```

**Fix:** Either use the fragment or remove it:

```bash
# Option 1: Remove unused fragment
# Delete the line

# Option 2: Use it
[safe] cmd ((unused))
```

## Step-by-Step Debugging

### 1. Run Validation

```bash
cd c-dfa
./tools/nfa_builder --validate-only <pattern_file>
```

### 2. Identify Errors

Output shows errors and warnings with line numbers.

### 3. Fix Each Error

Process errors in order:
1. First fix fragment definitions
2. Then fix category formats
3. Finally address warnings

### 4. Re-validate

```bash
./tools/nfa_builder --validate-only <pattern_file>
```

### 5. Rebuild DFA

```bash
make clean && make test
```

## Error Reference

| Error | Cause | Fix |
|-------|-------|-----|
| `Fragment 'X' not defined` | Reference without definition | Add `[fragment:ns::X] value` |
| `Unknown category: X` | Invalid category format | Use lowercase alphanumeric |
| `Invalid category format` | Empty first component | Add category name |
| `Fragment 'X' unused` | Defined but not used | Remove or use fragment |
| `+ quantifier on char class` | `[0-9]+` without fragment | Use `((frag))+` |

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

### Compare Defined vs Used

```bash
# Defined fragments
grep "^\[fragment:" patterns_safe_commands.txt | awk -F'[:\]]' '{print $2}' | sort

# Used fragments
grep -oE '\(\([a-zA-Z0-9_::]+\)\)' patterns_safe_commands.txt | tr -d '()' | sort | uniq
```

### Validate Specific Lines

```bash
sed -n '50p' patterns_safe_commands.txt
```

## Common Fixes by Pattern File

### patterns_safe_commands.txt

Always validate before build:

```bash
cd c-dfa && make validate-patterns
```

### patterns_quantifier_comprehensive.txt

May have unused fragments - check summary:

```
Fragments defined: 14
Fragments used: 10
Fragments unused: 4
```

### patterns_acceptance_category_test.txt

May have fragment namespace conflicts - use unique namespaces:

```bash
[fragment:group1::x] x
[fragment:group2::x] x
```

## When to Use Me

Use this skill when:
- Pattern validation fails
- Tests fail unexpectedly
- Adding new patterns
- Understanding error messages
- Debugging pattern matching issues
