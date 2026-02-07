# Patterns (c-dfa)

**Scope:** c-dfa subproject only

---
name: patterns-cdfa
description: Write and validate pattern files for the c-dfa DFA matching system
license: MIT
兼容性: opencode
metadata:
  project: readonlybox
  component: c-dfa
  workflow: patterns
  scope: c-dfa-subproject
---

## What I do

Provide reference for writing pattern files used by the DFA system in the **c-dfa subproject**. Cover syntax, fragments, categories, and quantifiers.

## Scope: c-dfa Subproject

This skill applies to files in `c-dfa/patterns_*.txt`:

```
readonlybox/c-dfa/
├── patterns_safe_commands.txt     # Production patterns
├── patterns_expanded_*.txt        # Test pattern files
├── patterns_command_*.txt         # Category patterns
└── patterns_capture_*.txt         # Capture patterns
```

## Pattern File Format

### Line Structure

```
[category:subcategory:operations] pattern
```

### Examples

```
[safe:readonly:git] git status
[caution:network:http] curl *
[safe] cat *
```

### Components

| Component | Required | Description |
|-----------|----------|-------------|
| category | Yes | Primary safety category |
| subcategory | No | Secondary categorization |
| operations | No | Operations string |

### Category Values

Categories are 8-bit bitmasks:

| Category | Value | Description |
|----------|-------|-------------|
| safe | 0x01 | Completely read-only |
| caution | 0x02 | Minor side effects |
| modifying | 0x04 | Modifies files |
| dangerous | 0x08 | Harmful operations |
| network | 0x10 | Network operations |
| admin | 0x20 | Administrative |
| build | 0x40 | Build/CI operations |
| container | 0x80 | Container-related |

## Pattern Syntax

### Literal Characters

Most characters match themselves:

```
git status    # matches "git status"
```

### Whitespace Handling

Space in patterns normalizes to `[ \t]+` (one or more whitespace):

```
git status    # matches "git status", "git  status", "git\tstatus"
```

### Fragment References

Fragments define reusable patterns:

```bash
# Definition
[fragment:namespace::name] pattern_value

# Reference
((namespace::name))
```

Examples:

```bash
[fragment:git::digit] [0-9]
[safe] git log -n ((git::digit))+
```

### Quantifiers

| Syntax | Behavior | Notes |
|--------|----------|-------|
| `*` | Zero or more | Works on preceding element |
| `+` | One or more | REQUIRES fragment reference |
| `?` | Zero or one | Optional |

#### CRITICAL: Plus Quantifier

The `+` quantifier **REQUIRES a fragment reference**:

```bash
# CORRECT - uses fragment:
[safe] git log -n ((safe::digit))+
[safe] a((safe::b))+

# INCORRECT - may not work:
[safe] [0-9]+    # Character class without fragment
```

### Alternation

```bash
(safe|caution|modifying)    # Matches one of the options
git (status|log|diff)       # Real-world example
```

### Capture Tags

```bash
<capname>pattern</capname>    # Captures matched portion

# Example
[safe] cat <filename>((FILENAME))</filename>
```

### Wildcard

Standalone `*` at argument position matches ANY argument:

```bash
[safe] cat *        # Matches "cat file.txt", "cat anything"
[safe] git log *    # Matches "git log --oneline", "git log -n 5"
```

## Fragment Definition Rules

1. **Fragments must be defined BEFORE patterns that use them**
2. **Use lowercase namespaces**: `safe::digit` not `SAFE::DIGIT`
3. **Fragment names should be descriptive**

### Standard Fragments

```bash
[fragment:safe::digit] [0-9]
[fragment:safe::b] b
[fragment:safe::alpha] [a-zA-Z]
```

## Common Patterns

### Git Read-Only Commands

```bash
[safe:readonly:git] git status
[safe:readonly:git] git log --oneline
[safe:readonly:git] git diff
[safe:readonly:git] git branch -a
```

### File Reading

```bash
[safe:readonly:file] cat
[safe:readonly:file] cat *
[safe:readonly:file] less *
[safe:readonly:file] head -n ((safe::digit))
```

### System Information

```bash
[safe:readonly:system] which bwrap
[safe:readonly:system] ps aux
[safe:readonly:system] df -h
```

## Anti-Patterns to Avoid

1. **Character class with + without fragment**
   ```bash
   # BAD
   [safe] [0-9]+

   # GOOD
   [safe] ((safe::digit))+
   ```

2. **Fragment not defined before use**
   ```bash
   # BAD - pattern uses undefined fragment
   [safe] cmd ((undefined_frag))
   ```

3. **Wrong category format**
   ```bash
   # BAD - category "safe path matching" not valid
   [safe path matching:quant:group] pattern

   # GOOD
   [safe::quant::group] pattern
   ```

4. **Unused fragments**
   ```bash
   # Define but never use
   [fragment:unused] pattern
   ```

## Validation

The nfa_builder validates patterns automatically:

```bash
cd c-dfa
./tools/nfa_builder --validate-only patterns_safe_commands.txt
```

This checks:
- Fragment definitions exist for all references
- Category format is valid
- Pattern syntax is correct

## When to Use Me

Use this skill when:
- Writing new patterns for safe commands
- Debugging pattern matching issues
- Adding command support to ReadOnlyBox
- Understanding pattern syntax errors
- Converting command wrappers to patterns

## Examples

### Simple Literal

```bash
[safe:readonly:git] git status
```

### With Numeric Argument

```bash
[safe] tail -n ((safe::digit))
```

### With Wildcard

```bash
[safe] cat *
```

### Complex with Alternation

```bash
[safe] git (status|log|diff|show)
```

### Quantifier Test Patterns

```bash
[safe:quant] a((safe::b))+
[caution:net] abc((safe::b))+
```
