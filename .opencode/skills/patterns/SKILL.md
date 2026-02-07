# PATTERNS Skill

**Scope:** c-dfa subproject only

---
name: patterns
description: Write and validate safe command patterns for ReadOnlyBox DFA matching
license: MIT
compatibility: opencode
metadata:
  project: readonlybox
  component: c-dfa
  scope: c-dfa-subproject
---

## What I do

Provide complete reference for writing pattern files used by the NFA/DFA system in the **c-dfa subproject**. Cover syntax, fragments, categories, and quantifiers.

## Scope: c-dfa Subproject

This skill applies to files in `c-dfa/` directory:

```
readonlybox/
├── c-dfa/                    ← THIS SCOPE
│   ├── patterns_safe_commands.txt    # Production patterns
│   ├── patterns_*.txt               # Test pattern files
│   ├── Makefile                     # c-dfa build
│   ├── tools/                       # NFA/DFA builders
│   └── src/                         # DFA evaluation code
└── cmd/readonlybox/       # Main binary (different scope)
```

## c-dfa Subproject Skills

For c-dfa-specific pattern tasks, use:

- **patterns-cdfa** - Detailed pattern syntax reference (c-dfa scope)

## Pattern File Format

### Line Structure

```
[category:subcategory:operations] pattern
```

Examples:
```
[safe:readonly:git] git status
[caution:network:http] curl *
[safe] cat *
```

### Components

| Component | Required | Description |
|-----------|----------|-------------|
| category | Yes | Primary safety category (safe, caution, modifying, dangerous, network, admin, build, container) |
| subcategory | No | Secondary categorization for organization |
| operations | No | Operations string (comma or dot-separated) |

### Category Values

Categories are 8-bit bitmasks:
- `safe` (0x01) - Completely read-only
- `caution` (0x02) - Minor side effects possible
- `modifying` (0x04) - Modifies files
- `dangerous` (0x08) - Potentially harmful
- `network` (0x10) - Network operations
- `admin` (0x20) - Administrative
- `build` (0x40) - Build/CI operations
- `container` (0x80) - Container-related

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

### Character Classes

| Syntax | Description |
|--------|-------------|
| `[abc]` | Matches a, b, or c |
| `[a-z]` | Matches a to z |
| `[^abc]` | NOT a, b, or c |
| `[a-zA-Z0-9_]` | Alphanumeric plus underscore |

### Quantifiers

| Syntax | Behavior | Notes |
|--------|----------|-------|
| `*` | Zero or more | Works on preceding element |
| `+` | One or more | **REQUIRES fragment reference** |
| `?` | Zero or one | Limited implementation |

#### CRITICAL: Plus Quantifier

The `+` quantifier **REQUIRES a fragment reference**:

```bash
# CORRECT - uses fragment:
[safe] git log -n ((safe::digit))+
[safe] a((safe::b))+

# INCORRECT - may not work:
[safe] [0-9]+    # Character class without fragment
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

### Alternation

```bash
(safe|caution|modifying)    # Matches one of the options
git (status|log|diff)      # Real-world example
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

### Escaped Characters

| Syntax | Meaning |
|--------|---------|
| `\x` | Literal character x |
| `\\` | Literal backslash |
| `\'` | Literal single quote |
| `\xNN` | Hex escape (ASCII NN) |

```bash
[safe] cat \*.txt    # Matches "cat *.txt"
[safe] hello\ world  # Matches "hello world"
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
[safe:readonly:git] git remote get-url origin
```

### File Reading

```bash
[safe:readonly:file] cat
[safe:readonly:file] cat *
[safe:readonly:file] less *
[safe:readonly:file] head -n ((safe::digit))
[safe:readonly:file] tail -n ((safe::digit))
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

The nfa_builder validates patterns automatically during build. To validate a pattern file without building:

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
