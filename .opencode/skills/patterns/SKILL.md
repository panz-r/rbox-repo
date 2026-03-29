# PATTERNS Skill

**Scope:** rbox-ptrace and rbox-wrap

---
name: patterns
description: Understand and modify command patterns for rbox-ptrace and rbox-wrap DFA validation
license: MIT
compatibility: opencode
metadata:
  project: readonlybox
  scope: patterns
---

## What I do

Explain pattern syntax for embedded DFA validation in rbox-ptrace and rbox-wrap.

## Pattern File Locations

```
rbox-ptrace/
└── rbox_ptrace_embedded_commands.txt   # Command patterns for ptrace client

rbox-wrap/
└── rbox_wrap_commands.txt             # Command patterns for wrapper
```

Patterns are embedded at compile time into `*_dfa_data.c` files.

## Pattern Format

```
[category:subcategory:ops] pattern
```

Examples:
```
[safe:readonly:git] git status
[caution:network:http] curl *
[safe] cat *
```

## Category Values

| Category | Value | Description |
|----------|-------|-------------|
| safe | 0x01 | Read-only operations |
| caution | 0x02 | Minor side effects |
| modifying | 0x04 | Modifies files |
| dangerous | 0x08 | Harmful operations |
| network | 0x10 | Network operations |
| admin | 0x20 | Administrative |

## Syntax

### Literal Characters

Most characters match themselves literally:
```
git status    # matches "git status"
```

### Whitespace

Space normalizes to `[ \t]+` (one or more whitespace).

### Alternation

Use `|` for alternatives (can be used in fragments for macro-like effects):
```
a|b|c          # matches a OR b OR c
(a|ab|c|de)    # matches a OR ab OR c OR de
0|1|2|3|4|5|6|7|8|9   # matches any digit
```

Fragments can contain complex alternations, providing macro-like pattern reuse:

### Quantifiers

| Syntax | Behavior |
|--------|----------|
| `*` | Zero or more |
| `+` | One or more |
| `?` | Zero or one |

### Fragment Definitions

```bash
# Define
[fragment:name] pattern_value

# Reference
((name))
```

### Grouping

```bash
(expr)          # Groups expressions
a|b|c           # Alternation
```

### Wildcard

Standalone `*` as an argument matches ANY argument:
```
[safe] cat *    # Matches "cat file.txt"
```

## Examples from Pattern File

```bash
# Digit fragment using alternation
[fragment:safe::digit] 0|1|2|3|4|5|6|7|8|9

# Using fragment reference
[safe] git log -n ((safe::digit))+

# Literal arguments
[autoallow:readonly:git] git status
[autoallow:readonly:file] ls -la
```

## Building

After modifying patterns, rebuild:

```bash
# rbox-ptrace
cd rbox-ptrace && make clean && make && make test

# rbox-wrap
cd rbox-wrap && make clean && make && make test
```

## When to Use Me

Use this skill when:
- Adding new commands to allow list
- Understanding pattern matching
- Debugging command validation
