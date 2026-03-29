# ReadOnlyBox Pattern System

## Overview

This document describes the advanced pattern system used by ReadOnlyBox for command validation. The system consists of multiple layers:

1. **Pattern Specification** → **NFA Builder** → **NFA** → **DFA Builder** → **DFA** → **Evaluation**

## Pattern Specification Format

### Basic Format

```
[category:subcategory:operations] pattern -> action
```

### Components

#### Categories
- `safe` - 100% read-only, no side effects
- `caution` - Read-only but may have side effects
- `modifying` - Modifies filesystem or state
- `dangerous` - Potentially destructive operations
- `network` - Network operations
- `admin` - Requires administrative privileges
- `build` - Build system operations
- `container` - Container operations

#### Subcategories
- `file` - File operations
- `text` - Text processing
- `system` - System operations
- `vcs` - Version control
- `build` - Build systems
- `container` - Container operations
- `cloud` - Cloud operations

#### Operations
- `read` - Read operations
- `write` - Write operations
- `execute` - Execution
- `create` - Creation
- `delete` - Deletion
- `network` - Network access
- `privilege` - Privilege escalation
- `compile` - Compilation
- `link` - Linking

#### Actions
- `allow` - Allow the command
- `caution` - Allow with caution/warning
- `block` - Block the command
- `audit` - Allow but audit/log
- `monitor` - Monitor execution

### Pattern Syntax

#### Literal Characters
Match exact characters:
```
[safe:file:read] cat file.txt -> allow
```

#### Wildcards
- `(*)` - Wildcard group: matches any single argument
- `(expr)*` - Quantifier: zero or more of preceding element (parentheses REQUIRED for literals)
- `(expr)+` - Quantifier: one or more of preceding element (parentheses REQUIRED for literals)
- `(expr)?` - Quantifier: zero or one of preceding element (parentheses REQUIRED for literals)

**Syntax Rules:**
- `(*)`  = wildcard (matches any single argument)
- `(a)*` = zero or more 'a' (quantifier)
- `a*`   = ERROR: ambiguous - use `(a)*` for quantifier
- `a+`, `a?` = ERROR: ambiguous - use `(a)+` or `(a)?`

**Quantifier Compatibility:**
- Literals: Require grouping `(a)+`
- Fragments: Work directly `((frag))+` or `((frag))*`
- Groups: Work directly `(a|b)+`

**Escape Sequences:**
- `\*` - Literal asterisk (for matching literal `*` arguments)
- `\?` - Literal question mark
- `\\` - Literal backslash

**Examples:**
```
[safe:file:read] cat (*) -> allow        # any single argument
[safe:file:read] cat (*) (*) -> allow   # two arguments
[safe:file:read] grep (*) (*) -> allow  # pattern and files

[safe:file:read] (*) -> allow           # any command (dangerous!)
[caution:file:read] find (*) -name (*) -> allow

# Literal asterisk (escape the star)
[safe:file:read] find (*) -name \* -> allow  # matches -name *

# Quantifiers (parentheses REQUIRED for literals)
[safe:file:read] git log (-n)* -> allow      # zero or more -n flags (grouped)
[safe:file:read] echo ((ARG))+ -> allow      # one or more args (fragment)
[safe:file:read] ls -la (h)? -> allow        # optional char (grouped)
```

### Complete Examples

```
# Safe file operations
[safe:file:read] cat (*) -> allow
[safe:file:read] head (*) -> allow
[safe:file:read] tail (*) -> allow

# Git operations
[safe:vcs:read] git log (*) -> allow
[safe:vcs:read] git show (*) -> allow
[modifying:vcs:write] git commit (*) -> caution

# Build operations
[safe:build:compile] gcc -c (*) -> allow
[modifying:build:install] make install -> caution

# Dangerous operations
[dangerous:file:delete] rm -rf (*) -> block
[dangerous:system:write] dd (*) -> block

# Network operations
[network:network:read] curl (*) -> audit
[network:network:execute] ssh (*) -> audit

# Admin operations
[admin:system:privilege] sudo (*) -> block
[admin:file:privilege] chmod (*) (*) -> audit
```

## Pattern Processing Pipeline

### 1. Pattern Specification
Input: `commands_advanced.txt`

### 2. NFA Builder
Tool: `nfa_builder`
Input: Pattern specification
Output: NFA (Non-deterministic Finite Automata) with tags

```bash
nfa_builder commands_advanced.txt readonlybox.nfa
```

### 3. NFA to DFA Conversion
Tool: `nfa2dfa`
Input: NFA file
Output: DFA (Deterministic Finite Automata) binary

```bash
nfa2dfa readonlybox.nfa readonlybox.dfa
```

### 4. DFA Evaluation
Library: `libdfa`
Input: Command string
Output: Validation result with tags

```c
dfa_result_t result;
dfa_evaluate("cat file.txt", 0, &result);
// result.category = DFA_CMD_READONLY_SAFE
// result.tags = ["safe", "file", "read", "allow"]
```

## Advanced Features

### Tag Inheritance
Tags from the pattern specification are attached to accepting states in the NFA/DFA:

```
[safe:file:read] cat (*) -> allow
                      ↓
              Accepting state with tags:
              - "safe" (category)
              - "file" (subcategory)
              - "read" (operation)
              - "allow" (action)
```

### Pattern Prioritization
Patterns are processed in order. More specific patterns should come before general ones:

```
# Specific pattern first
[safe:file:read] cat /etc/passwd -> block

# General pattern after
[safe:file:read] cat * -> allow
```

### Context-Aware Validation
The system can use multiple DFAs for different contexts:

```
# User context DFA
user_dfa.dfa - For regular user commands

# Admin context DFA
admin_dfa.dfa - For administrative commands

# Build context DFA
build_dfa.dfa - For build system commands
```

## Building the Complete Pipeline

### Step 1: Create Pattern Specification
Edit `commands_advanced.txt` with your patterns.

### Step 2: Build NFA
```bash
cd c-dfa/build
nfa_builder ../tools/commands_advanced.txt readonlybox.nfa
```

### Step 3: Convert to DFA
```bash
nfa2dfa readonlybox.nfa readonlybox.dfa
```

### Step 4: Test DFA
```bash
dfa_test readonlybox.dfa "cat file.txt"
dfa_test readonlybox.dfa "rm -rf /"
```

### Step 5: Integrate with ReadOnlyBox
```c
// Load DFA
void* dfa_data = load_file("readonlybox.dfa");
dfa_init(dfa_data);

// Evaluate command
dfa_result_t result;
if (dfa_evaluate(command, 0, &result)) {
    if (result.category == DFA_CMD_READONLY_SAFE) {
        // Allow command
    } else {
        // Block or caution based on category
    }
}
```

## Pattern Best Practices

### 1. Be Specific
```bash
# Good
[safe:file:read] cat /var/log/(*) -> allow

# Bad (too broad)
[safe:file:read] cat (*) -> allow
```

### 2. Order Matters
```bash
# Process specific before general
[dangerous:file:delete] rm -rf / -> block
[dangerous:file:delete] rm -rf (*) -> block
[modifying:file:delete] rm (*) -> caution
```

### 3. Use Subcategories
```bash
# More descriptive
[safe:text:read] grep (*) (*) -> allow

# Less descriptive
[safe:file:read] grep (*) (*) -> allow
```

### 4. Document Actions
```bash
# Clear intent
[safe:file:read] cat (*) -> allow

# Unclear intent
[safe:file:read] cat (*)
```

### 5. Test Thoroughly
```bash
# Test all variations
dfa_test my.dfa "cat file.txt"
dfa_test my.dfa "cat /etc/passwd"
dfa_test my.dfa "cat (*)"
```

## Performance Considerations

### DFA Size
- Typical DFA: 10-100KB
- Large DFA: 100-500KB
- Memory-mapped for efficiency

### Evaluation Speed
- Simple commands: <1μs
- Complex commands: <10μs
- Throughput: 1M+ commands/second

### Build Time
- Pattern compilation: <1s for 1000 patterns
- NFA to DFA: <1s for 1000 states
- Total build: <2s

## Integration with ReadOnlyBox

### Architecture
```
Command String
      ↓
[C DFA Layer] - Fast validation (ptrace interceptor)
      ↓
[rbox-server] - User decision via TUI
      ↓
Decision: Allow / Deny
```

### How It Works
1. **ptrace interceptor** validates commands using the DFA
2. **Fast path**: Safe commands execute directly
3. **Server path**: Unknown commands sent to rbox-server for user decision

### Benefits
1. **Performance**: C DFA provides fast pattern matching
2. **Safety**: Commands can be categorized and validated against patterns
3. **Flexibility**: Pattern files can be updated without recompiling

## Future Enhancements

### 1. Context-Aware DFAs
Multiple DFAs for different contexts (user, admin, build, etc.)

### 2. Pattern Versioning
Versioned DFAs for gradual rollouts

### 3. Dynamic DFA Loading
Load DFAs at runtime without restart

### 4. DFA Composition
Combine multiple DFAs for complex validation

### 5. Machine Learning
Learn new patterns from usage data

## Troubleshooting

### DFA Doesn't Match Expected Commands
1. Check pattern specification
2. Verify NFA with `dfaviz`
3. Test with `dfa_test`
4. Adjust patterns and rebuild

### Performance Issues
1. Check DFA size (`ls -lh *.dfa`)
2. Profile with `dfa_bench`
3. Optimize patterns
4. Split into multiple DFAs

### Build Errors
1. Check Meson version (`meson --version`)
2. Verify toolchain (`gcc --version`)
3. Clean build directory (`rm -rf build`)
4. Rebuild from scratch

## Conclusion

The ReadOnlyBox pattern system provides a powerful and flexible way to validate commands using a multi-layer approach. The advanced pattern notation allows for precise command specification with rich metadata, while the DFA-based evaluation ensures fast and safe validation.

By following the pattern best practices and understanding the processing pipeline, you can create effective command validation rules that balance security and usability.