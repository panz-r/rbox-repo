# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## General Coding Principles

### Single Source of Truth

**When implementing any feature, there must be ONE canonical implementation - not multiple implementations of the same logic.**

- If you need a function to do X, create ONE function that does X well
- Do NOT create variant functions like `doX()`, `doX_with_param()`, `doX_fast()`, `doX_legacy()`
- Tests, wrappers, and all code must use the canonical implementation
- When requirements change, MODIFY the existing function rather than adding new ones

**Why this matters:**
- Duplicate code causes bugs when only one copy is fixed
- Protocol field placement becomes inconsistent
- Caches and matching logic breaks when implementations diverge
- Maintenance becomes impossible

### Buffer Capacity - MANDATORY for All Write Functions

**Every function that writes to a buffer MUST take a capacity/size parameter and MUST NOT write beyond it.**

```c
// CORRECT: Takes capacity, returns error if buffer too small
rbox_error_t rbox_build_request(char *packet, size_t capacity, size_t *out_len, ...);

// WRONG: No capacity - can overwrite beyond buffer (STACK SMASHING BUG!)
rbox_error_t rbox_build_request(char *packet, size_t *out_len, ...);
```

**Requirements:**
1. All packet-building, encode, serialize, write functions MUST have a capacity parameter
2. Functions MUST check `if (capacity < min_required_size) return RBOX_ERR_INVALID;`
3. Functions MUST use capacity (not hardcoded values like 4096) for any memset/memcpy operations
4. Callers MUST pass `sizeof(buffer)` or the actual allocated size
5. Return a clear error code (e.g., `RBOX_ERR_INVALID`) when buffer is too small

**Why this matters:**
- Hardcoded sizes like `memset(packet, 0, 4096)` on a 1024-byte buffer causes STACK SMASHING
- Security implications: stack smashing can be exploited
- Correctness: buffer overruns corrupt memory unpredictably

### Protocol Field Placement

When working with protocols or data formats:
- The protocol defines WHERE fields go (header vs body, offset X vs offset Y)
- This placement is FIXED - do not create alternative encoders that put same data in different places
- All code must use canonical encoding functions

### Testing

- Tests should validate the canonical functions, not reimplement logic
- No local "build_packet()" or "parse_response()" functions in test files
- Tests use the same functions the production code uses

## Project Overview

**ReadOnlyBox** is a BusyBox-like single binary that provides read-only command wrappers for common Unix/Linux CLI tools. The project has evolved from individual wrappers to a consolidated single binary architecture while maintaining the same security principles.

### Architecture Evolution

**Before (Individual Wrappers):**
- Multiple separate binaries (ro-git, ro-find, ro-ls, etc.)
- Each wrapper was a standalone binary
- Total: 26+ individual binaries

**Current (ReadOnlyBox with LD_PRELOAD Client):**
- Single consolidated binary: `readonlybox`
- BusyBox-like interface: `readonlybox <command> [args...]`
- LD_PRELOAD client: `libreadonlybox_client.so` with DFA fast path
- Safe commands execute immediately via DFA
- Unknown commands redirect through `readonlybox --run`
- Legacy ro-* binaries have been removed

**Before (ReadOnlyBox Single Binary):**

This project uses **Mage** build system. Mage is a modern Go-based build tool that provides better integration with Go projects.

### Using Mage

You can use Mage commands:
```bash
# List available targets
mage -l

# Run default target (build)
mage
```

### Build Commands
```bash
# Build ReadOnlyBox single binary (using Mage)
mage build

# Build ReadOnlyBox single binary (using Make)
make build

# Clean build artifacts (using Mage)
mage clean

# Clean build artifacts (using Make)
make clean
```

### Installation
```bash
# Install to /usr/local/bin (using Mage)
mage install

# Install to /usr/local/bin (using Make)
make install

# Uninstall (using Mage)
mage uninstall

# Uninstall (using Make)
make uninstall

# Install to custom location (using Mage)
DESTDIR=/custom/path mage install

# Install to custom location (using Make)
make install DESTDIR=/custom/path
```

### Testing
```bash
# Run all tests (using Mage)
mage test

# Run all tests (using Make)
make test

# Run unit tests (using Mage)
mage unitTest

# Run integration tests (using Mage)
mage integrationTest

# Quick test (using Mage)
mage quickTest

# Test ReadOnlyBox single binary
./readonlybox --help
./readonlybox git --version
./readonlybox find . -name "*.go"
./readonlybox ps aux
```

## Code Architecture

### Project Structure
```
cmd/
  readonlybox/  # ReadOnlyBox single binary
    main.go
bin/           # Built binaries (created by make build)
internal/
  readonlybox/ # ReadOnlyBox core logic
    commands.go # Command registry and routing
  rogit/       # Git security validation
  rofind/      # Find security validation
  # ... all other security modules
```

### Key Components

#### readonlybox
- **Purpose**: Single binary providing all read-only command wrappers
- **Implementation**: BusyBox-like command router with security validation
- **Security**: Centralized security validation for all commands
- **Location**: `cmd/readonlybox/main.go` and `internal/readonlybox/commands.go`
- **Commands Supported**: 26+ read-only commands (ps, df, du, git, find, etc.)

### ReadOnlyBox Architecture

The ReadOnlyBox single binary follows a modular, security-first architecture:

```
User Command → Command Router → Security Validator → Safe Execution
                       ↓
                 (Block if dangerous)
```

#### Command Router
- **Location**: `internal/readonlybox/commands.go`
- **Function**: Routes commands to appropriate handlers
- **Implementation**: 26+ command handlers in a registry pattern
- **Benefits**: Easy to add new commands, centralized error handling

#### Security Validators
- **Pattern**: Reuse existing security modules
- **Benefits**: Consistent security across all commands
- **Modules**: rogit, rofind, rops, rodf, rodu, rowc, rouname, etc.

#### Execution Engine
- **Function**: Safe command execution with proper error handling
- **Features**: Exit code preservation, stdin/stdout/stderr passthrough

### Security Design

1. **Command Validation**: Each wrapper maintains a list of blocked operations
2. **Argument Parsing**: Careful analysis of command-line arguments for potential dangers
3. **Go Implementation**: More secure than shell scripts (no shell injection vulnerabilities)
4. **Direct Execution**: Uses `os/exec` to bypass shell interpretation entirely

### CRITICAL: Command Syntax Parsing

**MUST** implement proper command syntax parsing for each wrapper. The fundamental security principle is:

> "Validate arguments based on their ROLE in the command, not just their isolated appearance"

#### Requirements for All RO Wrappers:

1. **Full Command Parsing**: Must parse the complete command syntax according to the underlying tool's specification
2. **Role-Based Validation**: Arguments must be validated based on their semantic role (option, filename, owner spec, etc.)
3. **Parse Failure = Block**: If the command cannot be correctly parsed, it MUST be blocked as potentially dangerous
4. **Contextual Analysis**: The same string may be safe or dangerous depending on its position and role

#### Example: The chown Fix

**Before (Incorrect)**:
```go
// Just checked if each arg "looks dangerous"
for _, arg := range args {
    if isValidOwnerSpec(arg) {
        return false, "attempts to change ownership"
    }
}
```

**After (Correct)**:
```go
// Parse full command structure first
options, ownerSpec, files, err := parseChownCommand(args)
if err != nil {
    return false, fmt.Sprintf("invalid command: %s", err) // BLOCK if can't parse
}

// Validate based on parsed roles
if ownerSpec != "" {
    return false, "attempts to change ownership"
}
```

#### Why This Matters:

- **Prevents False Positives**: `chown file.txt` should not block because "file.txt" is a filename, not an owner spec
- **Prevents False Negatives**: `chown john file.txt` must block because "john" is an owner spec targeting "file.txt"
- **Security**: Malicious commands often rely on argument confusion attacks
- **Correctness**: Proper parsing ensures the wrapper behaves like the real command (just read-only)

## Development Workflow

### Adding New Commands to ReadOnlyBox

1. **Create security module** (if needed):
   ```bash
   mkdir -p internal/ro<command>
   # Implement security validation in ro<command>.go
   ```

2. **Add command handler** to `internal/readonlybox/commands.go`:
   ```go
   // Add to CommandRegistry
   "newcommand": {
       Name:        "newcommand",
       Description: "Description of the command",
       Handler:     handleNewCommand,
   }

   // Implement handler function
   func handleNewCommand(args []string) error {
       // Add security validation
       if safe, reason := ronewcommand.IsNewCommandSafe(args); !safe {
           return fmt.Errorf("newcommand: %s", reason)
       }
       return runCommand("newcommand", args...)
   }
   ```

3. **Add tests** following existing patterns
4. **Update documentation** in README.md

### Legacy: Adding Individual Wrappers

1. Create new directory under `cmd/` (e.g., `cmd/ro-ls/`)
2. Implement wrapper logic in `main.go`
3. Add build rule to Makefile/Magefile
4. Update this documentation

### Common Tasks

```bash
# Format code (using Mage)
mage fmt

# Format code (using Make)
make fmt

# Build and test (using Mage)
mage build && mage test

# Build and test (using Make)
make build && make test

# Use ReadOnlyBox single binary
./readonlybox --help
./readonlybox git log --oneline
./readonlybox find . -name "*.go" -type f
./readonlybox ps aux
./readonlybox df -h
```

### Testing Requirements

All RO wrapper tests **MUST** include:

1. **Syntax Parsing Tests**: Test cases that verify proper command syntax parsing
2. **Role-Based Validation Tests**: Tests for each argument type (options, targets, etc.)
3. **Edge Case Tests**: Ambiguous cases that could be misinterpreted
4. **Parse Failure Tests**: Commands that should fail to parse and be blocked

#### Example Test Structure:

```go
// Test command parsing
func TestParseCommand(t *testing.T) {
    // Test proper parsing of full command syntax
    // Verify options, targets, and arguments are correctly identified
}

// Test role-based validation
func TestRoleBasedValidation(t *testing.T) {
    // Test that the same string is handled differently based on role
    // e.g., "file.txt" as filename vs "file.txt" as invalid owner spec
}

// Test edge cases
func TestEdgeCases(t *testing.T) {
    // Test ambiguous or borderline cases
    // Test commands that look valid but should be blocked
}

// Test parse failures
func TestParseFailures(t *testing.T) {
    // Test malformed commands that should fail to parse
    // Verify they are blocked rather than allowed through
}
```

## Current Tools

### ReadOnlyBox (Single Binary - RECOMMENDED)
- **Commands**: 26+ read-only commands in one binary
- **Interface**: `readonlybox <command> [args...]`
- **Benefits**: Easy distribution, single installation, BusyBox-like interface
- **Status**: Active development, recommended approach

### LD_PRELOAD Client
- **Interface**: `LD_PRELOAD=libreadonlybox_client.so <command>`
- **Fast path**: DFA validates safe commands immediately
- **Fallback**: Unknown commands redirect through `readonlybox --run`
- **Status**: Active development, recommended for production use

## c-dfa Subproject

The `c-dfa/` subproject is a high-performance C implementation of a Deterministic Finite Automata (DFA) for fast validation of read-only commands. It serves as the first-layer security validation in ReadOnlyBox.

### Architecture

```
Command String → DFA Evaluator → Command Category
                          ↓
                   Binary DFA (static data)
```

### Build Commands

```bash
# Build all c-dfa tools and tests
cd c-dfa && make

# Run full test suite
cd c-dfa && make test

# Run specific algorithm tests
cd c-dfa && make test-moore      # Moore minimization
cd c-dfa && make test-hopcroft   # Hopcroft algorithm (recommended)
cd c-dfa && make test-brzozowski # Brzozowski algorithm

# Run SAT minimization tests
cd c-dfa && make build-sat
cd c-dfa && make test-sat

# Clean
cd c-dfa && make clean
cd c-dfa && make clean-all       # Also cleans vendor builds
```

### Key Components

| Component | Purpose |
|-----------|---------|
| `tools/nfa_builder` | Converts command specifications to NFA |
| `tools/nfa2dfa_advanced` | Converts NFA to DFA with minimization |
| `tools/nfa2dfa_sat` | SAT-based minimal DFA (requires CaDiCaL) |
| `src/dfa_eval.c` | Core DFA evaluation engine |
| `src/dfa_test.c` | Comprehensive test runner |

### Pattern Syntax

- `*` - Matches any sequence of characters
- `+` - Matches one or more characters
- `?` - Matches any single character
- `[...]` - Character classes
- `{a,b}` - Alternation

### Current Development

The c-dfa project is actively being debugged. Known issues being investigated:
- Alternation handling in combined DFAs
- Chain patterns requiring normalized space between elements
- Whitespace prefix sharing in NFA builder

### Integration

The C DFA layer integrates with the main ReadOnlyBox:
1. **First Layer (C DFA)**: Quick validation of obviously safe commands
2. **Second Layer (Go Parsers)**: Detailed semantic analysis for complex commands
3. **Fallback**: Conservative blocking for unknown commands
