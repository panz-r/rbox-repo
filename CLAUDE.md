# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains read-only command wrappers for common Unix/Linux CLI tools. The wrappers are implemented in Go for security and prevent any write operations while allowing safe read-only commands.

## Build System

### Build Commands
```bash
# Build all tools
make build

# Build individual tools
go build -o bin/ro-git ./cmd/ro-git
go build -o bin/ro-find ./cmd/ro-find

# Clean build artifacts
make clean
```

### Installation
```bash
# Install to /usr/local/bin
make install

# Uninstall
make uninstall

# Install to custom location
make install DESTDIR=/custom/path
```

### Testing
```bash
# Run basic tests
make test

# Test individual commands
./bin/ro-git --version
./bin/ro-find . -name "*.go"
```

## Code Architecture

### Project Structure
```
cmd/
  ro-git/      # Read-only git wrapper
    main.go
  ro-find/     # Read-only find wrapper
    main.go
bin/           # Built binaries (created by make build)
```

### Key Components

#### ro-git
- **Purpose**: Prevents any git commands that could modify the repository
- **Implementation**: Go program that validates git commands before execution
- **Security**: Blocks write operations like commit, push, add, reset, etc.
- **Location**: `cmd/ro-git/main.go`

#### ro-find
- **Purpose**: Prevents any find commands that could execute or delete files
- **Implementation**: Go program that validates find options before execution
- **Security**: Blocks dangerous options like -exec, -delete, -ok, etc.
- **Location**: `cmd/ro-find/main.go`

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

### Adding New Wrappers

1. Create new directory under `cmd/` (e.g., `cmd/ro-ls/`)
2. Implement wrapper logic in `main.go`
3. Add build rule to Makefile
4. Update this documentation

### Common Tasks

```bash
# Format code
make fmt

# Build and test
make build && make test

# Run specific wrapper
./bin/ro-git log --oneline
./bin/ro-find . -name "*.go" -type f
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

### ro-git
- **Safe commands**: log, show, diff, status, grep, blame, etc.
- **Blocked commands**: add, commit, push, pull, merge, rebase, etc.
- **Special handling**: config commands are analyzed for write operations

### ro-find
- **Safe options**: -name, -type, -size, -mtime, etc.
- **Blocked options**: -exec, -execdir, -ok, -okdir, -delete
- **Special handling**: -printf/-fprintf with file redirection is blocked