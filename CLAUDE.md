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

## Current Tools

### ro-git
- **Safe commands**: log, show, diff, status, grep, blame, etc.
- **Blocked commands**: add, commit, push, pull, merge, rebase, etc.
- **Special handling**: config commands are analyzed for write operations

### ro-find
- **Safe options**: -name, -type, -size, -mtime, etc.
- **Blocked options**: -exec, -execdir, -ok, -okdir, -delete
- **Special handling**: -printf/-fprintf with file redirection is blocked