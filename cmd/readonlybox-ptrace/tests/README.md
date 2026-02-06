# ReadOnlyBox Ptrace Client Unit Tests

This directory contains comprehensive unit tests for the ptrace client components.

## Test Structure

The test suite is organized into the following modules:

### 1. Memory Tests (`test_memory.c`)
Tests for the memory operations module:
- Memory context initialization
- String reading/writing operations
- String array handling
- Memory cleanup operations
- Edge cases (NULL pointers, empty arrays)

### 2. Syscall Handler Tests (`test_syscall_handler.c`)
Tests for the syscall interception and handling:
- Process state table management
- Syscall number detection (execve, fork, clone, vfork)
- Register macro functionality
- Process state lifecycle
- Architecture-specific syscall numbers

### 3. Validation Tests (`test_validation.c`)
Tests for command validation and protocol:
- DFA-based validation
- Protocol constants and limits
- Environment variable handling
- Socket path configuration
- Various command patterns (simple, complex, piped, etc.)

### 4. Integration Tests (`test_integration.c`)
Tests for component interactions and complex scenarios:
- Full initialization sequences
- Multiple init/shutdown cycles
- Process state with execve simulation
- Multiple processes with different states
- Hash table collision handling
- Error handling paths
- Concurrent process simulation

### 5. End-to-End Tests (`test_e2e.c`)
Tests that run actual commands through the ptrace client with a real server:
- Safe commands (ls, echo, cat, pwd, date) - allowed by DFA
- Dangerous commands (rm, mkdir) - denied by server with `-auto-deny`
- Write operations - denied by server
- Server modes: `-auto-deny` and `-debug-tui` (auto-allow)
- Command with arguments
- Non-existent command handling

## Building and Running Tests

### Build the test runner:
```bash
make
```

### Run unit tests (excludes e2e):
```bash
make test
```

### Run end-to-end tests (requires server binary):
```bash
make test-e2e
```

### Run specific test suites:
```bash
make test-memory       # Memory operation tests
make test-syscall      # Syscall handler tests
make test-validation   # Validation tests
make test-integration  # Integration tests
make test-e2e          # End-to-end tests
```

### Run with verbose output:
```bash
make test-verbose
```

### List available test suites:
```bash
make list
```

### Clean build files:
```bash
make clean
```

## Command Line Usage

The test runner supports various command line options:

```bash
./test_runner [options] [test_suite...]
```

### Options:
- `-h, --help`     - Show help message
- `-l, --list`     - List available test suites
- `-v, --verbose`  - Enable verbose output

### Test Suites:
- `memory`       - Run memory operation tests
- `syscall`      - Run syscall handler tests
- `validation`   - Run validation tests
- `integration`  - Run integration tests
- `e2e`          - Run end-to-end tests (requires server)
- `all`          - Run all unit tests (default, excludes e2e)

### Examples:
```bash
./test_runner                       # Run unit tests
./test_runner memory                # Run only memory tests
./test_runner memory syscall        # Run memory and syscall tests
./test_runner e2e                   # Run end-to-end tests
./test_runner -v                    # Run with verbose output
./test_runner integration -v        # Run integration tests with verbose output
```

## End-to-End Tests

The e2e tests require the `readonlybox-server` binary to be available. They test the full integration:

### Safe Commands (DFA fast-path):
- `ls`, `echo`, `cat`, `pwd`, `date` - Allowed by DFA without server contact

### Dangerous Commands (Server denies with `-auto-deny`):
- `rm`, `mkdir`, `cp`, `mv` - Blocked by server
- Write operations with `>` redirection - Blocked by server

### Server Modes:
- **`-auto-deny`**: Automatically denies unknown/dangerous commands
- **`-debug-tui`**: Auto-allows commands after 500ms timeout

### Running E2E Tests:
```bash
# Build the server first
cd ../readonlybox-server
go build

# Run e2e tests
cd ../readonlybox-ptrace/tests
./test_runner e2e
```

## Advanced Build Options

### Debug Build:
```bash
make debug
```

### Coverage Analysis (requires gcov):
```bash
make coverage
```

### Static Analysis (requires cppcheck):
```bash
make cppcheck
```

### Memory Leak Detection (requires valgrind):
```bash
make valgrind
```

## Test Output Format

Tests produce output in the following format:

```
=================================================
  ReadOnlyBox Ptrace Client Unit Tests
=================================================

=== Memory Tests ===
  Running memory_init_valid... PASSED
  Running memory_init_null_context... PASSED
  ...

=== Syscall Handler Tests ===
  Running syscall_handler_init_basic... PASSED
  ...

=== Validation Tests ===
  Running validation_init_basic... PASSED
  ...

=== Integration Tests ===
  Running full_initialization_sequence... PASSED
  ...

=== End-to-End Tests ===
  Running safe_command_ls_auto_deny... PASSED
  ...

=================================================
  Test Summary
=================================================
  Total tests run:    77
  Tests passed:       77
  Tests failed:       0

  ALL TESTS PASSED!
=================================================
```

## Adding New Tests

To add new tests:

1. **Add test function to appropriate test file:**
   ```c
   TEST(new_test_name) {
       // Test code here
       ASSERT_EQ(expected, actual);
   }
   ```

2. **Register the test in the run function:**
   ```c
   void run_memory_tests(void) {
       // ... existing tests ...
       RUN_TEST(new_test_name);
   }
   ```

3. **Rebuild and run:**
   ```bash
   make clean && make test
   ```

## Test Macros

The following macros are available for writing tests:

- `TEST(name)` - Define a test function
- `RUN_TEST(name)` - Run a test and record results
- `ASSERT(cond)` - Assert a condition is true
- `ASSERT_EQ(a, b)` - Assert two values are equal
- `ASSERT_NE(a, b)` - Assert two values are not equal
- `ASSERT_NULL(p)` - Assert pointer is NULL
- `ASSERT_NOT_NULL(p)` - Assert pointer is not NULL
- `ASSERT_STR_EQ(a, b)` - Assert two strings are equal

## Architecture Support

The tests support both x86_64 and i386 architectures:
- Syscall numbers are architecture-specific
- Register macros adapt to the architecture
- Tests verify correct architecture detection

## Notes

- Some tests use fake PIDs that don't exist (e.g., 99999) to avoid interfering with real processes
- DFA tests depend on the compiled DFA data and may return different results based on the DFA configuration
- Memory tests that involve ptrace operations may be limited when not running under ptrace
- Integration tests verify component interactions and may take longer to run
- E2E tests require the server binary and create temporary files in `/tmp`
