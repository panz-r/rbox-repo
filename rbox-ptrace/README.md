# ReadOnlyBox Ptrace

A ptrace-based command wrapper that intercepts and validates system calls before execution.

## Overview

`readonlybox-ptrace` uses Linux's `ptrace` mechanism to intercept `execve` system calls and validate commands against a DFA before allowing execution. This provides an additional layer of security by catching dangerous commands before they run.

## Building

```bash
# Build with make
cd rbox-ptrace && make

# Build tests
cd rbox-ptrace && make test
```

### Requirements

- GCC or Clang
- Linux with ptrace support
- polkit (optional, for authentication dialogs)
- PolicyKit (optional, for pkexec support)

## Usage

```bash
# Basic usage
readonlybox-ptrace wrap bash

# Example: Run with basic security restrictions (network blocked, memory limited)
./trace-bash-basic.sh

# Attach to existing process
readonlybox-ptrace -p <pid> -- <command>

# Run as specific user
readonlybox-ptrace -u 1000 -- <command>

# Set working directory
readonlybox-ptrace -c /tmp -- <command>

# Memory limit
readonlybox-ptrace --memory-limit 256M -- <command>

# Landlock allowed paths (read-only)
readonlybox-ptrace --landlock-paths /var/log:ro,/etc:ro -- <command>

# Block network access
readonlybox-ptrace --no-network -- <command>
```

## Privilege Escalation

`readonlybox-ptrace` requires elevated privileges to use ptrace. There are several methods:

### Method 1: Linux Capabilities (Recommended)

Set capabilities on the binary for persistent, transparent operation:

```bash
# Development helper (sets on local binary)
./dev-setcap.sh

# Or manually
sudo setcap cap_sys_ptrace,cap_sys_admin+eip ./readonlybox-ptrace
./readonlybox-ptrace wrap bash  # No sudo needed
```

### Method 2: pkexec (Automatic)

If the binary lacks capabilities, it automatically attempts `pkexec`:

```bash
./readonlybox-ptrace wrap bash  # Shows authentication dialog
```

### Method 3: sudo

```bash
sudo ./readonlybox-ptrace wrap bash
```

## PolicyKit Integration

### Overview

When `readonlybox-ptrace` runs without ptrace capabilities, it uses `pkexec` for privilege escalation. A custom PolicyKit configuration provides a descriptive authentication dialog.

### Policy File

The `readonlybox-ptrace.policy` file provides a customized authentication dialog with:
- Better description of what the program does
- Custom icon
- Configurable authorization rules

### Installation (Optional)

To enable the custom authentication dialog (instead of a generic one):

```bash
sudo cp readonlybox-ptrace.policy /usr/share/polkit-1/actions/org.freedesktop.policykit.pkexec.readonlybox-ptrace.policy
```

**Note**: This is purely cosmetic. The program works identically with or without the policy file - it only changes what the authentication dialog looks like.

### How It Works

1. **First**: Checks if it has CAP_SYS_PTRACE
2. **If not**: Attempts to use `pkexec` for automatic privilege escalation
3. **If pkexec fails**: Displays error with instructions to use sudo or setcap

## Troubleshooting

### "Cannot use ptrace: Operation not permitted"

**Cause**: Missing ptrace capabilities.

**Solution**: Use one of the privilege escalation methods above:
```bash
# Option 1: Use sudo
sudo ./readonlybox-ptrace wrap <command>

# Option 2: Set capabilities (permanent)
sudo setcap cap_sys_ptrace,cap_sys_admin+eip ./readonlybox-ptrace
```

### "pkexec: command not found"

**Cause**: PolicyKit is not installed.

**Solution**: Install polkit or use sudo:
```bash
sudo ./readonlybox-ptrace wrap bash
```

### Generic Authentication Dialog

**Cause**: Policy file is not installed.

**Solution**: Install the policy file:
```bash
sudo cp readonlybox-ptrace.policy /usr/share/polkit-1/actions/
```

## Desktop Environment Support

PolicyKit authentication dialogs work on:
- **GNOME**: polkit-gnome-authentication-agent-1
- **KDE**: polkit-kde-authentication-agent-1
- **XFCE**: polkit-gnome-authentication-agent-1
- **MATE**: polkit-mate-authentication-agent-1
- **Cinnamon**: polkit-gnome-authentication-agent-1

## Security Considerations

- ptrace provides deep visibility into process execution
- All commands are validated by the DFA before execution
- Landlock can restrict filesystem access
- Network access can be blocked
- Memory limits protect against resource exhaustion

## Testing

```bash
# Run all tests
make -C rbox-ptrace/tests test

# Run specific test suites
make -C rbox-ptrace/tests test-memory
make -C rbox-ptrace/tests test-syscall
make -C rbox-ptrace/tests test-validation

# Run with valgrind
make -C rbox-ptrace/tests valgrind

# Run static analysis
make -C rbox-ptrace/tests cppcheck
```
