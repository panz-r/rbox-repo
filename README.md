# ReadOnlyBox

**A ptrace-based command interceptor for user-decided execution**

[![C](https://img.shields.io/badge/C-C11-555?style=for-the-badge&logo=c)](https://en.cppreference.com/w/c/11)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

## Overview

ReadOnlyBox intercepts commands via ptrace and sends them to rbox-server for user decisions. The rbox-server TUI presents each command, allowing or denying execution with time-limited permissions.

## Installation

### From Source

```bash
git clone https://github.com/panz-r/rbox-repo.git
cd rbox-repo
git submodule update --init
mage build
mage install
```

## Usage

### Start the Server

```bash
# Interactive TUI mode
readonlybox-server

# Auto-deny unknown commands
readonlybox-server --auto-deny
```

### Run Commands Through Interceptor

```bash
# Restricted shell: no network, 1GB memory, read-only /etc, read-write /tmp
readonlybox-ptrace --no-network --memory-limit 1G \
    --hard-allow /w:rwx,/usr/bin:rx,/lib64:rx,/usr/lib:rx,/etc:ro,/tmp:rw,/proc:ro -- bash
```

### Server Options

```bash
-q              # Quiet mode (blocked commands only)
-v              # Verbose mode (show all commands)
--auto-deny     # Deny unknown commands automatically
--tui           # Interactive TUI mode
```

### Client Configuration

```bash
# Custom socket path
READONLYBOX_SOCKET=/var/run/readonlybox.sock readonlybox-ptrace -- vim
```

## License

MIT License - See [LICENSE](LICENSE) for details.
