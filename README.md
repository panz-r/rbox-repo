# ReadOnlyBox 🔒

**A BusyBox-like read-only toolbox for secure system exploration**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-ReadOnly-green.svg?style=for-the-badge)](https://github.com/panz/openroutertest)

## 🚀 Overview

ReadOnlyBox is a **single binary** that provides **26+ read-only command wrappers** for safe system exploration. Inspired by BusyBox, ReadOnlyBox consolidates essential Linux commands into one executable while **preventing all write operations**.

Perfect for:
- **Security audits** - Explore systems without risk
- **Forensic analysis** - Examine files and processes safely
- **Restricted environments** - Provide read-only access
- **Education** - Learn system commands safely
- **Container security** - Limit container capabilities

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/panz/openroutertest.git
cd openroutertest

# Build the single binary
make build

# Install to /usr/local/bin
make install
```

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/panz/openroutertest/releases) page.

### Package Managers (Coming Soon)

```bash
# Debian/Ubuntu
sudo apt install readonlybox

# RHEL/CentOS
sudo yum install readonlybox

# Homebrew
brew install readonlybox
```

## 🎯 Usage

ReadOnlyBox follows a BusyBox-like interface:

```bash
readonlybox <command> [arguments...]
```

### Basic Usage

```bash
# Show help and available commands
readonlybox

# List files (read-only ls)
readonlybox ls -la

# View file contents (read-only cat)
readonlybox cat /etc/passwd

# Search for files (read-only find)
readonlybox find /home -name "*.txt"

# Check process status (read-only ps)
readonlybox ps aux

# Check disk usage (read-only df)
readonlybox df -h

# View git history (read-only git)
readonlybox git log --oneline
```

### Available Commands

| Category | Commands |
|----------|----------|
| **System Info** | `ps`, `df`, `du`, `uname`, `wc` |
| **File Operations** | `ls`, `cat`, `grep`, `head`, `tail`, `touch`, `dd` |
| **Version Control** | `git` (read-only operations) |
| **Search** | `find`, `grep` |
| **Text Processing** | `sed`, `sort`, `echo` |
| **System Tools** | `date`, `timeout`, `ulimit`, `cd`, `bash` |
| **File Management** | `chmod`, `chown`, `mkdir`, `rmdir`, `ln`, `mv`, `cp`, `rm` |

**Total: 26+ read-only commands!**

## 🔒 Security Features

ReadOnlyBox **blocks all write operations** while allowing safe read-only exploration:

### 🛡️ Protected Operations

| Command | Blocked Operations |
|---------|-------------------|
| **git** | `add`, `commit`, `push`, `pull`, `merge`, `rebase`, `reset`, etc. |
| **find** | `-exec`, `-delete`, `-ok` |
| **ls/cat/grep** | File redirection (`>`, `>>`) |
| **All commands** | Command injection (`\``, `$`), long arguments (50+ chars) |

### 🚨 Security Examples

```bash
# ❌ BLOCKED - Write operations
readonlybox git add .
# Error: write operation not allowed

readonlybox git commit -m "test"
# Error: write operation not allowed

readonlybox find . -exec rm {} \;
# Error: can execute commands

# ✅ ALLOWED - Read-only operations
readonlybox git log
readonlybox git show
readonlybox find . -name "*.go"
readonlybox cat /etc/passwd
```

## 🔧 Development

### Build System

```bash
# Build all tools (single binary)
make build

# Clean build artifacts
make clean

# Run tests
make test

# Install to /usr/local/bin
make install

# Uninstall
make uninstall
```

---

## 🖥️ LD_PRELOAD Server & Client

The LD_PRELOAD server provides real-time command interception and policy enforcement over a Unix socket.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│ Shell (sh, bash, etc.)                              │
│ LD_PRELOAD=libreadonlybox_client.so                 │
│                                                      │
│ execve("/bin/ls", ...) → fast allow (execute)       │
│ execve("/bin/rm", ...) → send to server             │
│     ↓                                               │
│ Server evaluates policy                             │
│     ↓                                               │
│ ALLOW → execute command                             │
│ DENY → return error                                 │
└─────────────────────────────────────────────────────┘
```

### Fast Allow Commands

Commands in this list are executed directly without server consultation:

| Category | Commands |
|----------|----------|
| **File Ops** | `ls`, `cat`, `head`, `tail`, `wc`, `stat`, `file` |
| **Text Proc** | `sort`, `uniq`, `grep`, `tr`, `cut`, `join`, `paste`, `diff`, `comm`, `nl`, `od` |
| **System** | `date`, `pwd`, `hostname`, `uname`, `whoami`, `id`, `who`, `last`, `uptime` |
| **Utils** | `echo`, `printenv`, `sleep`, `expr`, `timeout`, `basename`, `dirname`, `readlink`, `which`, `test`, `[` |
| **Search** | `find`, `xargs` |
| **Other** | `true`, `false`, `null`, `base64`, `strings` |

**All other commands** (`rm`, `mv`, `cp`, `mkdir`, `chmod`, `chown`, etc.) are sent to the server for policy decision.

### Build Server and Client

```bash
# Build the server (Go)
cd cmd/readonlybox-server
go build -o ../../readonlybox-server .

# Build the client (C)
cd internal/client
gcc -shared -fPIC -O2 -o libreadonlybox_client.so client.c -pthread
```

Or use the helper script:

```bash
./scripts/build-all.sh
```

### Run the Server

```bash
# Quiet mode (blocked commands only)
./readonlybox-server -q

# Verbose mode (show all commands)
./readonlybox-server -v

# Very verbose mode (show commands + client logs)
./readonlybox-server -vv

# TUI mode (interactive terminal UI)
./readonlybox-server --tui
```

### Test with Client

```bash
# Preload the library into a shell
LD_PRELOAD=./internal/client/libreadonlybox_client.so sh -c 'rm /tmp/testfile'

# The rm command will be blocked and logged to the server

# Test read-only commands (allowed)
LD_PRELOAD=./internal/client/libreadonlybox_client.so ls /tmp

# Test other commands
LD_PRELOAD=./internal/client/libreadonlybox_client.so cat /etc/hostname
```

### Socket Path

By default, the server listens on `/tmp/readonlybox.sock`. Use environment variable to customize:

```bash
# Custom socket path
READONLYBOX_SOCKET=/var/run/readonlybox.sock LD_PRELOAD=... sh -c 'rm /tmp/testfile'
```

### Server Flags

| Flag | Description |
|------|-------------|
| `-socket <path>` | Unix socket path (default: /tmp/readonlybox.sock) |
| `-q` | Quiet mode: show blocked commands only |
| `-v` | Verbose mode: show all commands |
| `-vv` | Very verbose mode: show commands + client logs |
| `-p <port>` | Also listen on TCP port (0=disabled) |
| `--tui` | Run in interactive TUI mode |

### Protocol

The server uses a binary protocol over Unix socket:

**Message Types (ID field):**
| ID | Type | Purpose |
|----|------|---------|
| 0 | `ROBO_MSG_LOG` | Client debug/status logs |
| 1+ | `ROBO_MSG_REQ` | Command execution requests |

**Packet Structure:**
```
[magic:4][id:4][argc:4][envc:4][cmd\0][arg0\0]...[env0\0]...
```

**Response:**
```
[magic:4][id:4][decision:1][padding:3][reason_len:4][reason\0]
```

### Adding New Commands

To add a new read-only wrapper:

1. **Create security module** in `internal/ro<command>/`
2. **Add command handler** in `internal/readonlybox/commands.go`
3. **Register command** in the `CommandRegistry`
4. **Add tests** following existing patterns

Example structure:
```
cmd/ro<command>/main.go          # Individual wrapper (legacy)
internal/ro<command>/<command>.go # Security validation
internal/ro<command>/<command>_test.go # Unit tests
```

## 📚 Architecture

### Single Binary Design

```
readonlybox (single binary)
├── Command Registry (26+ commands)
├── Security Validation Modules
│   ├── rogit (git security)
│   ├── rofind (find security)
│   ├── rops (ps security)
│   └── ... (all other commands)
└── Unified Execution Engine
```

### Security Validation Flow

```
User Input → Command Parsing → Security Check → Safe Execution
                     ↓
               (Block if dangerous)
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-command`
3. **Commit changes**: `git commit -am 'Add new command'`
4. **Push to branch**: `git push origin feature/new-command`
5. **Create a Pull Request**

### Development Requirements

- Go 1.21+
- Make
- Standard Linux environment

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Inspired by BusyBox architecture
- Built with Go for security and performance
- Designed for system administrators and security professionals

## 📬 Contact

- **Project**: [github.com/panz/openroutertest](https://github.com/panz/openroutertest)
- **Issues**: [GitHub Issues](https://github.com/panz/openroutertest/issues)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

---

**ReadOnlyBox - Safe system exploration, one command at a time! 🔒**
