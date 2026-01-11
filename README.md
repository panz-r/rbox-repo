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