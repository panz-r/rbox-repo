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

# Build all tools (including LD_PRELOAD client and TUI server)
mage build

# Install to /usr/local/bin
mage install
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
# Build all tools (including TUI server and LD_PRELOAD client)
mage build

# Clean build artifacts
mage clean

# Run tests
mage test

# Install to /usr/local/bin
mage install

# Uninstall
make uninstall
```

---

## 🖥️ LD_PRELOAD Server & Client

The LD_PRELOAD server provides real-time command interception and policy enforcement over a Unix socket.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           System Process                             │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Shell (sh, bash, etc.)                                        │  │
│  │ LD_PRELOAD=libreadonlybox_client.so                           │  │
│  │                                                               │  │
│  │  execve("/bin/ls", ...)  →  fast allow (execute directly)    │  │
│  │  execve("/bin/vim", ...) →  send to server                   │  │
│  │                           ↓                                   │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │           Time-Limited Decision Cache                   │ │  │
│  │  │     (CLOCK_BOOTTIME - survives suspend/resume)          │ │  │
│  │  │                                                          │ │  │
│  │  │  Cache hit? → Return cached decision immediately         │ │  │
│  │  │  Cache miss → Send to server                             │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  │                           ↓                                   │  │
│  │              ┌──────────────────────────┐                    │  │
│  │              │   Unix Socket            │                    │  │
│  │              │ /tmp/readonlybox.sock    │                    │  │
│  │              └───────────┬──────────────┘                    │  │
│  └──────────────────────────┼───────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│              ┌───────────────────────────────┐                        │
│              │    readonlybox-server         │                        │
│              │    (Go + Bubble Tea TUI)      │                        │
│              │                               │                        │
│              │  ┌─────────────────────────┐  │                        │
│              │  │   Protocol v3 Handler   │  │                        │
│              │  │   - Client UUID         │  │                        │
│              │  │   - Request UUID        │  │                        │
│              │  │   - Server UUID         │  │                        │
│              │  └─────────────────────────┘  │                        │
│              │              ↓                │                        │
│              │  ┌─────────────────────────┐  │                        │
│              │  │   Policy Engine         │  │                        │
│              │  │   - Auto-deny           │  │                        │
│              │  │   - TUI decisions       │  │                        │
│              │  │   - Policy file         │  │                        │
│              │  └─────────────────────────┘  │                        │
│              │              ↓                │                        │
│              │  ┌─────────────────────────┐  │                        │
│              │  │   Time-Limited Response │  │                        │
│              │  │   ALLOW:4h, DENY:15m    │  │                        │
│              │  │   (durations: 1x,15m,1h,4h)  │                    │
│              │  └─────────────────────────┘  │                        │
│              └───────────────────────────────┘                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Protocol v3 (UUID-Based Request Matching)

The protocol uses UUIDs for robust request/response matching across reconnects:

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `0x524F424F` ("ROBO") |
| Version | 4 bytes | Protocol version (3) |
| Client UUID | 16 bytes | Unique client identifier |
| Request UUID | 16 bytes | Per-request identifier (incremented) |
| Server UUID | 16 bytes | Server identifier (for cache validation) |
| Message ID | 4 bytes | `0`=LOG, `1`=REQUEST |
| argc/envc | 4 bytes each | Argument/environment counts |
| Payload | Variable | Command, args, env vars |

**Time-Limited Decision Format:**
```
ALLOW           - Allow once (no caching)
ALLOW:15m       - Allow for 15 minutes
ALLOW:1h        - Allow for 1 hour
ALLOW:4h        - Allow for 4 hours
DENY            - Deny once (no caching)
DENY:15m        - Deny for 15 minutes
DENY:1h         - Deny for 1 hour
DENY:4h         - Deny for 4 hours
```

### Time-Limited Decision Cache

The client implements a time-limited decision cache using `CLOCK_BOOTTIME` which correctly handles system suspend/resume cycles:

| Feature | Description |
|---------|-------------|
| **Clock Source** | `CLOCK_BOOTTIME` (includes suspend time) |
| **Cache Size** | 128 entries |
| **Cache Key** | Full command string (cmd + args) |
| **Expiry** | Per-decision duration (1x, 15m, 1h, 4h) |
| **Cleanup** | Opportunistic (on cache access) |

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

**All other commands** (`rm`, `mv`, `cp`, `mkdir`, `chmod`, `chown`, `vim`, `git`, `ssh`, etc.) are sent to the server for policy decision.

### Build Server and Client

The `mage build` command builds both the TUI server and the LD_PRELOAD client:

```bash
# Build everything (tools, server, client)
mage build

# Build outputs are in bin/ and internal/client/:
# - bin/readonlybox-server        (TUI server)
# - internal/client/libreadonlybox_client.so  (LD_PRELOAD client)
```

### Run the Server

```bash
# Quiet mode (blocked commands only)
./bin/readonlybox-server -q

# Verbose mode (show all commands)
./bin/readonlybox-server -v

# TUI mode (interactive terminal UI - REQUIRES TERMINAL)
./bin/readonlybox-server --tui

# Debug TUI mode (auto-allow after 500ms for testing)
./bin/readonlybox-server --debug-tui

# Auto-deny mode (deny all unknown commands - for testing)
./bin/readonlybox-server --auto-deny
```

### Test with LD_PRELOAD Client

```bash
# Start server
./bin/readonlybox-server --auto-deny &

# Test blocked command
READONLYBOX_SOCKET=/tmp/readonlybox.sock \
LD_PRELOAD=internal/client/libreadonlybox_client.so \
vim --version

# Cleanup
pkill -f readonlybox-server
```

> **Note**: TUI mode requires an interactive terminal. Run in a real terminal (not SSH without -t, not in VS Code terminal that doesn't support full screen).

### TUI Mode

The interactive TUI shows pending requests with risk indicators and waits for user approval:

```
┌─────────────────────────────────────────────────────────┐
│ ✓ ALLOWED  ✗ DENIED  Pending: 2  15:04:05              │
├─────────────────────────────────────────────────────────┤
│ Requests:                                              │
│ ● 15:04 python3 --version [#3]        [RISK: MEDIUM]   │
│ ►● 15:03 python3 -c "print(1)" [#2]   [RISK: MEDIUM]   │
│ ◉ 15:02 rm /tmp/test [#1]             [RISK: CRITICAL] │
├─────────────────────────────────────────────────────────┤
│ Clients: client1 | client2                             │
├─────────────────────────────────────────────────────────┤
│ #2 python3 -c "print(1)"                               │
│  15:03:05  Client: @  [RISK: MEDIUM] [details]         │
│                                                          │
│  python3 -c "print(1)"                                  │
│                                                          │
│ Allow:  [1] Once   [2] 15m   [3] 1h    [4] 4h       │
│ Deny:   [5] Once   [6] 15m   [7] 1h    [8] 4h       │
│ Policy: allow command=python3 args="print(1)"           │
├─────────────────────────────────────────────────────────┤
│ Risk: ● LOW  ● MEDIUM  ● HIGH  ◉ CRITICAL              │
│ Controls: [Tab/←→] focus [↑↓] select [1-8] action [q] quit
└─────────────────────────────────────────────────────────┘
```

**Decision Options (Time-Limited):**

| Key | Decision | Duration |
|-----|----------|----------|
| `1` | Allow | Once (no caching) |
| `2` | Allow | 15 minutes |
| `3` | Allow | 1 hour |
| `4` | Allow | 4 hours |
| `5` | Deny | Once (no caching) |
| `6` | Deny | 15 minutes |
| `7` | Deny | 1 hour |
| `8` | Deny | 4 hours |

**Risk Indicators:**
| Symbol | Risk Level | Color |
|--------|------------|-------|
| ● | LOW | Green |
| ● | MEDIUM | Orange |
| ● | HIGH | Red |
| ◉ | CRITICAL | Bright Red |

### TUI Controls

| Key | Action |
|-----|--------|
| `Tab` / `←` / `→` | Cycle focus between sections |
| `↑` / `↓` | Select items within focused section |
| `1`-`8` | Decision with time duration |
| `q` | Quit |

### Policy File

When using `[2]` or `[4]` actions, policies are saved to a file:

```bash
# Default location
/tmp/readonlybox_policies.conf

# Custom location
READONLYBOX_POLICY_FILE=/etc/readonlybox-policies.conf ./readonlybox-server --tui
```

**Policy Format:**
```
2026-01-15 15:04:05 allow command=python3 args="print(1)" # risk=MEDIUM
2026-01-15 15:04:10 deny command=rm args="/tmp/test" # risk=CRITICAL
```

Policies can be reviewed and loaded for automated decision-making in the future.

### TUI Behavior

- **Dangerous commands** (`rm`, `mv`, `cp`, etc.): Immediately denied by server policy
- **Unknown commands** (e.g., `python3`): Client blocks indefinitely waiting for user decision in TUI mode
- **Fast allow commands**: Execute directly without server consultation

### Client Blocking Behavior

The client implements strict blocking for security:

1. **No timeouts**: Client waits indefinitely for server decision
2. **Automatic reconnection**: If server connection dies, client retries until connected
3. **Request resend**: After reconnecting, request is resent to server
4. **Proceed only on decision**: Command executes only after receiving ALLOW from server

```
Client Request Flow:
  execve() → send to server → wait for decision
                    ↓
           connection dies?
              ↓yes      ↓no
          reconnect     wait
              ↓          ↓
            resend   ALLOW/DENY?
              ↓          ↓no
            wait → ALLOW/DENY?
              ↓
        ALLOW → execute command
        DENY → return error
```

### Debug Mode

For testing without a terminal, use `--debug-tui` to simulate TUI decisions:

```bash
./readonlybox-server --debug-tui -vv
```

Unknown commands will wait 30 seconds for a (simulated) decision, then auto-allow.

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

The server uses Protocol v3, a binary protocol over Unix socket with UUID-based request matching:

**Message Types (ID field):**
| ID | Type | Purpose |
|----|------|---------|
| 0 | `ROBO_MSG_LOG` | Client debug/status logs |
| 1 | `ROBO_MSG_REQ` | Command execution requests |

**Request Packet Structure (Protocol v3):**
```
[magic:4][version:4][client_uuid:16][request_uuid:16][server_uuid:16][id:4][argc:4][envc:4][cmd\0][arg0\0]...[env0\0]...
```

| Field | Size | Description |
|-------|------|-------------|
| magic | 4 bytes | `0x524F424F` ("ROBO") |
| version | 4 bytes | Protocol version (3) |
| client_uuid | 16 bytes | Unique client identifier (generated on library load) |
| request_uuid | 16 bytes | Per-request identifier (incremented for each request) |
| server_uuid | 16 bytes | Server identifier (filled by server, used for cache validation) |
| id | 4 bytes | Message type (0=LOG, 1=REQ) |
| argc | 4 bytes | Argument count |
| envc | 4 bytes | Environment variable count |
| cmd | N+1 bytes | Null-terminated command string |
| args | ... | Null-terminated argument strings |
| env | ... | Null-terminated environment strings |

**Response Packet:**
```
[magic:4][version:4][client_uuid:16][request_uuid:16][server_uuid:16][id:4][decision:1][padding:3][reason_len:4][reason\0]
```

| Field | Size | Description |
|-------|------|-------------|
| decision | 1 byte | `2`=ALLOW, `3`=DENY, `4`=ERROR |
| reason_len | 4 bytes | Reason string length |
| reason | N bytes | Null-terminated reason (e.g., "ALLOW:4h", "DENY:15m") |

**Time-Limited Decision Reasons:**
| Reason | Meaning |
|--------|---------|
| `ALLOW` | Allow once (no caching) |
| `ALLOW:4h` | Allow for 4 hours |
| `ALLOW:1h` | Allow for 1 hour |
| `ALLOW:15m` | Allow for 15 minutes |
| `DENY` | Deny once (no caching) |
| `DENY:4h` | Deny for 4 hours |
| `DENY:1h` | Deny for 1 hour |
| `DENY:15m` | Deny for 15 minutes |

### Client Configuration

The client library uses environment variables for configuration:

| Variable | Description | Default |
|----------|-------------|---------|
| `READONLYBOX_SOCKET` | Unix socket path | `/tmp/readonlybox.sock` |

**Usage:**
```bash
# Start server with custom socket
./readonlybox-server -socket /var/run/readonlybox.sock

# Client connects to custom socket
READONLYBOX_SOCKET=/var/run/readonlybox.sock LD_PRELOAD=libreadonlybox_client.so vim
```

### Testing

Test the LD_PRELOAD system:

```bash
# Terminal 1: Start server
./readonlybox-server -v

# Terminal 2: Run client
READONLYBOX_SOCKET=/tmp/readonlybox.sock \
LD_PRELOAD=bin/libreadonlybox_client.so \
vim --version

# Or use a simple test program
cat > /tmp/test_block.c << 'EOF'
#include <unistd.h>
int main() {
    char *args[] = {"vim", "--version", NULL};
    execve("/usr/bin/vim", args, NULL);
    return 1;
}
EOF
gcc -o /tmp/test_block /tmp/test_block.c

READONLYBOX_SOCKET=/tmp/readonlybox.sock \
LD_PRELOAD=bin/libreadonlybox_client.so \
/tmp/test_block
```

### Recovery Scenarios

The system handles various failure scenarios:

| Scenario | Behavior |
|----------|----------|
| Server unavailable | Client retries with exponential backoff (50ms → 120s) |
| Server restart | UUID-based request matching ensures correct response |
| Socket timeout | Client retries request after reconnect |
| Suspend/resume | CLOCK_BOOTTIME ensures cache validity |

**UUID Request Matching:**
- Each client generates a unique Client UUID on library load
- Each request has a unique Request UUID (incremented per request)
- Server stores recent requests by UUID
- If client reconnects after server restart, server can match UUIDs

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
