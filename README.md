# ReadOnlyBox 🔒

**A ptrace-based command interceptor for secure system exploration**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

## 🚀 Overview

ReadOnlyBox intercepts commands via ptrace and sends them to rbox-server for user decisions. The rbox-server TUI presents each command to the user, who can allow or deny execution with various time-limited permissions.

Perfect for:
- **Security audits** - Inspect commands before execution
- **Forensic analysis** - Review all attempted commands
- **Restricted environments** - Control what commands can run
- **Learning** - Understand what commands applications attempt
- **Container security** - Intercept commands in containers

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/panz-r/rbox-repo.git
cd rbox-repo

# Build all tools (ptrace client, rbox-server TUI)
mage build

# Install to /usr/local/bin
mage install
```

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

ReadOnlyBox uses ptrace to intercept commands and presents a TUI for user decisions.

### Starting the Server

```bash
# Start the rbox-server TUI (in one terminal)
readonlybox-server

# Or run rbox-server with auto-deny for unknown commands
readonlybox-server --auto-deny
```

### Running Commands Through the Interceptor

```bash
# Run commands through ptrace interceptor (from another terminal)
readonlybox-ptrace -- /bin/ls -la

# Intercept git commands
readonlybox-ptrace -- git status
readonlybox-ptrace -- git log --oneline

# View files
readonlybox-ptrace -- cat /etc/passwd

# Search for files
readonlybox-ptrace -- find /home -name "*.txt"
```

## 🔒 How It Works

1. **Intercept**: `readonlybox-ptrace` uses ptrace to intercept command execution
2. **Analyze**: Commands are validated against DFA patterns and analyzed for danger
3. **Decide**: rbox-server TUI presents the command for user approval
4. **Execute**: User allows or denies - the command proceeds or is blocked

### User Decisions

In the rbox-server TUI, each command shows:
- Full command with arguments
- Caller and syscall information (when available)
- Flagged environment variables (v8 protocol)

User can:
- **Allow/Deny** with duration: Once, 15m, 1h, 4h, or session
- **Pattern rules**: Auto-allow/deny similar commands

## 🔧 Development

### Build System

This project uses [Mage](https://magefile.org/) as the primary build orchestrator for the Go components, with Make for C subprojects.

```bash
# Build all tools (rbox-ptrace, rbox-server)
mage build

# Build DFA tools only (nfa_builder, nfa2dfa_advanced, dfa2c_array)
mage deps

# Validate command pattern files
mage validate

# Clean build artifacts
mage clean

# Run tests
mage test

# Install to /usr/local/bin
mage install

# Show help
mage -h
```

### Subprojects

The project consists of several subprojects:

| Subproject | Purpose |
|------------|---------|
| **rbox-ptrace** | ptrace-based command interceptor |
| **rbox-server** | TUI server for user decisions |
| **rbox-preload** | LD_PRELOAD client with DFA validation |
| **c-dfa** | Deterministic Finite Automata for fast validation |
| **shellsplit** | Shell command tokenizer |
| **rbox-protocol** | Binary protocol for client-server communication |

Each can be built/tested individually:

```bash
cd c-dfa && make        # Build c-dfa tools
cd shellsplit && make   # Build shellsplit library
cd rbox-protocol && make test  # Run protocol tests
```

---

## 🖥️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           System Process                             │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Shell                                                          │  │
│  │ readonlybox-ptrace -- /bin/ls -la                             │  │
│  │                                                               │  │
│  │  ptrace(TRACEME) → execve intercepted                        │  │
│  │                           ↓                                   │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │           DFA Validation                                 │ │  │
│  │  │   Fast path: safe commands execute directly              │ │  │
│  │  │   Slow path: send to server for decision                 │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  │                           ↓                                   │  │
│  │              ┌──────────────────────────┐                    │  │
│  │              │   Unix Socket            │                    │  │
│  │              │ /run/readonlybox/readonlybox.sock            │  │
│  │              └───────────┬──────────────┘                    │  │
│  └──────────────────────────┼───────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│              ┌───────────────────────────────┐                        │
│              │    readonlybox-server         │                        │
│              │    (Go + Bubble Tea TUI)      │                        │
│              │                               │                        │
│              │  ┌─────────────────────────┐  │                        │
│              │  │   Command Display       │  │                        │
│              │  │   - Full command       │  │                        │
│              │  │   - Caller/syscall    │  │                        │
│              │  │   - Env vars          │  │                        │
│              │  └─────────────────────────┘  │                        │
│              │              ↓                │                        │
│              │  ┌─────────────────────────┐  │                        │
│              │  │   User Decision         │  │                        │
│              │  │   Allow/Deny + Duration│  │                        │
│              │  └─────────────────────────┘  │                        │
│              └───────────────────────────────┘                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Protocol

The server uses Protocol v3, a binary protocol over Unix socket with UUID-based request matching:

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

### Server Options

```bash
# Quiet mode (blocked commands only)
./bin/readonlybox-server -q

# Verbose mode (show all commands)
./bin/readonlybox-server -v

# TUI mode (interactive terminal UI)
./bin/readonlybox-server --tui

# Auto-deny mode (deny all unknown commands)
./bin/readonlybox-server --auto-deny

# Use system socket path
./bin/readonlybox-server --system-socket
```

### Test with ptrace Client

```bash
# Start server in one terminal
./bin/readonlybox-server --auto-deny &

# Test command in another terminal
./bin/readonlybox-ptrace -- vim --version

# Cleanup
pkill -f readonlybox-server
```

> **Note**: TUI mode requires an interactive terminal.

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

By default, the server listens on `/run/readonlybox/readonlybox.sock`. Use environment variable to customize:

```bash
# Custom socket path
READONLYBOX_SOCKET=/var/run/readonlybox.sock readonlybox-ptrace -- vim
```

### Server Flags

| Flag | Description |
|------|-------------|
| `-socket <path>` | Unix socket path (default: /run/readonlybox/readonlybox.sock) |
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
| `READONLYBOX_SOCKET` | Unix socket path | `/run/readonlybox/readonlybox.sock` |

**Usage:**
```bash
# Start server with custom socket
./readonlybox-server -socket /var/run/readonlybox.sock

# Client uses custom socket
READONLYBOX_SOCKET=/var/run/readonlybox.sock readonlybox-ptrace -- vim
```

### Testing

Test the ptrace system:

```bash
# Terminal 1: Start server
./readonlybox-server -v

# Terminal 2: Run client
readonlybox-ptrace -- vim --version
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

## 📚 Architecture

The project consists of several components:

| Component | Purpose |
|-----------|---------|
| **rbox-ptrace** | ptrace-based command interceptor |
| **rbox-server** | TUI server for user decisions |
| **c-dfa** | DFA for fast command validation |
| **shellsplit** | Shell command tokenizer |
| **rbox-protocol** | Binary protocol for client-server communication |

### Components Built

```
bin/
├── readonlybox-server   # TUI server
└── readonlybox-ptrace  # ptrace interceptor
```

## Development Requirements

- Go 1.21+
- Make
- Standard Linux environment

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

## 📬 Contact

- **Project**: [github.com/panz-r/rbox-repo](https://github.com/panz-r/rbox-repo)

---

**ReadOnlyBox - Intercept, inspect, decide. 🔒**
