# rbox-wrap

LD_PRELOAD client library for ReadOnlyBox. This wrapper validates commands against a DFA before contacting the server, providing fast-path execution for safe commands.

## Usage

```
rbox-wrap [options] [--] <command> [args...]
```

## Options

| Option | Description |
|--------|-------------|
| `--judge` | Query server for decision, print result (default) |
| `--run` | Query server and execute if allowed |
| `--clear-env` | Run with minimal clean environment (no inherited env vars) |
| `--bin` | Output raw response packet to stdout |
| `--relay` | Skip DFA, always contact server |
| `--socket <path>` | Unix socket path (overrides env and defaults) |
| `--system-socket` | Use system socket `/run/readonlybox/readonlybox.sock` |
| `--user-socket` | Use user socket `$XDG_RUNTIME_DIR/readonlybox.sock` |
| `--uid <uid>` | Drop privileges to this UID (for privilege separation) |

## Socket Selection

The socket path is determined in the following priority order:

1. `--socket <path>` command-line option
2. `--system-socket` flag (uses `/run/readonlybox/readonlybox.sock`)
3. `--user-socket` flag (uses `$XDG_RUNTIME_DIR/readonlybox.sock`)
4. `READONLYBOX_SOCKET` environment variable
5. `$XDG_RUNTIME_DIR/readonlybox.sock` (if `XDG_RUNTIME_DIR` is set)
6. Default: `/run/readonlybox/readonlybox.sock`

## Environment Variables

These are typically set by the ptrace client, not by users directly:

| Variable | Description |
|----------|-------------|
| `READONLYBOX_FLAGGED_ENVS` | Flagged environment vars for server filtering (format: `NAME1:score1,NAME2:score2`) |
| `READONLYBOX_CALLER` | Caller info for audit logging |
| `READONLYBOX_UID` | UID to run command as |
| `READONLYBOX_SOCKET` | Unix socket path |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command allowed and executed (`--run` only) |
| 1 | Command denied or error |
| 9 | Server decision printed (deny once) |
| 143 | Signal propagated (e.g., SIGTERM) |

## Architecture

The wrapper uses a two-tier approach:

1. **DFA Fast-Path**: Commands matching the DFA's auto-allow patterns are executed directly without server contact
2. **Server Validation**: Unknown commands are sent to the server for decision

This provides low-latency execution for safe commands while maintaining security for complex or unknown commands.

## Platform

rbox-wrap uses Linux-specific features (`prctl`, `clearenv`) and requires a Linux system with a running ReadOnlyBox server.
