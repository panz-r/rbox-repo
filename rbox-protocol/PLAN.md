# rbox-protocol (ReadOnlyBox Protocol Library)

## Overview

A C library providing unified client-server communication for ReadOnlyBox. All communication (clients → server, server → clients) flows through this library.

This library absorbs and consolidates:
- All socket communication code from ptrace client
- All socket communication code from LD_PRELOAD client  
- All packet handling code from Go server
- Protocol definitions and handling

## Goals

1. **Unified communication** - Both clients and server use the same library
2. **Zero-copy parsing** - Work directly with network buffers, avoid unnecessary copies
3. **shellsplit integration** - Parse commands in-place without Go String allocation
4. **Optimized for Linux** - Custom socket code, not limited by Go runtime
5. **Testable & Fuzzable** - Pure C code with comprehensive tests
6. **Reusable** - Both ptrace and LD_PRELOAD clients use same code

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 readonlybox-lib (C Library)                   │
├─────────────────────────────────────────────────────────────────┤
│  Socket I/O    │  Packet Handler  │  shellsplit Parser  │       │
│  - connect()   │  - read_req()   │  - parse_raw()     │       │
│  - accept()    │  - write_resp() │  - get_subcmds()   │       │
└─────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌────────────┐       ┌────────────┐       ┌────────────┐
    │  Clients  │       │   Server   │       │  Testing  │
    │  - ptrace │       │  - Go TUI  │       │  - unit   │
    │  - preload│       │  - request│       │  - fuzz   │
    └────────────┘       └────────────┘       └────────────┘
```

## Directory Structure

```
rbox-protocol/
├── Makefile
├── README.md
├── PLAN.md
├── include/
│   └── rbox_protocol.h        # Public API header
├── src/
│   ├── socket.c           # Socket operations
│   ├── socket.h
│   ├── packet.c           # Packet parsing/building
│   ├── packet.h
│   ├── parser.c           # shellsplit integration
│   └── parser.h
└── tests/
    ├── test_socket.c
    ├── test_packet.c
    └── fuzz/
```

## Core Concepts

### 1. Packet Format

The library handles the binary protocol directly:

```
┌──────────┬──────────┬────────────┬────────────┬──────────┐
│  Magic   │ Version  │  ClientID  │ RequestID  │  Type    │
│  4 bytes │  4 bytes │  16 bytes  │  16 bytes │  4 bytes │
├──────────┼──────────┼────────────┼────────────┼──────────┤
│  Argc    │  Envc    │ Checksum   │   Data...  │          │
│  4 bytes │  4 bytes│  4 bytes  │   n bytes  │          │
└──────────┴──────────┴────────────┴────────────┴──────────┘
```

### 2. Zero-Copy Parsing

Instead of creating Go strings:
```go
// OLD: Go copies entire command
cmd := string(packet.Data)

// NEW: Work with C buffer directly
func parseCommand(data []byte) {
    C.parse_raw(data, len(data), &result)
    // result.points into original buffer
    for i := 0; i < result.count; i++ {
        subcmd := result.cmds[i]
        // subcmd.start and subcmd.len reference original data
    }
}
```

### 3. Memory Model

- **Library owns packet memory**: allocated/freed by C
- **Views into memory**: Go gets slices that reference C buffers
- **Lifetime**: Go must use data before calling next read
- **Allocation**: Small fixed pools, not malloc per-request

## API Design

### Server Side

```c
// Create server socket
rbox_server_t *server = rbox_server_new("/path/to/socket");
rbox_server_listen(server);

// Accept and handle
rbox_client_t *client = rbox_server_accept(server);

// Read request (blocks)
rbox_request_t req;
rbox_request_read(client, &req);

// Parse command with shellsplit (zero-copy)
rbox_command_t cmd;
rbox_command_parse(&req, &cmd);

// cmd.subcommands[0].start points into original buffer!

// Send response
rbox_response_t resp = { .decision = ALLOW };
rbox_response_send(client, &resp);

// Cleanup
rbox_request_free(&req);
rbox_client_close(client);
rbox_server_free(server);
```

### Client Side

```c
// Connect to server
rbox_client_t *client = rbox_client_connect("/path/to/socket");

// Build request
rbox_request_t req;
rbox_request_init(&req);
rbox_request_set_command(&req, "ls -la");
rbox_request_set_args(&req, argc, argv);

// Send and get response
rbox_response_t resp;
rbox_request_send(client, &req, &resp);

// Check decision
if (resp.decision == RBOX_ALLOW) {
    // Proceed
}

// Cleanup
rbox_response_free(&resp);
rbox_request_free(&req);
rbox_client_free(client);
```

### Go Integration (Server)

```go
/*
#cgo LDFLAGS: -L./readonlybox-lib -lreadonlybox-lib
#include <readonlybox_lib.h>
*/
import "C"

func handleRequest(data []byte) {
    // Pass C buffer directly - no copy
    req := C.rbox_request_from_buffer(
        (*C.char)(unsafe.Pointer(&data[0])),
        C.size_t(len(data)))
    
    // Get structured parse results (still referencing original buffer)
    var cmd C.rbox_command_t
    C.rbox_command_parse(req, &cmd)
    
    // Access subcommands (references into original buffer)
    for i := 0; i < int(cmd.count); i++ {
        sub := cmd.subcommands[i]
        // sub.start, sub.len reference original data!
    }
    
    // Must free before next request
    C.rbox_request_free(req)
}
```

## Implementation Steps

### Phase 1: Core Library

1. **Socket operations**
   - `rbox_socket_connect()` - client connect
   - `rbox_socket_listen()` - server listen  
   - `rbox_socket_accept()` - server accept
   - Abstract over socket for testing

2. **Packet handling**
   - Read/parse packet header
   - Read variable-length data
   - Build packets
   - Checksum validation

3. **Memory management**
   - Fixed pool allocator
   - Request/response object pools
   - Zero-allocation common paths

### Phase 2: shellsplit Integration

4. **Parser wrapper**
   - `rbox_command_parse()` - parse command buffer
   - Return subcommand ranges (not copies)
   - Support all shellsplit modes

5. **Semantic extraction**
   - Extract command name
   - Extract arguments
   - Identify redirects, pipes

### Phase 3: Go Integration

6. **cgo bindings**
   - Expose C functions to Go
   - Zero-copy buffer passing
   - Handle memory lifetime

7. **Server integration**
   - Replace Go socket code with C library calls
   - Request handling loop
   - Response generation

### Phase 4: Testing & Clients

8. **Comprehensive tests**
   - Unit tests for packet parsing
   - Socket tests (mock/real)
   - Integration tests

9. **Fuzzing**
   - libFuzzer integration
   - Protocol fuzzing
   - Edge cases

10. **Client updates**
    - ptrace client uses readonlybox-lib
    - LD_PRELOAD client uses readonlybox-lib
    - Shared validation logic

## Protocol Notes

- Binary protocol (already defined)
- Magic: `0x524F424F` ("ROBO")
- Version: 4 (current)
- All integers little-endian
- Strings null-terminated in data section

## Memory Safety

- All buffers validated before parsing
- Bounds checking on all accesses
- No use-after-free (ownership clear)
- Pool allocator prevents leaks

## Performance Targets

- < 1μs packet parse (hot path)
- < 10μs shell parse
- Zero allocations in request path
- Batch processing support

## Testing Strategy

1. **Unit tests** - Each component in isolation
2. **Integration tests** - Full client↔server
3. **Fuzzing** - Protocol robustness
4. **Benchmarks** - Performance regression testing
5. **Memory sanitizers** - Address/undefined behavior
