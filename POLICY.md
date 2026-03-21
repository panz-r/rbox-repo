# Protocol Policy

## Single Source of Truth

The rbox-protocol library is the **only** source of truth for protocol encoding and decoding. All code that needs to build or parse protocol packets must use the canonical library functions.

## Encoding Functions

All packet building must use these functions:

| Function | Purpose |
|----------|---------|
| `rbox_build_request()` | Build request packet (header + body) |
| `rbox_build_response()` | Build response packet (header + body) |
| `rbox_encode_request_body()` | Encode request body only |
| `rbox_encode_response_body()` | Encode response body only |

## Decoding Functions

All packet parsing must use these functions:

| Function | Purpose |
|----------|---------|
| `rbox_request_read()` | Read and parse complete request |
| `rbox_response_send()` | Send response to client |
| `rbox_decode_header()` | Decode header only |
| `rbox_decode_request_body()` | Decode request body only |
| `rbox_decode_response_details()` | Decode response details |

## Policy Rules

### NEVER create duplicate functions

If you need to add a variant like:
- ❌ `rbox_build_request_with_id()` 
- ❌ `rbox_build_request_with_caller()`
- ❌ `rbox_encode_with_env()`

Instead, **extend the existing function** to accept all parameters.

### Example

Instead of:
```c
// WRONG - creates duplicate code path
rbox_error_t rbox_build_request_with_id(char *pkt, size_t *len, 
    const uint8_t *id, const char *cmd, ...);
```

Do:
```c
// CORRECT - extend existing function
rbox_error_t rbox_build_request(char *pkt, size_t *len, 
    const char *cmd, const char *caller, const char *syscall, int argc, const char **argv);
```

### Protocol Field Placement

The protocol defines **where** fields go (header vs body). This is fixed. Do not create alternative encoders that put the same data in different places.

### Testing

All tests must use canonical library functions. Do not reimplement packet building or parsing in test code.

```c
// CORRECT - use library function
rbox_build_request(packet, &len, cmd, caller, syscall, argc, argv);

// WRONG - duplicate implementation
build_my_own_request(packet, cmd);
```

## Rationale

1. **Maintainability**: Single code path means bug fixes apply everywhere
2. **Consistency**: Protocol format is guaranteed to be identical
3. **Testability**: Tests validate the actual library functions
4. **Protocol Integrity**: Ensures the protocol remains well-defined

## Enforcement

- Code review should catch duplicate function creation
- Protocol changes should modify existing functions, not add new ones
- Tests should fail if canonical functions are not used
