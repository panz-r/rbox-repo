# Environment Screening and Policy Enforcement Plan

## Overview

Add environment variable screening to ReadOnlyBox ptrace client. Flag likely secrets at exec time, allow server/TUI to make policy decisions about which env vars to allow or remove.

---

## Phase 1: Environment Screening with Warnings

**Goal**: Screen env at exec time, warn but pass through unchanged

### Steps

1. **In ptrace exec handler**, after shellsplit command parsing, screen the environment
2. Use existing shellsplit env-screening logic (detect likely secrets like passwords, tokens, keys)
3. Log warnings for flagged variables (print to stderr / server log)
4. Pass all env vars to command as usual (no behavior change)

### Files
- `rbox-ptrace/` - add env screening before execve

---

## Phase 2: Protocol Changes for Env Decisions

**Goal**: Send flagged env var **names** to server for policy decision

### Steps

1. **Protocol**: Extend request to include flagged env var names
   - Add field in v7 header or request body for env_var_names (comma-separated or array)

2. **Client (ptrace)**: Send flagged env var names to server with request

3. **Server**: Parse and store env var names with request

4. **Go bindings**: Add method to get env var names from request

### Files
- `rbox-protocol/` - protocol changes
- `rbox-ptrace/` - send env var names
- `cmd/readonlybox-server/` - receive env var names

---

## Phase 3: Server Policy Decisions

**Goal**: TUI shows env decisions, server enforces policy

### Steps

1. **TUI**: Add env decision UI
   - Show command AND flagged env vars
   - Allow/deny each env var independently
   - Options: allow, deny (remove from env)

2. **Server**:
   - Store pending env decisions (like command decisions)
   - Include env decisions in response

3. **Client**:
   - Parse env decisions from server response
   - Remove denied env vars before execve

4. **Response protocol**: Include env decisions in response

### Files
- `cmd/readonlybox-server/tui.go` - env decision UI
- `cmd/readonlybox-server/server.go` - env decision handling
- `rbox-protocol/` - response changes

---

## Additional Considerations (Clarified)

1. **Shellsplit integration**: Link the shellsplit library - env screening is already part of it, need to call it from ptrace client

2. **Env var limits**: Only screen **flagged variables** that are likely sensitive secrets (not all env vars). Shellsplit identifies likely secrets.

3. **Cache behavior**: 
   - ptrace client is persistent, can implement rich policies
   - Examples: allow-once-then-filter, inject-once, etc.
   - Full control always given: make decision for each use

4. **Backward compatibility**: Not needed - we develop the whole system together as a unit

5. **Multiple flagged vars**: What if many env vars are flagged? Show them all in TUI or batch?

---

## Implementation Order

```
Phase 1 (independent):
├─ 1.1 Call shellsplit env screening in ptrace exec handler
├─ 1.2 Log warnings for flagged variables  
└─ 1.3 Test locally

Phase 2 (depends on Phase 1):
├─ 2.1 Protocol: add env_var_names to request
├─ 2.2 Client: send env_var_names with request
├─ 2.3 Server: parse and store env_var_names
└─ 2.4 Test end-to-end

Phase 3 (depends on Phase 2):
├─ 3.1 TUI: add env decision UI
├─ 3.2 Server: handle env decisions
├─ 3.3 Client: remove denied env vars
└─ 3.4 Full integration test
```

---

## Protocol Details (Draft)

### Request Extension (Phase 2)

```
Request packet (after command+args):
  - env_var_count: uint16
  - env_var_names: [name_len:uint8, name:var] repeated env_var_count times
```

### Response Extension (Phase 3)

```
Response packet (after reason):
  - env_decision_count: uint16
  - env_decisions: [name_len:uint8, name:var, decision:uint8] repeated
    - decision: 0=allow, 1=deny (remove from env)
```

---

## Implementation Order
