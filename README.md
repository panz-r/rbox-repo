# landlock-builder

A C library for building and enforcing filesystem access policies, supporting two deployment scenarios:

1. **Landlock translation** — Build a policy and translate it to Linux Landlock BPF rules.
2. **In-process enforcement** — Compile a policy and evaluate it inside your own syscall interceptor.

Both scenarios share the same policy file format and parser. A single `.policy` file can be loaded and then routed to either deployment target.

## Quick Start

```c
#include "rule_engine.h"
#include "policy_parser.h"

/* Load a policy from text */
soft_ruleset_t *rs = soft_ruleset_new();
int line = 0;
const char *err = NULL;
soft_ruleset_parse_text(rs,
    "@0 PRECEDENCE\n"
    "/usr/** -> R /read\n"
    "/tmp/... -> RW recursive\n"
    "/data/secret -> D\n",
    &line, &err);

/* Scenario 2: In-process enforcement (see below) */
/* Scenario 1: Landlock translation (see below) */

soft_ruleset_free(rs);
```

## Policy File Format

Policies are written in a declarative text format parsed by `soft_ruleset_parse_text()` / `soft_ruleset_parse_file()`.

### Rule Syntax

```
pattern -> mode [/operation] [recursive] [subject:REGEX] [uid:UID]
```

| Component | Required | Example |
|---|---|---|
| `pattern` | Yes | `/usr/**`, `/data/...`, `"path with spaces/**"` |
| `->` | Yes | Arrow separator |
| `mode` | Yes | `R`, `W`, `X`, `RW`, `D` (deny) |
| `/operation` | No | `/read`, `/exec`, `/copy` |
| `recursive` | No | Matches subdirectories (suffix `/**` or `/...` already implies this) |
| `subject:REGEX` | No | Restricts which calling binary the rule applies to |
| `uid:UID` | No | Minimum UID for the rule to apply |

### Layer Declarations

```
@0 PRECEDENCE       /* Default: DENY shadows lower, mode intersection */
@1 SPECIFICITY      /* Longest-match wins, overrides PRECEDENCE */
@2 PRECEDENCE:RW    /* Layer with mode mask — rules cannot exceed RW */
```

### Macros

```
[USR] /usr/**
((USR)) -> R
```

### Comments

```
# This is a comment
```

### Example Policy

```
# Allow reading from /usr and /lib
[USR] /usr/**
((USR)) -> R /read

# Recursive read+write on /tmp
/tmp/... -> RW recursive

# Deny access to secrets
/data/secret -> D
```

---

## Scenario 1: Landlock Translation

Translate a policy to Linux Landlock BPF rules. This path:

- Validates that the policy **can** be expressed in Landlock
- Converts SOFT_ACCESS flags to LL_FS flags
- Expands `/**` and `/...` wildcards to prefix paths
- Adds deny rules to the builder so `prepare()` subtracts them from allows via radix tree overlap removal
- Optionally expands symlinks during `prepare()`

### Usage

```c
#include "rule_engine.h"
#include "policy_parser.h"
#include "landlock_bridge.h"
#include "landlock_builder.h"

/* 1. Build the ruleset from policy text or file */
soft_ruleset_t *rs = soft_ruleset_new();
soft_ruleset_parse_file(rs, "/etc/myapp.policy", &line, &err);

/* 2. Compile to an effective ruleset */
soft_ruleset_compile(rs);

/* 3. Validate Landlock compatibility */
const char *v_err = NULL;
int v_line = 0;
if (soft_ruleset_validate_for_landlock(rs, &v_err, &v_line) < 0) {
    fprintf(stderr, "Policy not expressible in Landlock at line %d: %s\n",
            v_line, v_err);
    soft_ruleset_free(rs);
    return -1;
}

/* 4. Translate to a Landlock builder */
const char **deny_prefixes = NULL;
landlock_builder_t *b = soft_ruleset_to_landlock(rs, &deny_prefixes);

/* Report deny prefixes (informational — overlap removal handles them) */
if (deny_prefixes) {
    for (int i = 0; deny_prefixes[i] != NULL; i++)
        fprintf(stderr, "  deny: %s\n", deny_prefixes[i]);
}
soft_landlock_deny_prefixes_free(deny_prefixes);
soft_ruleset_free(rs);

/* 5. Prepare: overlap removal, simplify, symlink expansion, ABI masking */
int abi = LANDLOCK_ABI_V4;  /* Or detect kernel ABI at runtime */
bool expand_symlinks = true;
landlock_builder_prepare(b, abi, expand_symlinks);

/* 6. Retrieve compiled rules */
size_t rule_count = 0;
const landlock_rule_t *rules = landlock_builder_get_rules(b, &rule_count);

/* 7. Apply to Landlock — one ruleset per path hierarchy level */
for (size_t i = 0; i < rule_count; i++) {
    int fd = landlock_rule_open_fd(&rules[i], O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        perror("landlock_rule_open_fd");
        continue;
    }
    struct landlock_path_beneath_attr attr = {
        .allowed_access = rules[i].access,
        .parent_fd = fd,
    };
    landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);
}

landlock_builder_free(b);
```

### What the Bridge Does

| Input | Transformation | Output |
|---|---|---|
| `/usr/**` with `SOFT_ACCESS_READ` | Strip `/**`, map flags → `LL_FS_READ_FILE|LL_FS_READ_DIR` | `allow("/usr", READ_FILE|READ_DIR)` |
| `/data/...` with `SOFT_ACCESS_WRITE` | Strip `/...`, map flags → `LL_FS_WRITE_FILE` | `allow("/data", WRITE_FILE)` |
| `/secret` with `SOFT_ACCESS_DENY` | Pass to builder as deny rule | `deny("/secret")` → subtracted during `prepare()` |

### What Cannot Be Translated

The validator rejects these with clear error messages:

- **Subject constraints** — Landlock has no process filtering
- **UID constraints** — Same limitation
- **Dual-path operations** — `${SRC}`/`${DST}` cannot be single-path
- **Mid-path wildcards** — `/etc/*/passwd` (Landlock only supports prefix matching)
- **SPECIFICITY layers** — Longest-match semantics have no Landlock equivalent

---

## Scenario 2: In-Process Enforcement

Compile a policy and evaluate it inside your syscall interceptor. This path:

- Does **not** expand symlinks (paths are resolved at evaluation time)
- Provides O(log n) lookup for exact/prefix patterns via binary search
- Supports subject regex, UID filtering, binary operations, and all layer types
- Caches results per path+subject+UID for repeated lookups

### Usage

```c
#include "rule_engine.h"
#include "policy_parser.h"

/* 1. Build and compile */
soft_ruleset_t *rs = soft_ruleset_new();
soft_ruleset_parse_file(rs, "/etc/myapp.policy", &line, &err);
soft_ruleset_compile(rs);  /* O(n log n) — do this once at startup */

/* 2. Single-path check (e.g., for open/read/write syscalls) */
soft_access_ctx_t ctx = {
    .op = SOFT_OP_READ,
    .src_path = "/data/config.json",
    .dst_path = NULL,
    .subject = "/usr/bin/cat",
    .uid = 1000,
};
int result = soft_ruleset_check_ctx(rs, &ctx, NULL);
if (result == -EACCES) {
    /* Deny the syscall */
    return -EACCES;
}
/* result is a bitmask of granted access — verify it includes what you need */
if (!(result & SOFT_ACCESS_READ)) {
    return -EACCES;
}

/* 3. Binary operation (e.g., for rename syscall) */
soft_access_ctx_t rename_ctx = {
    .op = SOFT_OP_MOVE,
    .src_path = "/tmp/old_name",
    .dst_path = "/tmp/new_name",
    .subject = "/usr/bin/mv",
    .uid = 1000,
};
result = soft_ruleset_check_ctx(rs, &rename_ctx, &audit_log);
if (result == -EACCES) {
    fprintf(stderr, "rename denied: %s (layer %d)\n",
            audit_log.deny_reason, audit_log.deny_layer);
    return -EACCES;
}

/* 4. Batch evaluation (e.g., for readdir or recursive copy) */
soft_access_ctx_t *ctxs[1000];
int results[1000];
/* ... populate ctxs array ... */
soft_ruleset_check_batch_ctx(rs, (const soft_access_ctx_t **)ctxs, results, 1000);
/* results[i] is SOFT_ACCESS_* or -EACCES for each path */

soft_ruleset_free(rs);
```

### Performance Characteristics

| Path Type | Lookup Complexity | Notes |
|---|---|---|
| Exact match (`/usr/bin/gcc`) | **O(log n)** | Binary search on sorted static rules |
| Prefix match (`/usr/**` covers `/usr/bin/gcc`) | **O(log n + k)** | Binary search insertion point + backward scan |
| Wildcard (`/etc/*`, `/data/...`) | **O(n × m)** | Linear scan with pattern matching |
| Cached (repeated path) | **O(1)** | 256-entry direct-mapped query cache |
| Batch (parent directory hit) | **O(1)** | Parent-directory cache avoids re-evaluation |

### When to Compile

- **Call `soft_ruleset_compile()`** after loading all rules and before any evaluation.
- Adding rules after compilation **invalidates** the compiled state automatically.
- Call `soft_ruleset_is_compiled(rs)` to check.

### Thread Safety

Rulesets are **not thread-safe** for concurrent mutation. After `compile()`, the ruleset is read-only and can be safely read by one thread at a time. For multi-threaded use:

- Clone the compiled ruleset per thread, or
- Protect access with a mutex, or
- Use a single-threaded evaluator and communicate results via IPC

---

## API Reference

### Core Types

| Header | Type | Purpose |
|---|---|---|
| `rule_engine.h` | `soft_ruleset_t*` | Opaque ruleset handle |
| `rule_engine.h` | `soft_access_ctx_t` | Access transaction (op, src, dst, subject, uid) |
| `rule_engine.h` | `soft_audit_log_t` | Optional audit output (result, reason, matched rule) |
| `landlock_builder.h` | `landlock_builder_t*` | Opaque Landlock builder handle |
| `landlock_builder.h` | `landlock_rule_t` | Compiled Landlock rule (path + access mask) |

### Key Constants

| Header | Prefix | Purpose |
|---|---|---|
| `rule_engine.h` | `SOFT_ACCESS_*` | Access flags (READ=1, WRITE=2, EXEC=4, DENY=0x80000000) |
| `rule_engine.h` | `SOFT_OP_*` | Operation types (READ, WRITE, EXEC, COPY, MOVE, LINK, MOUNT) |
| `rule_engine.h` | `SOFT_RULE_*` | Rule flags (RECURSIVE, STRICT, TEMPLATE) |
| `landlock_builder.h` | `LL_FS_*` | Landlock access flags (READ_FILE, WRITE_FILE, EXECUTE, ...) |
| `landlock_builder.h` | `LANDLOCK_ABI_V*` | ABI versions (1..4) |

### Error Conventions

- Functions returning `int`: **0** = success, **-1** = failure (check `errno`)
- `soft_ruleset_check_ctx()`: returns **`SOFT_ACCESS_*`** bitmask on success, **`-EACCES`** on denial
- `soft_ruleset_check_batch_ctx()`: returns **0** on success, **-1** on failure (individual results in `results[]`)
- Error strings from out-params are **static** (do not free)

### Memory Ownership

| Function | Ownership |
|---|---|
| `soft_ruleset_new()` / `soft_ruleset_free()` | Caller owns ruleset |
| `landlock_builder_new()` / `landlock_builder_free()` | Caller owns builder |
| `landlock_builder_get_rules()` | **Borrowed** — do not free, valid until next `prepare()` or `free()` |
| `soft_ruleset_to_landlock()` | **New** — caller must `free()` the returned builder |
| `deny_prefixes` out-param | **Caller-owned** — free with `soft_landlock_deny_prefixes_free()` |
| `landlock_rule_open_fd()` | Caller must `close(2)` the returned fd |

## Build

```bash
make lib        # Build liblandlock-builder.a
make test       # Build and run unit tests (1040 assertions)
make benchmark  # Build and run performance benchmarks
make clean      # Remove build artifacts
```

## Project Layout

```
include/
  rule_engine.h          # In-process enforcement API
  landlock_builder.h     # Landlock policy compiler API
  landlock_bridge.h      # Translation between the two
  policy_parser.h        # Text policy parser/serializer

src/
  rule_engine.c          # Layer evaluation (unary + binary ops)
  rule_engine_compile.c  # 7-phase compiler (shadow, intersection, subsumption, sort)
  builder.c              # Landlock builder (allow/deny, prepare, simplify)
  radix_tree.c           # Radix tree for overlap removal and prefix simplification
  policy_parser.c        # Text format parser with macros and layers
  landlock_bridge.c      # soft_ruleset_t → landlock_builder_t translation
  arena.c                # String interning arena for compiled rules

tests/
  test_rule_engine.c     # Rule engine evaluation tests
  test_policy_parser.c   # Policy parser and serializer tests (13 functions, 1000+ assertions)
  test_builder.c         # Landlock builder tests
  test_landlock_bridge.c # Bridge translation tests
  ...
```
