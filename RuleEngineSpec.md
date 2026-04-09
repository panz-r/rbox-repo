 This is a significant architectural shift. To support binary operations (like cp, mv, ln, mount --bind) efficiently, we need to move from a simple "path lookup" to a "transactional context" model.

Here is the upgraded specification (v3.0) incorporating Binary Operations, Path Variables, and Expression-Based Rules while maintaining high performance through batchable contexts.

ReadOnlyBox Rule Engine Specification (v3.0)
1. Overview
The engine now evaluates Access Transactions rather than isolated path lookups. A transaction consists of a Subject (process/binary), an Operation (e.g., COPY, EXEC), and Operands (Source Path, Destination Path).

Core Innovation: The "Dual-Path Resolver" allows atomic evaluation of two paths (Source and Destination) in a single pass, enabling rules like "Allow copying only from /usr to /tmp".

2. Binary Operations & Path Roles
2.1 Operation Types
We define standard binary operations. Custom operations can be added via the API.

c
typedef enum {
    SOFT_OP_READ,           /* Single path (fallback) */
    SOFT_OP_WRITE,          /* Single path (fallback) */
    SOFT_OP_EXEC,           /* Single path (fallback) */
    SOFT_OP_COPY,           /* Requires SRC (Read) and DST (Write/Create) */
    SOFT_OP_MOVE,           /* Requires SRC (Write/Unlink) and DST (Write/Create) */
    SOFT_OP_LINK,           /* Requires SRC (Read/Link) and DST (Write/Create) */
    SOFT_OP_MOUNT,          /* Requires SRC (Read) and DST (Mount point) */
    SOFT_OP_CHMOD_CHOWN,    /* Requires Target (Write) and... */
    SOFT_OP_CUSTOM          /* User-defined operation */
} soft_binary_op_t;
2.2 Path Roles
Paths are no longer just strings; they have semantic roles in a binary operation:

SRC (Source): The origin of data (requires READ/EXEC).
DST (Destination): The target of data (requires WRITE/CREATE/MKDIR).
BASE: A base directory constraint (e.g., "chroot").
3. Expressive Rule Format
To support complex policies without sacrificing performance, rules now support Path Variables and Constraints.

3.1 Rule Structure (Enhanced)
c
typedef struct {
    char *pattern;          /* Path pattern with variables, e.g., "${SRC}" or "/src/..." */
    soft_mode_t mode;        /* Allowed mode */
    uint32_t flags;         /* SOFT_RULE_RECURSIVE, SOFT_RULE_STRICT, etc. */
    
    /* Binary Operation Constraints */
    soft_binary_op_t op_type;      /* If BINARY, which operation this rule applies to */
    char *linked_path_var;        /* E.g., "DST". If op is COPY, match SRC, but check DST var too */
    
    /* Advanced Matching */
    const char *subject_regex;     /* Regex match on the calling binary path (e.g., ".*/cp$") */
    uint32_t min_uid;              /* Rule only applies if UID >= this */
} soft_rule_t;
3.2 Path Variables in Patterns
Rules can use ${VAR} syntax to act as placeholders for operands.

Static Rule: /bin/bash:rx (Applies to /bin/bash)
Binary Rule (Copy):
Rule 1 (Src): pattern="${SRC}", op_type=SOFT_OP_COPY, mode=RO
Rule 2 (Dst): pattern="${DST}", op_type=SOFT_OP_COPY, mode=RW
Effect: To perform a copy, the SRC must match a RO rule and DST must match an RW rule.
Relative Rule: pattern="/src/.../${SRC}" (Recursive copy from anywhere under /src).
4. The "Dual-Path" Query API
The core evaluation function now accepts a Context object containing both paths and the operation type.

4.1 The Context Structure
c
typedef struct {
    soft_binary_op_t op;
    const char *src_path;   /* Source path (can be NULL for unary ops) */
    const char *dst_path;   /* Destination path (can be NULL for unary ops) */
    const char *subject;    /* Calling binary path (for subject_regex matching) */
    uid_t uid;              /* Caller UID (for min_uid matching) */
} soft_access_ctx_t;
4.2 Evaluation Functions
Primary Evaluation (Atomic Binary Check)
c
int soft_ruleset_check_ctx(const soft_ruleset_t *rs, 
                           const soft_access_ctx_t *ctx,
                           soft_audit_log_t *out_log);
Logic:

Iterate layers from Top (High Precedence) to Bottom.
For SOFT_OP_COPY:
Evaluate src_path against rules where op_type == SOFT_OP_COPY or op_type == SOFT_OP_READ.
Evaluate dst_path against rules where op_type == SOFT_OP_COPY or op_type == SOFT_OP_WRITE.
Intersect the results. If SRC is DENY or DST is DENY, result is DENY.
If SRC allows RW but DST only allows RO, result is RO (most restrictive).
If linked_path_var is set in a matching rule, fetch the variable path (e.g., DST) from the context and evaluate it immediately.
Batch Binary Evaluation (High Performance)
For tools like cp -r or compilers processing thousands of files:

c
int soft_ruleset_check_batch_ctx(const soft_ruleset_t *rs,
                                 const soft_access_ctx_t *ctxs[],
                                 int *results,
                                 int count);
Optimizes by caching layer results for parent directories.
If 100 files are copied from /a to /b, it evaluates /a and /b once, then reuses the result for all children.
5. Rule Insertion with Expressions
5.1 Parsing Expressions
The engine supports a simplified policy language for insertion:

Format: op:subject:src_pattern:dst_pattern -> mode

Examples:

cp::/etc/*:/tmp/ -> RW (Allow cp from /etc to /tmp)
cp:/usr/bin/cp:${SRC}:${DST} -> RO (Only allow cp binary to copy if SRC is RO and DST is RW implicitly)
mount::/dev/sd*:/mnt/usb -> RWX (Allow mounting block devices to /mnt/usb)
5.2 API for Expression Rules
c
/* Parse a string rule into the internal structure */
int soft_layer_add_rule_str(soft_layer_t *layer, 
                           const char *rule_str, 
                           const char *source_file);
6. Performance Optimizations for Binary Ops
Binary operations are expensive if done naively (two full tree traversals).

6.1 The "Pair Cache"
The ruleset maintains a small LRU cache of recent (Src_Path_ID, Dst_Path_ID, Op) tuples.

If cp /a/f1 /b/f1 was just allowed, cp /a/f2 /b/f2 can be fast-allowed if the parent dirs /a and /b have stable rules.
6.2 Short-Circuit Logic
DENY First: If any layer has a DENY rule matching SRC or DST, return DENY immediately (no need to check lower layers or the other path).
Mode Intersection: We don't need to check every bit. We can pre-calculate the "Minimum Required Mode" for the operation.
COPY requires SRC_MODE & READ && DST_MODE & WRITE.
If SRC_MODE is already DENY, stop.
7. Updated Specification Details
7.1 Extended Access Flags
Added flags specific to binary operations:

c
#define SOFT_ACCESS_LINK_SRC  0x1000  /* Read source to create a link */
#define SOFT_ACCESS_MOUNT_SRC 0x2000  /* Read source for mounting */
7.2 Rule Precedence with Variables
When a rule contains ${SRC}, it is considered a "Templated Rule".

Templated rules have lower priority than Static Path Rules within the same layer.
Example:
Rule A (Static): /etc/shadow: DENY
Rule B (Template): ${SRC}: RO (for op=COPY)
Query: cp /etc/shadow /tmp/x
Result: DENY. Rule A (Static) matches the specific path /etc/shadow and wins over the generic template Rule B.
8. Example Use Cases
Use Case 1: Restricted Copy
Policy: Only allow copying files from /readonly to /scratch, but not the other way around.

Ruleset:

Layer "strict" (High Precedence):
op=COPY, src=${SRC}, dst=${DST} -> Mode: DENY (Default safety)
Layer "permissive" (Low Precedence):
path=/readonly, op=COPY, role=SRC -> Mode: RO
path=/scratch, op=COPY, role=DST -> Mode: RW
path=/readonly/..., op=COPY, role=SRC, recursive=1 -> Mode: RO
path=/scratch/..., op=COPY, role=DST, recursive=1 -> Mode: RW
Query: soft_ruleset_check_ctx(rs, {OP_COPY, "/readonly/file", "/scratch/out"})

Check "strict": No specific allow rule, default DENY.
Check "permissive":
Src /readonly/file matches /readonly/... -> RO granted.
Dst /scratch/out matches /scratch/... -> RW granted.
Result: Intersection of RO and RW is effectively RW (write to dst, read from src). Access Allowed.
Query: soft_ruleset_check_ctx(rs, {OP_COPY, "/scratch/file", "/readonly/out"})

Check "permissive":
Src /scratch/file -> Matches /scratch/... (RW).
Dst /readonly/out -> No match (Defaults to DENY or lower layer default).
Result: Dst is DENY. Access Denied.
Use Case 2: Compiler Sandbox
Policy: gcc can read from /src and write to /build, but cannot write to /src.

Rules:

subject="/usr/bin/gcc", op=READ, path=/src/..., mode=RO
subject="/usr/bin/gcc", op=WRITE, path=/build/..., mode=RW
subject="/usr/bin/gcc", op=WRITE, path=/src/..., mode=DENY (Explicit override)
9. Backward Compatibility
For unary operations (the old behavior), src_path is used, and dst_path is NULL.

soft_ruleset_check(rs, path, mask) becomes a wrapper:
c
soft_access_ctx_t ctx = { .op = SOFT_OP_READ, .src_path = path };
return soft_ruleset_check_ctx(rs, &ctx, NULL);
Rules without op_type default to SOFT_OP_READ (unary).
10. Implementation Notes
Radix Tree Extension: The tree nodes need to store a small hash map of {op_type, rule_index} to handle templated rules efficiently.
Variable Resolution: ${SRC} and ${DST} are resolved at query time from the soft_access_ctx_t struct, not at rule insertion time. This keeps rules generic.
Subject Matching: Matching the subject_regex (calling binary) should be done once per transaction (per cp invocation), not per file, and cached in the context. 
