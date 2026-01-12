# Access Control Model Examples

This document shows how the access control models work for different commands in the ReadOnlyBox system.

## Basic Structure

The access control system uses a Domain-Specific Language (DSL) to define rules for each command:

```go
type AST struct {
    BaseDir    string          // Base directory for relative paths
    Rules      []AccessRule    // Access rules for commands
}

type AccessRule struct {
    Command     string           // Command name (e.g., "ls", "cat", "sort")
    Operations  []FileOperation  // Allowed file operations
    Directories []DirectoryAccess // Directory access rules
}

type FileOperation struct {
    OpType      OperationType   // Type of operation (Read, Write, etc.)
    Path        string          // Path pattern (supports wildcards)
    IsTemp      bool            // Whether this applies to temp files
    CreatedByUs bool            // Whether file must be created by ReadOnlyBox
}

type DirectoryAccess struct {
    Path   string      // Directory path
    Level  AccessLevel // Access level (At, Super, Sub)
    Depth  int         // Maximum depth for Super/Sub access
}
```

## Example 1: `ls` Command

The `ls` command is configured to allow reading files with specific directory access:

```go{
    Command: "ls",
    Operations: []dsl.FileOperation{
        {OpType: dsl.OpRead},  // Only read operations allowed
    },
    Directories: []dsl.DirectoryAccess{
        {
            Path:  "/home/user/project",
            Level: dsl.AccessAt,      // Exact directory only
        },
        {
            Path:  "/home/user/project/src",
            Level: dsl.AccessSub,     // Subdirectories allowed
            Depth: 2,                 // Up to 2 levels deep
        },
    },
}
```

### What This Allows:

✅ **Allowed Access:**
- `ls /home/user/project/file.txt` - Exact directory match
- `ls /home/user/project/src/subdir/file.txt` - 1 level deep in src
- `ls /home/user/project/src/subdir/subdir2/file.txt` - 2 levels deep in src

❌ **Denied Access:**
- `ls /home/user/project/src/subdir/subdir2/subdir3/file.txt` - Too deep (3 levels)
- `ls /home/user/other/file.txt` - Outside allowed directories
- Any write operations (not in Operations list)

### Access Levels Explained:

- **`AccessAt`**: Only the exact specified directory
- **`AccessSub`**: The specified directory and its subdirectories (up to Depth)
- **`AccessSuper`**: The specified directory and its parent directories (up to Depth)

## Example 2: `cat` Command

The `cat` command allows reading with both exact and parent directory access:

```go{
    Command: "cat",
    Operations: []dsl.FileOperation{
        {OpType: dsl.OpRead},  // Only read operations allowed
    },
    Directories: []dsl.DirectoryAccess{
        {
            Path:  "/home/user/project",
            Level: dsl.AccessAt,      // Exact directory
        },
        {
            Path:  "/home/user/project",
            Level: dsl.AccessSuper,   // Parent directories
            Depth: 1,                 // 1 level up
        },
    },
}
```

### What This Allows:

✅ **Allowed Access:**
- `cat /home/user/project/file.txt` - Exact directory match
- `cat /home/user/file.txt` - Parent directory (1 level up)

❌ **Denied Access:**
- `cat /home/file.txt` - Too far up (2 levels)
- `cat /home/user/other/file.txt` - Different branch
- Any write operations

## Example 3: `sort` Command with Temp Files

The `sort` command demonstrates temporary file handling:

```go{
    Command: "sort",
    Operations: []dsl.FileOperation{
        {
            OpType:   dsl.OpRedirect,    // Redirect output to temp file
            Path:     "/tmp/readonlybox_*.txt",  // Pattern matching
            IsTemp:   true,               // This is a temp file operation
        },
        {
            OpType:      dsl.OpOverwrite, // Overwrite temp file
            Path:        "/tmp/readonlybox_*.txt",
            IsTemp:      true,
            CreatedByUs: true,           // Only files we created
        },
    },
    Directories: []dsl.DirectoryAccess{
        {
            Path:  "/home/user/project",
            Level: dsl.AccessAt,
        },
    },
}
```

### What This Allows:

✅ **Allowed Access:**
- `sort input.txt > /tmp/readonlybox_result.txt` - Redirect to new temp file
- `sort input.txt > /tmp/readonlybox_result.txt` (if we created the file) - Overwrite our own temp file

❌ **Denied Access:**
- `sort input.txt > /tmp/readonlybox_other.txt` (if not created by us) - Overwrite others' temp files
- `sort input.txt > /tmp/other_file.txt` - Doesn't match pattern
- Any operations outside `/home/user/project` base directory

### Temp File Special Handling:

- Temp files use base directory for access control context
- Pattern matching supports wildcards (`*.txt`)
- `CreatedByUs` ensures only our own temp files can be overwritten
- Temp files are registered in the engine's `TempFiles` map

## Operation Types

The system defines these operation types:

```go
const (
    OpRead      OperationType = iota  // Read file contents
    OpEdit                              // Edit/modify file
    OpCreate                            // Create new file
    OpWrite                             // Write to file
    OpRedirect                          // Redirect output to file
    OpOverwrite                          // Overwrite existing file
)
```

## How Access Control Works

1. **Command Matching**: Find rules for the specific command or wildcard (`*`)
2. **Directory Access**: Check if target path matches directory rules
3. **Operation Type**: Verify the operation is in the allowed list
4. **Temp File Rules**: For temp files, apply additional pattern and ownership checks
5. **Decision**: Return `true, nil` (allowed) or `false, nil` (denied by rules) or `false, error` (no rules found)

## Example Access Control Flow

For command: `ls /home/user/project/src/subdir/file.txt`

1. **Find Rules**: Match `ls` command rules
2. **Check Directories**:
   - `/home/user/project` with `AccessAt` - No match (not exact)
   - `/home/user/project/src` with `AccessSub` (depth 2) - Match! ✅
3. **Check Operations**: `OpRead` is in allowed operations - Match! ✅
4. **Temp File Check**: Not a temp file - Skip
5. **Result**: `true, nil` - Access granted! 🎉

For command: `sort data.txt > /tmp/readonlybox_result.txt`

1. **Find Rules**: Match `sort` command rules
2. **Check Directories**: Use base dir `/home/user/project` (temp file special case) - Match! ✅
3. **Check Operations**: `OpRedirect` is in allowed operations - Match! ✅
4. **Temp File Check**:
   - Pattern `/tmp/readonlybox_*.txt` matches `/tmp/readonlybox_result.txt` ✅
   - `CreatedByUs` not required for redirect
5. **Result**: `true, nil` - Access granted! 🎉