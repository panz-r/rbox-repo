package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDdParser(t *testing.T) {
	parser := NewDdParser()

	// Test dd command with input and output
	cmd, err := parser.ParseArguments([]string{"if=/dev/zero", "of=output.txt", "bs=1M", "count=10"})
	require.NoError(t, err)
	ddCmd, ok := cmd.(*DdCommand)
	require.True(t, ok)
	assert.Equal(t, "/dev/zero", ddCmd.InputFile)
	assert.Equal(t, "output.txt", ddCmd.OutputFile)
	assert.Equal(t, "1M", ddCmd.BlockSize)
	assert.Equal(t, "10", ddCmd.Count)
	assert.True(t, ddCmd.HasInputFile)
	assert.True(t, ddCmd.HasOutputFile)
	assert.True(t, ddCmd.Dangerous)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(ddCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read and write operations
	hasRead := false
	hasWrite := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
		}
		if op.OperationType == OpWrite {
			hasWrite = true
		}
	}
	assert.True(t, hasRead, "Should have read operations")
	assert.True(t, hasWrite, "Should have write operations")

	// Test dd command with only input
	cmd, err = parser.ParseArguments([]string{"if=input.txt", "bs=4K"})
	require.NoError(t, err)
	ddCmd, ok = cmd.(*DdCommand)
	require.True(t, ok)
	assert.Equal(t, "input.txt", ddCmd.InputFile)
	assert.Equal(t, "4K", ddCmd.BlockSize)
	assert.False(t, ddCmd.HasOutputFile)
	assert.False(t, ddCmd.Dangerous)

	// Test semantic operations for read-only dd
	ops, err = parser.GetSemanticOperations(ddCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have only read operations
	hasRead = false
	hasWrite = false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
		}
		if op.OperationType == OpWrite {
			hasWrite = true
		}
	}
	assert.True(t, hasRead, "Should have read operations")
	assert.False(t, hasWrite, "Should not have write operations for read-only dd")
}

func TestExprParser(t *testing.T) {
	parser := NewExprParser()

	// Test expr command
	cmd, err := parser.ParseArguments([]string{"1", "+", "2"})
	require.NoError(t, err)
	exprCmd, ok := cmd.(*ExprCommand)
	require.True(t, ok)
	assert.Equal(t, "1 + 2", exprCmd.Expression)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(exprCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for environment
	hasEnvRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "$ENV" {
			hasEnvRead = true
			break
		}
	}
	assert.True(t, hasEnvRead, "Should have environment read operations")

	// Test expr with dangerous patterns
	cmd, err = parser.ParseArguments([]string{"`dangerous`"})
	require.NoError(t, err)
	exprCmd, ok = cmd.(*ExprCommand)
	require.True(t, ok)

	// Test semantic operations for dangerous expr
	ops, err = parser.GetSemanticOperations(exprCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have execute operations for dangerous patterns
	hasExecute := false
	for _, op := range ops {
		if op.OperationType == OpExecute {
			hasExecute = true
			break
		}
	}
	assert.True(t, hasExecute, "Should have execute operations for dangerous patterns")
}

func TestLnParser(t *testing.T) {
	parser := NewLnParser()

	// Test ln command
	cmd, err := parser.ParseArguments([]string{"file.txt", "link.txt"})
	require.NoError(t, err)
	lnCmd, ok := cmd.(*LnCommand)
	require.True(t, ok)
	assert.Equal(t, "file.txt", lnCmd.Target)
	assert.Equal(t, "link.txt", lnCmd.LinkName)
	assert.False(t, lnCmd.Symbolic)

	// Test ln with symbolic option
	cmd, err = parser.ParseArguments([]string{"-s", "file.txt", "symlink.txt"})
	require.NoError(t, err)
	lnCmd, ok = cmd.(*LnCommand)
	require.True(t, ok)
	assert.Equal(t, "file.txt", lnCmd.Target)
	assert.Equal(t, "symlink.txt", lnCmd.LinkName)
	assert.True(t, lnCmd.Symbolic)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(lnCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read and create operations
	hasRead := false
	hasCreate := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
		}
		if op.OperationType == OpCreate {
			hasCreate = true
		}
	}
	assert.True(t, hasRead, "Should have read operations")
	assert.True(t, hasCreate, "Should have create operations")

	// Test ln with force option
	cmd, err = parser.ParseArguments([]string{"-sf", "file.txt", "link.txt"})
	require.NoError(t, err)
	lnCmd, ok = cmd.(*LnCommand)
	require.True(t, ok)
	assert.True(t, lnCmd.Symbolic)
	assert.True(t, lnCmd.Force)

	// Test semantic operations for force ln
	ops, err = parser.GetSemanticOperations(lnCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have write operations for force
	hasWrite := false
	for _, op := range ops {
		if op.OperationType == OpWrite {
			hasWrite = true
			break
		}
	}
	assert.True(t, hasWrite, "Should have write operations for force")
}

func TestMkdirParser(t *testing.T) {
	parser := NewMkdirParser()

	// Test mkdir command
	cmd, err := parser.ParseArguments([]string{"dir1", "dir2"})
	require.NoError(t, err)
	mkdirCmd, ok := cmd.(*MkdirCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"dir1", "dir2"}, mkdirCmd.Directories)
	assert.False(t, mkdirCmd.Parents)

	// Test mkdir with parents option
	cmd, err = parser.ParseArguments([]string{"-p", "dir1/dir2/dir3"})
	require.NoError(t, err)
	mkdirCmd, ok = cmd.(*MkdirCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"dir1/dir2/dir3"}, mkdirCmd.Directories)
	assert.True(t, mkdirCmd.Parents)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(mkdirCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have create operations
	hasCreate := false
	for _, op := range ops {
		if op.OperationType == OpCreate {
			hasCreate = true
			break
		}
	}
	assert.True(t, hasCreate, "Should have create operations")

	// Test mkdir with mode option
	cmd, err = parser.ParseArguments([]string{"-m", "755", "dir1"})
	require.NoError(t, err)
	mkdirCmd, ok = cmd.(*MkdirCommand)
	require.True(t, ok)
	assert.Equal(t, "755", mkdirCmd.Mode)
}

func TestPrintenvParser(t *testing.T) {
	parser := NewPrintenvParser()

	// Test printenv command
	cmd, err := parser.ParseArguments([]string{"PATH", "HOME"})
	require.NoError(t, err)
	printenvCmd, ok := cmd.(*PrintenvCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"PATH", "HOME"}, printenvCmd.Variables)
	assert.False(t, printenvCmd.All)

	// Test printenv with all option
	cmd, err = parser.ParseArguments([]string{"--all"})
	require.NoError(t, err)
	printenvCmd, ok = cmd.(*PrintenvCommand)
	require.True(t, ok)
	assert.True(t, printenvCmd.All)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(printenvCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for environment variables
	hasEnvRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "$") {
			hasEnvRead = true
			break
		}
	}
	assert.True(t, hasEnvRead, "Should have environment variable read operations")
}

func TestRmdirParser(t *testing.T) {
	parser := NewRmdirParser()

	// Test rmdir command
	cmd, err := parser.ParseArguments([]string{"dir1", "dir2"})
	require.NoError(t, err)
	rmdirCmd, ok := cmd.(*RmdirCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"dir1", "dir2"}, rmdirCmd.Directories)
	assert.False(t, rmdirCmd.Parents)

	// Test rmdir with parents option
	cmd, err = parser.ParseArguments([]string{"-p", "dir1/dir2/dir3"})
	require.NoError(t, err)
	rmdirCmd, ok = cmd.(*RmdirCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"dir1/dir2/dir3"}, rmdirCmd.Directories)
	assert.True(t, rmdirCmd.Parents)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(rmdirCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have dangerous write operations
	hasWrite := false
	hasDangerous := false
	for _, op := range ops {
		if op.OperationType == OpWrite {
			hasWrite = true
		}
		if op.Parameters != nil {
			if dangerous, ok := op.Parameters["dangerous"].(bool); ok && dangerous {
				hasDangerous = true
			}
		}
	}
	assert.True(t, hasWrite, "Should have write operations")
	assert.True(t, hasDangerous, "Should have dangerous operations")
}

func TestUlimitParser(t *testing.T) {
	parser := NewUlimitParser()

	// Test ulimit command
	cmd, err := parser.ParseArguments([]string{"-n", "1024"})
	require.NoError(t, err)
	ulimitCmd, ok := cmd.(*UlimitCommand)
	require.True(t, ok)
	assert.Equal(t, "-n", ulimitCmd.Limit)
	assert.Equal(t, "1024", ulimitCmd.Value)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(ulimitCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read and write operations for process limits
	hasRead := false
	hasWrite := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "limits") {
			hasRead = true
		}
		if op.OperationType == OpWrite && strings.Contains(op.TargetPath, "limits") {
			hasWrite = true
		}
	}
	assert.True(t, hasRead, "Should have process limits read operations")
	assert.True(t, hasWrite, "Should have process limits write operations")

	// Test ulimit without value (read-only)
	cmd, err = parser.ParseArguments([]string{"-n"})
	require.NoError(t, err)
	ulimitCmd, ok = cmd.(*UlimitCommand)
	require.True(t, ok)
	assert.Equal(t, "-n", ulimitCmd.Limit)
	assert.Equal(t, "", ulimitCmd.Value)

	// Test semantic operations for read-only ulimit
	ops, err = parser.GetSemanticOperations(ulimitCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have only read operations for read-only ulimit
	hasRead = false
	hasWrite = false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
		}
		if op.OperationType == OpWrite {
			hasWrite = true
		}
	}
	assert.True(t, hasRead, "Should have read operations")
	assert.False(t, hasWrite, "Should not have write operations for read-only ulimit")
}