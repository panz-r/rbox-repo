package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCpMvParser(t *testing.T) {
	parser := &CpMvParser{}

	// Test cp command
	cmd, err := parser.ParseArguments([]string{"cp", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	cpCmd, ok := cmd.(*CpMvCommand)
	require.True(t, ok)
	assert.Equal(t, "cp", cpCmd.CommandType)
	assert.Equal(t, []string{"file1.txt"}, cpCmd.Sources)
	assert.Equal(t, "file2.txt", cpCmd.Destination)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(cpCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read and write operations
	hasRead := false
	hasWrite := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
		}
		if op.OperationType == OpWrite || op.OperationType == OpCreate {
			hasWrite = true
		}
	}
	assert.True(t, hasRead, "Should have read operations")
	assert.True(t, hasWrite, "Should have write operations")

	// Test mv command with recursive
	cmd, err = parser.ParseArguments([]string{"mv", "-r", "dir1", "dir2"})
	require.NoError(t, err)
	mvCmd, ok := cmd.(*CpMvCommand)
	require.True(t, ok)
	assert.Equal(t, "mv", mvCmd.CommandType)
	assert.Equal(t, []string{"dir1"}, mvCmd.Sources)
	assert.Equal(t, "dir2", mvCmd.Destination)
	assert.True(t, mvCmd.Recursive)

	// Test semantic operations for recursive mv
	ops, err = parser.GetSemanticOperations(mvCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)
}

func TestRmParser(t *testing.T) {
	parser := &RmParser{}

	// Test basic rm command
	cmd, err := parser.ParseArguments([]string{"rm", "file.txt"})
	require.NoError(t, err)
	rmCmd, ok := cmd.(*RmCommand)
	require.True(t, ok)
	assert.Equal(t, "rm", rmCmd.CommandType)
	assert.Equal(t, []string{"file.txt"}, rmCmd.Targets)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(rmCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have dangerous operations
	hasDangerous := false
	for _, op := range ops {
		if op.Parameters != nil {
			if dangerous, ok := op.Parameters["dangerous"].(bool); ok && dangerous {
				hasDangerous = true
				break
			}
		}
	}
	assert.True(t, hasDangerous, "RM operations should be marked as dangerous")

	// Test rmdir with recursive and force
	cmd, err = parser.ParseArguments([]string{"rmdir", "-rf", "dir1", "dir2"})
	require.NoError(t, err)
	rmdirCmd, ok := cmd.(*RmCommand)
	require.True(t, ok)
	assert.Equal(t, "rmdir", rmdirCmd.CommandType)
	assert.Equal(t, []string{"dir1", "dir2"}, rmdirCmd.Targets)
	assert.True(t, rmdirCmd.Recursive)
	assert.True(t, rmdirCmd.Force)

	// Test semantic operations for dangerous rmdir
	ops, err = parser.GetSemanticOperations(rmdirCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)
}

func TestChmodChownParser(t *testing.T) {
	parser := &ChmodChownParser{}

	// Test chmod command
	cmd, err := parser.ParseArguments([]string{"chmod", "755", "file.txt"})
	require.NoError(t, err)
	chmodCmd, ok := cmd.(*ChmodChownCommand)
	require.True(t, ok)
	assert.Equal(t, "chmod", chmodCmd.CommandType)
	assert.Equal(t, "755", chmodCmd.Mode)
	assert.Equal(t, []string{"file.txt"}, chmodCmd.Targets)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(chmodCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have attribute change operations
	hasAttrChange := false
	for _, op := range ops {
		if op.Parameters != nil {
			if attrChange, ok := op.Parameters["attribute_change"].(bool); ok && attrChange {
				hasAttrChange = true
				break
			}
		}
	}
	assert.True(t, hasAttrChange, "Should have attribute change operations")

	// Test chown command with recursive
	cmd, err = parser.ParseArguments([]string{"chown", "-R", "user:group", "dir1", "file1"})
	require.NoError(t, err)
	chownCmd, ok := cmd.(*ChmodChownCommand)
	require.True(t, ok)
	assert.Equal(t, "chown", chownCmd.CommandType)
	assert.Equal(t, "user:group", chownCmd.Owner)
	assert.Equal(t, []string{"dir1", "file1"}, chownCmd.Targets)
	assert.True(t, chownCmd.Recursive)

	// Test semantic operations for recursive chown
	ops, err = parser.GetSemanticOperations(chownCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)
}

func TestBaseParser(t *testing.T) {
	// Test the base parser utilities
	parser := NewBaseParser("test")

	// Test basic argument parsing
	cmd, _, err := parser.ParseBasicArguments([]string{"-abc", "file1", "file2"})
	require.NoError(t, err)
	assert.NotNil(t, cmd)
	assert.Equal(t, "test", cmd.CommandName)
	assert.Equal(t, []string{"file1", "file2"}, cmd.Arguments)

	// Check that combined options were parsed
	assert.True(t, cmd.HasOption("-a"))
	assert.True(t, cmd.HasOption("-b"))
	assert.True(t, cmd.HasOption("-c"))

	// Test file/directory separation
	files, dirs := parser.ParseFilesAndDirectories([]string{"file.txt", "dir1", "script.sh", "dir2/"})
	assert.Contains(t, files, "file.txt")
	assert.Contains(t, files, "script.sh")
	assert.Contains(t, dirs, "dir1")
	assert.Contains(t, dirs, "dir2/")
}

func TestParserUtils(t *testing.T) {
	utils := ParserUtilsInstance

	// Test option parsing
	options, _, err := utils.ParseOptions([]string{"-abc", "--long", "-x", "value"}, 0)
	require.NoError(t, err)
	assert.True(t, options["-a"].(bool))
	assert.True(t, options["-b"].(bool))
	assert.True(t, options["-c"].(bool))
	assert.True(t, options["--long"].(bool))
	assert.Equal(t, "value", options["-x"])

	// Test semantic operation builder
	builder := utils.SemanticOperationBuilder()
	builder.AddReadOperation("file.txt", "test_read")
	builder = builder.WithParameter("test", "value")
	builder = builder.WithPrecise()

	ops := builder.Build()
	assert.Len(t, ops, 1)
	assert.Equal(t, OpRead, ops[0].OperationType)
	assert.Equal(t, "file.txt", ops[0].TargetPath)
	assert.Equal(t, "value", ops[0].Parameters["test"])
	assert.True(t, ops[0].Parameters["precise"].(bool))

	// Test file path utilities
	fpu := utils.FilePathUtils()
	assert.Equal(t, "./file.txt", fpu.EnsureAbsolutePath(".", "file.txt"))
	assert.Equal(t, "/tmp/file.txt", fpu.EnsureAbsolutePath("/tmp", "file.txt"))
	assert.Equal(t, "file.txt/*", fpu.AddWildcard("file.txt"))
	assert.True(t, fpu.IsStdPath("/dev/stdin"))
	assert.False(t, fpu.IsStdPath("file.txt"))

	// Test command validation utils
	cvu := utils.CommandValidationUtils()
	assert.True(t, cvu.IsDangerousOption("--install"))
	assert.True(t, cvu.IsDangerousOption("-i"))
	assert.False(t, cvu.IsDangerousOption("-h"))
	assert.True(t, cvu.IsWriteOperation(OpWrite))
	assert.False(t, cvu.IsWriteOperation(OpRead))

	// Test risk scoring
	op := SemanticOperation{
		OperationType: OpWrite,
		Parameters: map[string]interface{}{
			"dangerous": true,
		},
	}
	riskScore := cvu.GetOperationRiskScore(op)
	assert.Greater(t, riskScore, 5, "Dangerous write operation should have higher risk score")
}

func TestCommonParser(t *testing.T) {
	// Test the base parser directly
	parser := NewBaseParser("test")

	// Test parsing with base parser
	cmd, _, err := parser.ParseBasicArguments([]string{"-v", "file1.txt", "dir1"})
	require.NoError(t, err)
	assert.Equal(t, "test", cmd.CommandName)
	assert.True(t, cmd.HasOption("-v"), "Should have -v option")
	assert.Equal(t, []string{"file1.txt", "dir1"}, cmd.Arguments)

	// Test file/directory separation
	files, dirs := parser.ParseFilesAndDirectories(cmd.Arguments)
	assert.Contains(t, files, "file1.txt")
	assert.Contains(t, dirs, "dir1")

	// Test semantic operation generation
	gen := NewBaseSemanticOperationGenerator("test")
	ops := gen.GenerateReadOperations(files, dirs, "test_read", nil)
	assert.NotEmpty(t, ops)

	// Should have read operations for files and directories
	hasFileRead := false
	hasDirRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			if op.TargetPath == "file1.txt" {
				hasFileRead = true
			}
			if op.TargetPath == "dir1" {
				hasDirRead = true
			}
		}
	}
	assert.True(t, hasFileRead, "Should have read operation for file")
	assert.True(t, hasDirRead, "Should have read operation for directory")
}