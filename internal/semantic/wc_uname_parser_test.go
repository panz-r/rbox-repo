package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWcUnameParser_Wc(t *testing.T) {
	parser := &WcUnameParser{commandType: "wc"}

	// Test wc with files
	cmd, err := parser.ParseArguments([]string{"file1.txt", "file2.txt"})
	require.NoError(t, err)
	wcCmd, ok := cmd.(*WcCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, wcCmd.InputFiles)
	assert.True(t, wcCmd.CountLines)
	assert.True(t, wcCmd.CountWords)
	assert.True(t, wcCmd.CountChars)

	// Test wc with specific options
	cmd, err = parser.ParseArguments([]string{"-l", "file.txt"})
	require.NoError(t, err)
	wcCmd, ok = cmd.(*WcCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, wcCmd.InputFiles)
	assert.True(t, wcCmd.CountLines)
	assert.False(t, wcCmd.CountWords)
	assert.False(t, wcCmd.CountChars)

	// Test wc with combined options
	cmd, err = parser.ParseArguments([]string{"-lc", "data.txt"})
	require.NoError(t, err)
	wcCmd, ok = cmd.(*WcCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"data.txt"}, wcCmd.InputFiles)
	assert.True(t, wcCmd.CountLines)
	assert.True(t, wcCmd.CountBytes)

	// Test semantic operations for wc
	ops, err := parser.GetSemanticOperations(wcCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "input_file", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "wc", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations")

	// Test wc with stdin (no files)
	cmd, err = parser.ParseArguments([]string{"-w"})
	require.NoError(t, err)
	wcCmd, ok = cmd.(*WcCommand)
	require.True(t, ok)
	assert.Empty(t, wcCmd.InputFiles)
	assert.True(t, wcCmd.CountWords)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(wcCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "stdin", op.Context)
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestWcUnameParser_Uname(t *testing.T) {
	parser := &WcUnameParser{commandType: "uname"}

	// Test uname with no options (should show system info)
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	unameCmd, ok := cmd.(*UnameCommand)
	require.True(t, ok)

	// Test uname with -a option
	cmd, err = parser.ParseArguments([]string{"-a"})
	require.NoError(t, err)
	unameCmd, ok = cmd.(*UnameCommand)
	require.True(t, ok)
	assert.True(t, unameCmd.AllInfo)

	// Test uname with specific options
	cmd, err = parser.ParseArguments([]string{"-s", "-n", "-r"})
	require.NoError(t, err)
	unameCmd, ok = cmd.(*UnameCommand)
	require.True(t, ok)
	assert.True(t, unameCmd.KernelName)
	assert.True(t, unameCmd.NodeName)
	assert.True(t, unameCmd.KernelRelease)

	// Test semantic operations for uname
	ops, err := parser.GetSemanticOperations(unameCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have system info read operation
	hasSystemRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "kernel") {
			hasSystemRead = true
			assert.Equal(t, "system_info", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "uname", val)
			}
			break
		}
	}
	assert.True(t, hasSystemRead, "Should have system info read operation")
}

func TestWcUnameParser_EdgeCases(t *testing.T) {
	// Test wc parser with no arguments (should fail)
	wcParser := &WcUnameParser{commandType: "wc"}
	_, err := wcParser.ParseArguments([]string{})
	assert.Error(t, err)

	// Test uname parser with unknown option
	unameParser := &WcUnameParser{commandType: "uname"}
	_, err = unameParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestWcUnameParser_Soundness(t *testing.T) {
	parser := &WcUnameParser{commandType: "wc"}

	// Test that file reading is properly captured
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have precise read operation for the file
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "file.txt" {
			assert.Equal(t, "input_file", op.Context)
			if params, exists := op.Parameters["precise"]; exists && params.(bool) {
				return // Found precise operation
			}
		}
	}
	assert.Fail(t, "Should have precise read operation for file.txt")
}