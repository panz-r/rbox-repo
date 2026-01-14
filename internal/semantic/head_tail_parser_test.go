package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeadTailParser(t *testing.T) {
	parser := &HeadTailParser{commandType: "head"}

	// Test head command with files
	cmd, err := parser.ParseArguments([]string{"-n", "5", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	headCmd, ok := cmd.(*HeadTailCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, headCmd.InputFiles)
	assert.NotZero(t, headCmd.Lines)

	// Test tail command with options
	cmd, err = parser.ParseArguments([]string{"-v", "-n", "10", "log.txt"})
	require.NoError(t, err)
	tailCmd, ok := cmd.(*HeadTailCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"log.txt"}, tailCmd.InputFiles)
	assert.True(t, tailCmd.Verbose)
	assert.NotZero(t, tailCmd.Lines)

	// Test semantic operations for head
	ops, err := parser.GetSemanticOperations(headCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "input_file", op.Context)
			if val, exists := op.Parameters["command_type"]; exists {
				assert.Equal(t, "head", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations")

	// Test with stdin (no files)
	cmd, err = parser.ParseArguments([]string{"-n", "5"})
	require.NoError(t, err)
	stdinCmd, ok := cmd.(*HeadTailCommand)
	require.True(t, ok)
	assert.Empty(t, stdinCmd.InputFiles)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(stdinCmd)
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

func TestHeadTailParser_EdgeCases(t *testing.T) {
	parser := &HeadTailParser{}

	// Test with no arguments (should fail)
	_, err := parser.ParseArguments([]string{})
	assert.Error(t, err)

	// Test with only options (no files)
	cmd, err := parser.ParseArguments([]string{"--verbose", "--quiet"})
	require.NoError(t, err)
	headCmd, ok := cmd.(*HeadTailCommand)
	require.True(t, ok)
	assert.True(t, headCmd.Verbose)
	assert.True(t, headCmd.Quiet)
	assert.Empty(t, headCmd.InputFiles)

	// Test with combined options
	cmd, err = parser.ParseArguments([]string{"-nv", "5", "file.txt"})
	require.NoError(t, err)
	headCmd, ok = cmd.(*HeadTailCommand)
	require.True(t, ok)
	assert.NotZero(t, headCmd.Lines)
	assert.True(t, headCmd.Verbose)
	assert.Equal(t, []string{"file.txt"}, headCmd.InputFiles)
}

func TestHeadTailParser_Soundness(t *testing.T) {
	parser := &HeadTailParser{}

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