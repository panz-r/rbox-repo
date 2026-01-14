package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatFileParser_Stat(t *testing.T) {
	parser := &StatFileParser{commandType: "stat"}

	// Test stat with files
	cmd, err := parser.ParseArguments([]string{"file1.txt", "file2.txt"})
	require.NoError(t, err)
	statCmd, ok := cmd.(*StatCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, statCmd.Files)
	assert.False(t, statCmd.FileSystem)
	assert.False(t, statCmd.Terse)

	// Test stat with format option
	cmd, err = parser.ParseArguments([]string{"-c", "%n:%s", "file.txt"})
	require.NoError(t, err)
	statCmd, ok = cmd.(*StatCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, statCmd.Files)
	assert.Equal(t, "%n:%s", statCmd.Format)

	// Test stat with file system option
	cmd, err = parser.ParseArguments([]string{"-f", "file.txt"})
	require.NoError(t, err)
	statCmd, ok = cmd.(*StatCommand)
	require.True(t, ok)
	assert.True(t, statCmd.FileSystem)

	// Test semantic operations for stat
	ops, err := parser.GetSemanticOperations(statCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for file metadata
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "file_metadata", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "stat", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for file metadata")

	// Test stat with no files (should use stdin)
	cmd, err = parser.ParseArguments([]string{"-t"})
	require.NoError(t, err)
	statCmd, ok = cmd.(*StatCommand)
	require.True(t, ok)
	assert.Empty(t, statCmd.Files)
	assert.True(t, statCmd.Terse)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(statCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "file_metadata", op.Context)
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestStatFileParser_File(t *testing.T) {
	parser := &StatFileParser{commandType: "file"}

	// Test file with files
	cmd, err := parser.ParseArguments([]string{"file1.txt", "file2.txt"})
	require.NoError(t, err)
	fileCmd, ok := cmd.(*FileCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, fileCmd.Files)
	assert.False(t, fileCmd.Brief)
	assert.False(t, fileCmd.MimeType)

	// Test file with brief option
	cmd, err = parser.ParseArguments([]string{"-b", "file.txt"})
	require.NoError(t, err)
	fileCmd, ok = cmd.(*FileCommand)
	require.True(t, ok)
	assert.True(t, fileCmd.Brief)

	// Test file with mime type option
	cmd, err = parser.ParseArguments([]string{"-i", "file.txt"})
	require.NoError(t, err)
	fileCmd, ok = cmd.(*FileCommand)
	require.True(t, ok)
	assert.True(t, fileCmd.MimeType)

	// Test file with combined options
	cmd, err = parser.ParseArguments([]string{"-bi", "file.txt"})
	require.NoError(t, err)
	fileCmd, ok = cmd.(*FileCommand)
	require.True(t, ok)
	assert.True(t, fileCmd.Brief)
	assert.True(t, fileCmd.MimeType)

	// Test semantic operations for file
	ops, err := parser.GetSemanticOperations(fileCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for file type
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "file_type", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "file", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for file type")

	// Test file with no files (should use stdin)
	cmd, err = parser.ParseArguments([]string{"--mime-encoding"})
	require.NoError(t, err)
	fileCmd, ok = cmd.(*FileCommand)
	require.True(t, ok)
	assert.Empty(t, fileCmd.Files)
	assert.True(t, fileCmd.MimeEncoding)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(fileCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "file_type", op.Context)
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestStatFileParser_EdgeCases(t *testing.T) {
	// Test stat parser with unknown option
	statParser := &StatFileParser{commandType: "stat"}
	_, err := statParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test file parser with unknown option
	fileParser := &StatFileParser{commandType: "file"}
	_, err = fileParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestStatFileParser_Soundness(t *testing.T) {
	parser := &StatFileParser{commandType: "stat"}

	// Test that file reading is properly captured
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have precise read operation for the file
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "file.txt" {
			assert.Equal(t, "file_metadata", op.Context)
			if params, exists := op.Parameters["precise"]; exists && params.(bool) {
				return // Found precise operation
			}
		}
	}
	assert.Fail(t, "Should have precise read operation for file.txt")
}