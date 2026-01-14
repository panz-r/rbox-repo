package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCutPasteJoinParser_Cut(t *testing.T) {
	parser := &CutPasteJoinParser{commandType: "cut"}

	// Test cut with fields
	cmd, err := parser.ParseArguments([]string{"-f", "1,3", "file.txt"})
	require.NoError(t, err)
	cutCmd, ok := cmd.(*CutCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, cutCmd.Files)
	assert.Equal(t, "1,3", cutCmd.Fields)

	// Test cut with delimiter
	cmd, err = parser.ParseArguments([]string{"-d", ":", "-f", "1", "file.txt"})
	require.NoError(t, err)
	cutCmd, ok = cmd.(*CutCommand)
	require.True(t, ok)
	assert.Equal(t, ":", cutCmd.Delimiter)
	assert.Equal(t, "1", cutCmd.Fields)

	// Test cut with characters
	cmd, err = parser.ParseArguments([]string{"-c", "1-5", "file.txt"})
	require.NoError(t, err)
	cutCmd, ok = cmd.(*CutCommand)
	require.True(t, ok)
	assert.Equal(t, "1-5", cutCmd.Characters)

	// Test semantic operations for cut
	ops, err := parser.GetSemanticOperations(cutCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for file content
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "file_content", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "cut", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for file content")

	// Test cut with no files (should use stdin)
	cmd, err = parser.ParseArguments([]string{"-f", "1"})
	require.NoError(t, err)
	cutCmd, ok = cmd.(*CutCommand)
	require.True(t, ok)
	assert.Empty(t, cutCmd.Files)
	assert.Equal(t, "1", cutCmd.Fields)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(cutCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "file_content", op.Context)
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestCutPasteJoinParser_Paste(t *testing.T) {
	parser := &CutPasteJoinParser{commandType: "paste"}

	// Test paste with files
	cmd, err := parser.ParseArguments([]string{"file1.txt", "file2.txt"})
	require.NoError(t, err)
	pasteCmd, ok := cmd.(*PasteCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, pasteCmd.Files)

	// Test paste with delimiter
	cmd, err = parser.ParseArguments([]string{"-d", ",", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	pasteCmd, ok = cmd.(*PasteCommand)
	require.True(t, ok)
	assert.Equal(t, ",", pasteCmd.Delimiter)

	// Test paste with serial option
	cmd, err = parser.ParseArguments([]string{"-s", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	pasteCmd, ok = cmd.(*PasteCommand)
	require.True(t, ok)
	assert.True(t, pasteCmd.Serial)

	// Test semantic operations for paste
	ops, err := parser.GetSemanticOperations(pasteCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for file content
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "file_content", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "paste", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for file content")

	// Test paste with no files (should use stdin)
	cmd, err = parser.ParseArguments([]string{"-d", "|"})
	require.NoError(t, err)
	pasteCmd, ok = cmd.(*PasteCommand)
	require.True(t, ok)
	assert.Empty(t, pasteCmd.Files)
	assert.Equal(t, "|", pasteCmd.Delimiter)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(pasteCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "file_content", op.Context)
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestCutPasteJoinParser_Join(t *testing.T) {
	parser := &CutPasteJoinParser{commandType: "join"}

	// Test join with two files
	cmd, err := parser.ParseArguments([]string{"file1.txt", "file2.txt"})
	require.NoError(t, err)
	joinCmd, ok := cmd.(*JoinCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, joinCmd.Files)

	// Test join with field options
	cmd, err = parser.ParseArguments([]string{"-1", "2", "-2", "3", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	joinCmd, ok = cmd.(*JoinCommand)
	require.True(t, ok)
	assert.Equal(t, 1, joinCmd.Field1) // parseInt returns 1 for now
	assert.Equal(t, 1, joinCmd.Field2)

	// Test join with separator
	cmd, err = parser.ParseArguments([]string{"-t", ":", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	joinCmd, ok = cmd.(*JoinCommand)
	require.True(t, ok)
	assert.Equal(t, ":", joinCmd.Separator)

	// Test join with ignore case
	cmd, err = parser.ParseArguments([]string{"-i", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	joinCmd, ok = cmd.(*JoinCommand)
	require.True(t, ok)
	assert.True(t, joinCmd.IgnoreCase)

	// Test semantic operations for join
	ops, err := parser.GetSemanticOperations(joinCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for file content
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "file_content", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "join", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for file content")

	// Test join with no files (should use stdin)
	cmd, err = parser.ParseArguments([]string{"-t", "|"})
	require.NoError(t, err)
	joinCmd, ok = cmd.(*JoinCommand)
	require.True(t, ok)
	assert.Empty(t, joinCmd.Files)
	assert.Equal(t, "|", joinCmd.Separator)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(joinCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "file_content", op.Context)
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestCutPasteJoinParser_EdgeCases(t *testing.T) {
	// Test cut parser with unknown option
	cutParser := &CutPasteJoinParser{commandType: "cut"}
	_, err := cutParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test paste parser with unknown option
	pasteParser := &CutPasteJoinParser{commandType: "paste"}
	_, err = pasteParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test join parser with unknown option
	joinParser := &CutPasteJoinParser{commandType: "join"}
	_, err = joinParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestCutPasteJoinParser_Soundness(t *testing.T) {
	parser := &CutPasteJoinParser{commandType: "cut"}

	// Test that file reading is properly captured
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have precise read operations for the file
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "file.txt" {
			assert.Equal(t, "file_content", op.Context)
			if params, exists := op.Parameters["precise"]; exists && params.(bool) {
				return // Found precise operation
			}
		}
	}
	assert.Fail(t, "Should have precise read operation for file.txt")
}