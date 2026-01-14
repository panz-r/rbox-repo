package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffCommUniqParser_Diff(t *testing.T) {
	parser := &DiffCommUniqParser{commandType: "diff"}

	// Test diff with two files
	cmd, err := parser.ParseArguments([]string{"file1.txt", "file2.txt"})
	require.NoError(t, err)
	diffCmd, ok := cmd.(*DiffCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, diffCmd.Files)
	assert.Equal(t, 3, diffCmd.Context) // Default context

	// Test diff with unified format
	cmd, err = parser.ParseArguments([]string{"-u", "5", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	diffCmd, ok = cmd.(*DiffCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, diffCmd.Files)
	assert.True(t, diffCmd.Unified > 0)

	// Test diff with ignore case
	cmd, err = parser.ParseArguments([]string{"-i", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	diffCmd, ok = cmd.(*DiffCommand)
	require.True(t, ok)
	assert.True(t, diffCmd.IgnoreCase)

	// Test semantic operations for diff
	ops, err := parser.GetSemanticOperations(diffCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for file content
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "file_content", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "diff", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for file content")

	// Test diff with no files (should use stdin)
	cmd, err = parser.ParseArguments([]string{"-q"})
	require.NoError(t, err)
	diffCmd, ok = cmd.(*DiffCommand)
	require.True(t, ok)
	assert.Empty(t, diffCmd.Files)
	assert.True(t, diffCmd.Brief)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(diffCmd)
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

func TestDiffCommUniqParser_Comm(t *testing.T) {
	parser := &DiffCommUniqParser{commandType: "comm"}

	// Test comm with two files
	cmd, err := parser.ParseArguments([]string{"file1.txt", "file2.txt"})
	require.NoError(t, err)
	commCmd, ok := cmd.(*CommCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, commCmd.Files)

	// Test comm with column suppression
	cmd, err = parser.ParseArguments([]string{"-1", "-3", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	commCmd, ok = cmd.(*CommCommand)
	require.True(t, ok)
	assert.True(t, commCmd.SuppressColumn1)
	assert.True(t, commCmd.SuppressColumn3)

	// Test semantic operations for comm
	ops, err := parser.GetSemanticOperations(commCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for file content
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "file_content", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "comm", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for file content")
}

func TestDiffCommUniqParser_Uniq(t *testing.T) {
	parser := &DiffCommUniqParser{commandType: "uniq"}

	// Test uniq with file
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)
	uniqCmd, ok := cmd.(*UniqCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, uniqCmd.Files)

	// Test uniq with count option
	cmd, err = parser.ParseArguments([]string{"-c", "file.txt"})
	require.NoError(t, err)
	uniqCmd, ok = cmd.(*UniqCommand)
	require.True(t, ok)
	assert.True(t, uniqCmd.Count)

	// Test uniq with repeated option
	cmd, err = parser.ParseArguments([]string{"-d", "file.txt"})
	require.NoError(t, err)
	uniqCmd, ok = cmd.(*UniqCommand)
	require.True(t, ok)
	assert.True(t, uniqCmd.Repeated)

	// Test uniq with skip fields
	cmd, err = parser.ParseArguments([]string{"-f", "2", "file.txt"})
	require.NoError(t, err)
	uniqCmd, ok = cmd.(*UniqCommand)
	require.True(t, ok)
	assert.Equal(t, 1, uniqCmd.SkipFields) // parseInt returns 1 for now

	// Test semantic operations for uniq
	ops, err := parser.GetSemanticOperations(uniqCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for file content
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "file_content", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "uniq", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for file content")

	// Test uniq with no files (should use stdin)
	cmd, err = parser.ParseArguments([]string{"-u"})
	require.NoError(t, err)
	uniqCmd, ok = cmd.(*UniqCommand)
	require.True(t, ok)
	assert.Empty(t, uniqCmd.Files)
	assert.True(t, uniqCmd.Unique)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(uniqCmd)
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

func TestDiffCommUniqParser_EdgeCases(t *testing.T) {
	// Test diff parser with unknown option
	diffParser := &DiffCommUniqParser{commandType: "diff"}
	_, err := diffParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test comm parser with unknown option
	commParser := &DiffCommUniqParser{commandType: "comm"}
	_, err = commParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test uniq parser with unknown option
	uniqParser := &DiffCommUniqParser{commandType: "uniq"}
	_, err = uniqParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestDiffCommUniqParser_Soundness(t *testing.T) {
	parser := &DiffCommUniqParser{commandType: "diff"}

	// Test that file reading is properly captured
	cmd, err := parser.ParseArguments([]string{"file1.txt", "file2.txt"})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have precise read operations for the files
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "file1.txt" {
			assert.Equal(t, "file_content", op.Context)
			if params, exists := op.Parameters["precise"]; exists && params.(bool) {
				return // Found precise operation
			}
		}
	}
	assert.Fail(t, "Should have precise read operation for file1.txt")
}