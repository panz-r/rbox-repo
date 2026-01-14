package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadlinkBasenameUptimeParser_Readlink(t *testing.T) {
	parser := &ReadlinkBasenameUptimeParser{commandType: "readlink"}

	// Test readlink with file
	cmd, err := parser.ParseArguments([]string{"symlink.txt"})
	require.NoError(t, err)
	readlinkCmd, ok := cmd.(*ReadlinkCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"symlink.txt"}, readlinkCmd.Files)
	assert.True(t, readlinkCmd.Follow)

	// Test readlink with canonicalize option
	cmd, err = parser.ParseArguments([]string{"-f", "symlink.txt"})
	require.NoError(t, err)
	readlinkCmd, ok = cmd.(*ReadlinkCommand)
	require.True(t, ok)
	assert.True(t, readlinkCmd.Canonicalize)

	// Test readlink with no newline
	cmd, err = parser.ParseArguments([]string{"-n", "symlink.txt"})
	require.NoError(t, err)
	readlinkCmd, ok = cmd.(*ReadlinkCommand)
	require.True(t, ok)
	assert.True(t, readlinkCmd.NoNewline)

	// Test semantic operations for readlink
	ops, err := parser.GetSemanticOperations(readlinkCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for symbolic link
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "symbolic_link", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "readlink", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for symbolic link")

	// Test readlink with no files (should use stdin)
	cmd, err = parser.ParseArguments([]string{"-f"})
	require.NoError(t, err)
	readlinkCmd, ok = cmd.(*ReadlinkCommand)
	require.True(t, ok)
	assert.Empty(t, readlinkCmd.Files)
	assert.True(t, readlinkCmd.Canonicalize)

	// Test semantic operations for stdin
	ops, err = parser.GetSemanticOperations(readlinkCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "symbolic_link", op.Context)
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestReadlinkBasenameUptimeParser_Basename(t *testing.T) {
	parser := &ReadlinkBasenameUptimeParser{commandType: "basename"}

	// Test basename with path
	cmd, err := parser.ParseArguments([]string{"/usr/local/bin/program"})
	require.NoError(t, err)
	basenameCmd, ok := cmd.(*BasenameCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"/usr/local/bin/program"}, basenameCmd.Paths)

	// Test basename with suffix
	cmd, err = parser.ParseArguments([]string{"-s", ".txt", "file.txt"})
	require.NoError(t, err)
	basenameCmd, ok = cmd.(*BasenameCommand)
	require.True(t, ok)
	assert.Equal(t, ".txt", basenameCmd.Suffix)

	// Test basename with multiple option
	cmd, err = parser.ParseArguments([]string{"-a", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	basenameCmd, ok = cmd.(*BasenameCommand)
	require.True(t, ok)
	assert.True(t, basenameCmd.Multiple)

	// Test semantic operations for basename
	ops, err := parser.GetSemanticOperations(basenameCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for pathname
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "pathname", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "basename", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for pathname")
}

func TestReadlinkBasenameUptimeParser_Dirname(t *testing.T) {
	parser := &ReadlinkBasenameUptimeParser{commandType: "dirname"}

	// Test dirname with path
	cmd, err := parser.ParseArguments([]string{"/usr/local/bin/program"})
	require.NoError(t, err)
	dirnameCmd, ok := cmd.(*DirnameCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"/usr/local/bin/program"}, dirnameCmd.Paths)

	// Test dirname with zero option
	cmd, err = parser.ParseArguments([]string{"-z", "/usr/local/bin/program"})
	require.NoError(t, err)
	dirnameCmd, ok = cmd.(*DirnameCommand)
	require.True(t, ok)
	assert.True(t, dirnameCmd.Zero)

	// Test semantic operations for dirname
	ops, err := parser.GetSemanticOperations(dirnameCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for pathname
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "pathname", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "dirname", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for pathname")
}

func TestReadlinkBasenameUptimeParser_Uptime(t *testing.T) {
	parser := &ReadlinkBasenameUptimeParser{commandType: "uptime"}

	// Test uptime with no arguments
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	uptimeCmd, ok := cmd.(*UptimeCommand)
	require.True(t, ok)

	// Test uptime with pretty option
	cmd, err = parser.ParseArguments([]string{"-p"})
	require.NoError(t, err)
	uptimeCmd, ok = cmd.(*UptimeCommand)
	require.True(t, ok)
	assert.True(t, uptimeCmd.Pretty)

	// Test semantic operations for uptime
	ops, err := parser.GetSemanticOperations(uptimeCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have system info read operation
	hasSystemRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "uptime") {
			hasSystemRead = true
			assert.Equal(t, "system_info", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "uptime", val)
			}
			break
		}
	}
	assert.True(t, hasSystemRead, "Should have system info read operation")
}

func TestReadlinkBasenameUptimeParser_Free(t *testing.T) {
	parser := &ReadlinkBasenameUptimeParser{commandType: "free"}

	// Test free with no arguments
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	freeCmd, ok := cmd.(*FreeCommand)
	require.True(t, ok)

	// Test free with human option
	cmd, err = parser.ParseArguments([]string{"-h"})
	require.NoError(t, err)
	freeCmd, ok = cmd.(*FreeCommand)
	require.True(t, ok)
	assert.True(t, freeCmd.Human)

	// Test free with mega option
	cmd, err = parser.ParseArguments([]string{"-m"})
	require.NoError(t, err)
	freeCmd, ok = cmd.(*FreeCommand)
	require.True(t, ok)
	assert.True(t, freeCmd.MegaBytes)

	// Test semantic operations for free
	ops, err := parser.GetSemanticOperations(freeCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have system info read operation
	hasSystemRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "meminfo") {
			hasSystemRead = true
			assert.Equal(t, "system_info", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "free", val)
			}
			break
		}
	}
	assert.True(t, hasSystemRead, "Should have system info read operation")
}

func TestReadlinkBasenameUptimeParser_EdgeCases(t *testing.T) {
	// Test readlink parser with unknown option
	readlinkParser := &ReadlinkBasenameUptimeParser{commandType: "readlink"}
	_, err := readlinkParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test basename parser with unknown option
	basenameParser := &ReadlinkBasenameUptimeParser{commandType: "basename"}
	_, err = basenameParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test dirname parser with unknown option
	dirnameParser := &ReadlinkBasenameUptimeParser{commandType: "dirname"}
	_, err = dirnameParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test uptime parser with unknown option
	uptimeParser := &ReadlinkBasenameUptimeParser{commandType: "uptime"}
	_, err = uptimeParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test free parser with unknown option
	freeParser := &ReadlinkBasenameUptimeParser{commandType: "free"}
	_, err = freeParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestReadlinkBasenameUptimeParser_Soundness(t *testing.T) {
	parser := &ReadlinkBasenameUptimeParser{commandType: "readlink"}

	// Test that file reading is properly captured
	cmd, err := parser.ParseArguments([]string{"symlink.txt"})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have precise read operations for the file
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "symlink.txt" {
			assert.Equal(t, "symbolic_link", op.Context)
			if params, exists := op.Parameters["precise"]; exists && params.(bool) {
				return // Found precise operation
			}
		}
	}
	assert.Fail(t, "Should have precise read operation for symlink.txt")
}