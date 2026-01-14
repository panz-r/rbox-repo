package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPwdParser(t *testing.T) {
	parser := NewPwdParser()

	// Test simple pwd command
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	pwdCmd, ok := cmd.(*PwdCommand)
	require.True(t, ok)
	assert.True(t, pwdCmd.Logical)
	assert.False(t, pwdCmd.Physical)

	// Test pwd with physical option
	cmd, err = parser.ParseArguments([]string{"-P"})
	require.NoError(t, err)
	pwdCmd, ok = cmd.(*PwdCommand)
	require.True(t, ok)
	assert.True(t, pwdCmd.Physical)
	assert.False(t, pwdCmd.Logical)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(pwdCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
			assert.Equal(t, "/proc/self/cwd", op.TargetPath)
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations")
}

func TestSleepParser(t *testing.T) {
	parser := NewSleepParser()

	// Test sleep command
	cmd, err := parser.ParseArguments([]string{"5"})
	require.NoError(t, err)
	sleepCmd, ok := cmd.(*SleepCommand)
	require.True(t, ok)
	assert.Equal(t, "5", sleepCmd.Duration)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(sleepCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for process state
	hasProcessRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "proc") {
			hasProcessRead = true
			break
		}
	}
	assert.True(t, hasProcessRead, "Should have process state read operations")
}

func TestTimeoutParser(t *testing.T) {
	parser := NewTimeoutParser()

	// Test timeout command
	cmd, err := parser.ParseArguments([]string{"10", "sleep", "5"})
	require.NoError(t, err)
	timeoutCmd, ok := cmd.(*TimeoutCommand)
	require.True(t, ok)
	assert.Equal(t, "10", timeoutCmd.Duration)
	assert.Equal(t, "sleep", timeoutCmd.Command)
	assert.Equal(t, []string{"5"}, timeoutCmd.Args)

	// Test timeout with kill-after option
	cmd, err = parser.ParseArguments([]string{"10", "-k", "5", "sleep", "5"})
	require.NoError(t, err)
	timeoutCmd, ok = cmd.(*TimeoutCommand)
	require.True(t, ok)
	assert.Equal(t, "10", timeoutCmd.Duration)
	assert.True(t, timeoutCmd.KillAfter)
	assert.Equal(t, "5", timeoutCmd.Signal)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(timeoutCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have execute operations
	hasExecute := false
	for _, op := range ops {
		if op.OperationType == OpExecute {
			hasExecute = true
			break
		}
	}
	assert.True(t, hasExecute, "Should have execute operations")
}

func TestWhichParser(t *testing.T) {
	parser := NewWhichParser()

	// Test which command
	cmd, err := parser.ParseArguments([]string{"ls", "grep"})
	require.NoError(t, err)
	whichCmd, ok := cmd.(*WhichCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"ls", "grep"}, whichCmd.Programs)
	assert.False(t, whichCmd.All)

	// Test which with all option
	cmd, err = parser.ParseArguments([]string{"-a", "python"})
	require.NoError(t, err)
	whichCmd, ok = cmd.(*WhichCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"python"}, whichCmd.Programs)
	assert.True(t, whichCmd.All)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(whichCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for PATH and executables
	hasPathRead := false
	hasExecRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			if op.TargetPath == "$PATH" {
				hasPathRead = true
			}
			if strings.Contains(op.TargetPath, "/usr/bin/") || strings.Contains(op.TargetPath, "/bin/") {
				hasExecRead = true
			}
		}
	}
	assert.True(t, hasPathRead, "Should have PATH read operations")
	assert.True(t, hasExecRead, "Should have executable search operations")
}

func TestFreeParser(t *testing.T) {
	parser := NewFreeParser()

	// Test free command
	cmd, err := parser.ParseArguments([]string{"-h"})
	require.NoError(t, err)
	freeCmd, ok := cmd.(*FreeCommand)
	require.True(t, ok)
	assert.True(t, freeCmd.Human)

	// Test free with multiple options
	cmd, err = parser.ParseArguments([]string{"-h", "-t", "-w"})
	require.NoError(t, err)
	freeCmd, ok = cmd.(*FreeCommand)
	require.True(t, ok)
	assert.True(t, freeCmd.Human)
	assert.True(t, freeCmd.Total)
	assert.True(t, freeCmd.Wide)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(freeCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for memory info
	hasMemRead := false
	hasSwapRead := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			if op.TargetPath == "/proc/meminfo" {
				hasMemRead = true
			}
			if op.TargetPath == "/proc/swaps" {
				hasSwapRead = true
			}
		}
	}
	assert.True(t, hasMemRead, "Should have memory info read operations")
	assert.True(t, hasSwapRead, "Should have swap info read operations")
}