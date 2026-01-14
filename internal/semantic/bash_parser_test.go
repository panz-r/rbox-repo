package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBashParser(t *testing.T) {
	parser := NewBashParser()

	// Test simple bash command with -c option
	cmd, err := parser.ParseArguments([]string{"-c", "echo hello"})
	require.NoError(t, err)
	bashCmd, ok := cmd.(*BashCommand)
	require.True(t, ok)
	assert.Equal(t, "echo hello", bashCmd.Script)
	assert.Equal(t, "echo hello", bashCmd.CommandLine)
	assert.False(t, bashCmd.HasExecution)
	assert.False(t, bashCmd.HasSubshell)

	// Test bash command with execution patterns
	cmd, err = parser.ParseArguments([]string{"-c", "$(whoami)"})
	require.NoError(t, err)
	bashCmd, ok = cmd.(*BashCommand)
	require.True(t, ok)
	assert.Equal(t, "$(whoami)", bashCmd.Script)
	assert.True(t, bashCmd.HasExecution)
	assert.True(t, bashCmd.HasSubshell)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(bashCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have execute operations
	hasExecute := false
	hasDangerous := false
	for _, op := range ops {
		if op.OperationType == OpExecute {
			hasExecute = true
		}
		if op.Parameters != nil {
			if dangerous, ok := op.Parameters["dangerous"].(bool); ok && dangerous {
				hasDangerous = true
			}
		}
	}
	assert.True(t, hasExecute, "Should have execute operations")
	assert.True(t, hasDangerous, "Should have dangerous operations")

	// Test bash command with subshell
	cmd, err = parser.ParseArguments([]string{"-c", "(ls; pwd)"})
	require.NoError(t, err)
	bashCmd, ok = cmd.(*BashCommand)
	require.True(t, ok)
	assert.Equal(t, "(ls; pwd)", bashCmd.Script)
	assert.True(t, bashCmd.HasSubshell)

	// Test bash command with multiple options
	cmd, err = parser.ParseArguments([]string{"-v", "-i", "-c", "echo test"})
	require.NoError(t, err)
	bashCmd, ok = cmd.(*BashCommand)
	require.True(t, ok)
	assert.Equal(t, "echo test", bashCmd.Script)
	assert.True(t, bashCmd.Options["-v"].(bool))
	assert.True(t, bashCmd.Options["interactive"].(bool))
}

func TestBashParserExecutionPatterns(t *testing.T) {
	parser := NewBashParser()

	testCases := []struct {
		script     string
		expectedExec bool
		expectedSubshell bool
	}{
		{"echo hello", false, false},
		{"$(whoami)", true, true},
		{"`date`", true, true},
		{"$(ls)", true, true},
		{"exec command", true, false},
		{"eval \"echo test\"", true, false},
		{"source file.sh", true, false},
		{". file.sh", true, false},
		{"ls | grep test", false, false},
		{"(cd /tmp && ls)", false, true},
		{"if true; then echo test; fi", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.script, func(t *testing.T) {
			cmd, err := parser.ParseArguments([]string{"-c", tc.script})
			require.NoError(t, err)
			bashCmd, ok := cmd.(*BashCommand)
			require.True(t, ok)
			assert.Equal(t, tc.expectedExec, bashCmd.HasExecution)
			assert.Equal(t, tc.expectedSubshell, bashCmd.HasSubshell)
		})
	}
}