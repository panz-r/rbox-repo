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

func TestBashParserAdvancedPatterns(t *testing.T) {
	parser := NewBashParser()

	testCases := []struct {
		script string
		expectedEnvironmentVariables bool
		expectedSourceCommands bool
		expectedLoops bool
		expectedConditionals bool
	}{
		{"echo hello", false, false, false, false},
		{"export PATH=/usr/bin", true, false, false, false},
		{"export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1", true, false, false, false},
		{". venv/bin/activate", false, true, false, false},
		{"source /etc/profile", false, true, false, false},
		{"for f in *.rs; do echo $f; done", false, false, true, false},
		{"if [ -f file.txt ]; then echo exists; fi", false, false, false, true},
		{"cd /home/panz/osrc/mistral-vibe && export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 && . venv/bin/activate", true, true, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.script, func(t *testing.T) {
			cmd, err := parser.ParseArguments([]string{"-c", tc.script})
			require.NoError(t, err)
			bashCmd, ok := cmd.(*BashCommand)
			require.True(t, ok)
			assert.Equal(t, tc.expectedEnvironmentVariables, bashCmd.HasEnvironmentVariables)
			assert.Equal(t, tc.expectedSourceCommands, bashCmd.HasSourceCommands)
			assert.Equal(t, tc.expectedLoops, bashCmd.HasLoops)
			assert.Equal(t, tc.expectedConditionals, bashCmd.HasConditionals)
		})
	}
}

func TestBashParserComplexPatterns(t *testing.T) {
	parser := NewBashParser()

	testCases := []struct {
		script string
		expectedChaining bool
		expectedPipes bool
		expectedRedirections bool
		expectedIndividualCommands int
	}{
		{"echo hello", false, false, false, 1},
		{"echo hello && echo world", true, false, false, 2},
		{"ls | grep test", false, true, false, 3},
		{"echo test > file.txt", false, false, true, 1},
		{"echo hello | grep test && echo world", true, true, false, 4},
		{"echo test > file.txt && echo test2 > file2.txt", true, false, true, 2},
	}

	for _, tc := range testCases {
		t.Run(tc.script, func(t *testing.T) {
			cmd, err := parser.ParseArguments([]string{"-c", tc.script})
			require.NoError(t, err)
			bashCmd, ok := cmd.(*BashCommand)
			require.True(t, ok)
			assert.Equal(t, tc.expectedChaining, bashCmd.HasChaining)
			assert.Equal(t, tc.expectedPipes, bashCmd.HasPipes)
			assert.Equal(t, tc.expectedRedirections, bashCmd.HasRedirections)
			if len(bashCmd.IndividualCommands) != tc.expectedIndividualCommands {
		t.Logf("Expected %d commands, got %d: %v", tc.expectedIndividualCommands, len(bashCmd.IndividualCommands), bashCmd.IndividualCommands)
	}
	assert.Equal(t, tc.expectedIndividualCommands, len(bashCmd.IndividualCommands))
		})
	}
}