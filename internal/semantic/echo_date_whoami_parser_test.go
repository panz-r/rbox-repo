package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEchoDateWhoamiParser_Echo(t *testing.T) {
	parser := &EchoDateWhoamiParser{commandType: "echo"}

	// Test echo with text
	cmd, err := parser.ParseArguments([]string{"Hello World"})
	require.NoError(t, err)
	echoCmd, ok := cmd.(*EchoCommand)
	require.True(t, ok)
	assert.Equal(t, "Hello World", echoCmd.Text)
	assert.False(t, echoCmd.NoNewline)
	assert.False(t, echoCmd.EnableInterpretation)

	// Test echo with -n option
	cmd, err = parser.ParseArguments([]string{"-n", "Hello"})
	require.NoError(t, err)
	echoCmd, ok = cmd.(*EchoCommand)
	require.True(t, ok)
	assert.Equal(t, "Hello", echoCmd.Text)
	assert.True(t, echoCmd.NoNewline)

	// Test echo with -e option
	cmd, err = parser.ParseArguments([]string{"-e", "Hello $USER"})
	require.NoError(t, err)
	echoCmd, ok = cmd.(*EchoCommand)
	require.True(t, ok)
	assert.Equal(t, "Hello $USER", echoCmd.Text)
	assert.True(t, echoCmd.EnableInterpretation)

	// Test semantic operations for echo
	ops, err := parser.GetSemanticOperations(echoCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdout write operation
	hasStdout := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdout" {
			hasStdout = true
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "echo", val)
			}
			break
		}
	}
	assert.True(t, hasStdout, "Should have stdout operation")

	// Test echo with no arguments
	cmd, err = parser.ParseArguments([]string{})
	require.NoError(t, err)
	echoCmd, ok = cmd.(*EchoCommand)
	require.True(t, ok)
	assert.Empty(t, echoCmd.Text)
}

func TestEchoDateWhoamiParser_Date(t *testing.T) {
	parser := &EchoDateWhoamiParser{commandType: "date"}

	// Test date with no arguments (shows current date)
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	dateCmd, ok := cmd.(*DateCommand)
	require.True(t, ok)
	assert.Empty(t, dateCmd.Format)
	assert.False(t, dateCmd.UTC)

	// Test date with format
	cmd, err = parser.ParseArguments([]string{"+%Y-%m-%d"})
	require.NoError(t, err)
	dateCmd, ok = cmd.(*DateCommand)
	require.True(t, ok)
	assert.Equal(t, "+%Y-%m-%d", dateCmd.Format)

	// Test date with UTC option
	cmd, err = parser.ParseArguments([]string{"-u"})
	require.NoError(t, err)
	dateCmd, ok = cmd.(*DateCommand)
	require.True(t, ok)
	assert.True(t, dateCmd.UTC)

	// Test date with ISO-8601 format
	cmd, err = parser.ParseArguments([]string{"--iso-8601"})
	require.NoError(t, err)
	dateCmd, ok = cmd.(*DateCommand)
	require.True(t, ok)
	assert.True(t, dateCmd.ISO8601)

	// Test semantic operations for date
	ops, err := parser.GetSemanticOperations(dateCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have system time read operation
	hasTimeRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "time") {
			hasTimeRead = true
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "date", val)
			}
			break
		}
	}
	assert.True(t, hasTimeRead, "Should have system time read operation")
}

func TestEchoDateWhoamiParser_Whoami(t *testing.T) {
	parser := &EchoDateWhoamiParser{commandType: "whoami"}

	// Test whoami with no arguments
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	whoamiCmd, ok := cmd.(*WhoamiCommand)
	require.True(t, ok)

	// Test semantic operations for whoami
	ops, err := parser.GetSemanticOperations(whoamiCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have user info read operation
	hasUserRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "status") {
			hasUserRead = true
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "whoami", val)
			}
			break
		}
	}
	assert.True(t, hasUserRead, "Should have user info read operation")

	// Test whoami with help option
	cmd, err = parser.ParseArguments([]string{"--help"})
	require.NoError(t, err)
	whoamiCmd, ok = cmd.(*WhoamiCommand)
	require.True(t, ok)
	if val, exists := whoamiCmd.Options["--help"]; exists {
		assert.True(t, val.(bool))
	}
}

func TestEchoDateWhoamiParser_EdgeCases(t *testing.T) {
	// Test echo parser with unknown option
	echoParser := &EchoDateWhoamiParser{commandType: "echo"}
	_, err := echoParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test date parser with unknown option
	dateParser := &EchoDateWhoamiParser{commandType: "date"}
	_, err = dateParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test whoami parser with unexpected argument
	whoamiParser := &EchoDateWhoamiParser{commandType: "whoami"}
	_, err = whoamiParser.ParseArguments([]string{"unexpected"})
	assert.Error(t, err)
}

func TestEchoDateWhoamiParser_Soundness(t *testing.T) {
	// Test echo with variable interpretation
	echoParser := &EchoDateWhoamiParser{commandType: "echo"}
	cmd, err := echoParser.ParseArguments([]string{"-e", "Hello $USER"})
	require.NoError(t, err)

	ops, err := echoParser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have environment read operation when interpretation is enabled
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "environment") {
			assert.Equal(t, "environment_variables", op.Context)
			if params, exists := op.Parameters["over_approximated"]; exists && params.(bool) {
				return // Found over-approximated operation
			}
		}
	}
	assert.Fail(t, "Should have over-approximated environment read operation")
}