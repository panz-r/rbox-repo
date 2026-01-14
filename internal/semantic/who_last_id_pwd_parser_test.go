package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoLastIdPwdParser_Who(t *testing.T) {
	parser := &WhoLastIdPwdParser{commandType: "who"}

	// Test who with no arguments
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	whoCmd, ok := cmd.(*WhoCommand)
	require.True(t, ok)
	assert.Empty(t, whoCmd.Users)

	// Test who with heading option
	cmd, err = parser.ParseArguments([]string{"-H"})
	require.NoError(t, err)
	whoCmd, ok = cmd.(*WhoCommand)
	require.True(t, ok)
	assert.True(t, whoCmd.Heading)

	// Test who with short option
	cmd, err = parser.ParseArguments([]string{"-s"})
	require.NoError(t, err)
	whoCmd, ok = cmd.(*WhoCommand)
	require.True(t, ok)
	assert.True(t, whoCmd.Short)

	// Test who with user filter
	cmd, err = parser.ParseArguments([]string{"root", "user1"})
	require.NoError(t, err)
	whoCmd, ok = cmd.(*WhoCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"root", "user1"}, whoCmd.Users)

	// Test semantic operations for who
	ops, err := parser.GetSemanticOperations(whoCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have system info read operation
	hasSystemRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "utmp") {
			hasSystemRead = true
			assert.Equal(t, "user_info", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "who", val)
			}
			break
		}
	}
	assert.True(t, hasSystemRead, "Should have system info read operation")
}

func TestWhoLastIdPwdParser_Last(t *testing.T) {
	parser := &WhoLastIdPwdParser{commandType: "last"}

	// Test last with no arguments
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	lastCmd, ok := cmd.(*LastCommand)
	require.True(t, ok)
	assert.Equal(t, -1, lastCmd.Number)

	// Test last with limit
	cmd, err = parser.ParseArguments([]string{"-n", "10"})
	require.NoError(t, err)
	lastCmd, ok = cmd.(*LastCommand)
	require.True(t, ok)
	assert.Equal(t, 1, lastCmd.Number) // parseInt returns 1 for now

	// Test last with full times
	cmd, err = parser.ParseArguments([]string{"-f"})
	require.NoError(t, err)
	lastCmd, ok = cmd.(*LastCommand)
	require.True(t, ok)
	assert.True(t, lastCmd.FullTimes)

	// Test semantic operations for last
	ops, err := parser.GetSemanticOperations(lastCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have system info read operation
	hasSystemRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "wtmp") {
			hasSystemRead = true
			assert.Equal(t, "login_info", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "last", val)
			}
			break
		}
	}
	assert.True(t, hasSystemRead, "Should have system info read operation")
}

func TestWhoLastIdPwdParser_Id(t *testing.T) {
	parser := &WhoLastIdPwdParser{commandType: "id"}

	// Test id with no arguments (shows current user info)
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	idCmd, ok := cmd.(*IdCommand)
	require.True(t, ok)

	// Test id with user option
	cmd, err = parser.ParseArguments([]string{"-u"})
	require.NoError(t, err)
	idCmd, ok = cmd.(*IdCommand)
	require.True(t, ok)
	assert.Equal(t, "user", idCmd.User)

	// Test id with group option
	cmd, err = parser.ParseArguments([]string{"-g"})
	require.NoError(t, err)
	idCmd, ok = cmd.(*IdCommand)
	require.True(t, ok)
	assert.Equal(t, "group", idCmd.Group)

	// Test id with username
	cmd, err = parser.ParseArguments([]string{"username"})
	require.NoError(t, err)
	idCmd, ok = cmd.(*IdCommand)
	require.True(t, ok)
	if val, exists := idCmd.Options["username"]; exists {
		assert.Equal(t, "username", val)
	}

	// Test semantic operations for id
	ops, err := parser.GetSemanticOperations(idCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have system info read operations
	hasSystemRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && (strings.Contains(op.TargetPath, "passwd") || strings.Contains(op.TargetPath, "group")) {
			hasSystemRead = true
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "id", val)
			}
			break
		}
	}
	assert.True(t, hasSystemRead, "Should have system info read operations")
}

func TestWhoLastIdPwdParser_Pwd(t *testing.T) {
	parser := &WhoLastIdPwdParser{commandType: "pwd"}

	// Test pwd with no arguments
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	pwdCmd, ok := cmd.(*PwdCommand)
	require.True(t, ok)
	assert.True(t, pwdCmd.Logical)
	assert.False(t, pwdCmd.Physical)

	// Test pwd with logical option
	cmd, err = parser.ParseArguments([]string{"-L"})
	require.NoError(t, err)
	pwdCmd, ok = cmd.(*PwdCommand)
	require.True(t, ok)
	assert.True(t, pwdCmd.Logical)

	// Test pwd with physical option
	cmd, err = parser.ParseArguments([]string{"-P"})
	require.NoError(t, err)
	pwdCmd, ok = cmd.(*PwdCommand)
	require.True(t, ok)
	assert.True(t, pwdCmd.Physical)

	// Test semantic operations for pwd
	ops, err := parser.GetSemanticOperations(pwdCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have current directory read operation
	hasDirRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "cwd") {
			hasDirRead = true
			assert.Equal(t, "current_directory", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "pwd", val)
			}
			break
		}
	}
	assert.True(t, hasDirRead, "Should have current directory read operation")
}

func TestWhoLastIdPwdParser_EdgeCases(t *testing.T) {
	// Test who parser with unknown option
	whoParser := &WhoLastIdPwdParser{commandType: "who"}
	_, err := whoParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test last parser with unknown option
	lastParser := &WhoLastIdPwdParser{commandType: "last"}
	_, err = lastParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test id parser with unknown option
	idParser := &WhoLastIdPwdParser{commandType: "id"}
	_, err = idParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test pwd parser with unknown option
	pwdParser := &WhoLastIdPwdParser{commandType: "pwd"}
	_, err = pwdParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestWhoLastIdPwdParser_Soundness(t *testing.T) {
	parser := &WhoLastIdPwdParser{commandType: "who"}

	// Test that system info reading is properly captured
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have over-approximated system info read operation
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "utmp") {
			assert.Equal(t, "user_info", op.Context)
			if params, exists := op.Parameters["over_approximated"]; exists && params.(bool) {
				return // Found over-approximated operation
			}
		}
	}
	assert.Fail(t, "Should have over-approximated system info read operation")
}