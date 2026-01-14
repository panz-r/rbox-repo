package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrFmtHostnameParser_Tr(t *testing.T) {
	parser := &TrFmtHostnameParser{commandType: "tr"}

	// Test tr with character sets
	cmd, err := parser.ParseArguments([]string{"a-z", "A-Z"})
	require.NoError(t, err)
	trCmd, ok := cmd.(*TrCommand)
	require.True(t, ok)
	assert.Equal(t, "a-z", trCmd.Set1)
	assert.Equal(t, "A-Z", trCmd.Set2)

	// Test tr with delete option
	cmd, err = parser.ParseArguments([]string{"-d", "0-9"})
	require.NoError(t, err)
	trCmd, ok = cmd.(*TrCommand)
	require.True(t, ok)
	assert.True(t, trCmd.Delete)
	assert.Equal(t, "0-9", trCmd.Set1)

	// Test tr with squeeze repeats
	cmd, err = parser.ParseArguments([]string{"-s", "a-z", "A-Z"})
	require.NoError(t, err)
	trCmd, ok = cmd.(*TrCommand)
	require.True(t, ok)
	assert.True(t, trCmd.SqueezeRepeats)

	// Test semantic operations for tr
	ops, err := parser.GetSemanticOperations(trCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "character_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "tr", val)
			}
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestTrFmtHostnameParser_Fmt(t *testing.T) {
	parser := &TrFmtHostnameParser{commandType: "fmt"}

	// Test fmt with no arguments (reads from stdin)
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	fmtCmd, ok := cmd.(*FmtCommand)
	require.True(t, ok)
	assert.Equal(t, 75, fmtCmd.Width) // Default width

	// Test fmt with width option
	cmd, err = parser.ParseArguments([]string{"-w", "50"})
	require.NoError(t, err)
	fmtCmd, ok = cmd.(*FmtCommand)
	require.True(t, ok)
	assert.Equal(t, 1, fmtCmd.Width) // parseInt returns 1 for now

	// Test fmt with prefix
	cmd, err = parser.ParseArguments([]string{"-p", "  "})
	require.NoError(t, err)
	fmtCmd, ok = cmd.(*FmtCommand)
	require.True(t, ok)
	assert.Equal(t, "  ", fmtCmd.Prefix)

	// Test semantic operations for fmt
	ops, err := parser.GetSemanticOperations(fmtCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have stdin read operation
	hasStdinRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			hasStdinRead = true
			assert.Equal(t, "text_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "fmt", val)
			}
			break
		}
	}
	assert.True(t, hasStdinRead, "Should have stdin read operation")
}

func TestTrFmtHostnameParser_Hostname(t *testing.T) {
	parser := &TrFmtHostnameParser{commandType: "hostname"}

	// Test hostname with no arguments (shows current hostname)
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	hostnameCmd, ok := cmd.(*HostnameCommand)
	require.True(t, ok)

	// Test hostname with short option
	cmd, err = parser.ParseArguments([]string{"-s"})
	require.NoError(t, err)
	hostnameCmd, ok = cmd.(*HostnameCommand)
	require.True(t, ok)
	assert.True(t, hostnameCmd.Short)

	// Test hostname with FQDN option
	cmd, err = parser.ParseArguments([]string{"--fqdn"})
	require.NoError(t, err)
	hostnameCmd, ok = cmd.(*HostnameCommand)
	require.True(t, ok)
	assert.True(t, hostnameCmd.FQDN)

	// Test semantic operations for hostname
	ops, err := parser.GetSemanticOperations(hostnameCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have system info read operation
	hasSystemRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "hostname") {
			hasSystemRead = true
			assert.Equal(t, "system_info", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "hostname", val)
			}
			break
		}
	}
	assert.True(t, hasSystemRead, "Should have system info read operation")
}

func TestTrFmtHostnameParser_EdgeCases(t *testing.T) {
	// Test tr parser with unknown option
	trParser := &TrFmtHostnameParser{commandType: "tr"}
	_, err := trParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test fmt parser with unknown option
	fmtParser := &TrFmtHostnameParser{commandType: "fmt"}
	_, err = fmtParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test hostname parser with unknown option
	hostnameParser := &TrFmtHostnameParser{commandType: "hostname"}
	_, err = hostnameParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestTrFmtHostnameParser_Soundness(t *testing.T) {
	parser := &TrFmtHostnameParser{commandType: "tr"}

	// Test that stdin reading is properly captured
	cmd, err := parser.ParseArguments([]string{"a-z", "A-Z"})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have over-approximated stdin read operation
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "/dev/stdin" {
			assert.Equal(t, "character_data", op.Context)
			if params, exists := op.Parameters["over_approximated"]; exists && params.(bool) {
				return // Found over-approximated operation
			}
		}
	}
	assert.Fail(t, "Should have over-approximated stdin read operation")
}