package semantic

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPythonIntegration(t *testing.T) {
	parser := NewBashParser()

	testCases := []struct {
		name           string
		script         string
		expectedPython bool
	}{
		{
			name:           "no python",
			script:         "echo hello",
			expectedPython: false,
		},
		{
			name:           "python print",
			script:         "python -c \"print('hello')\"",
			expectedPython: true,
		},
		{
			name:           "python3 with import",
			script:         "python3 -c \"import os; print('hello')\"",
			expectedPython: true,
		},
		{
			name:           "python with chaining",
			script:         "cd /tmp && python3 script.py",
			expectedPython: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments([]string{"-c", tc.script})
			require.NoError(t, err)
			bashCmd, ok := cmd.(*BashCommand)
			require.True(t, ok)

			// Test Python command detection
			hasPython := parser.HasPythonCommands(tc.script)
			assert.Equal(t, tc.expectedPython, hasPython, "Python detection should match expected")

			// Test semantic operations for Python
			ops, err := parser.GetSemanticOperations(bashCmd)
			require.NoError(t, err)
			assert.NotEmpty(t, ops)

			if tc.expectedPython {
				// Look for Python-specific operations
				hasPythonOp := false
				for _, op := range ops {
					if op.OperationType == OpExecute {
						if desc, ok := op.Parameters["description"].(string); ok && strings.Contains(desc, "Python") {
							hasPythonOp = true
							break
						}
					}
				}
				assert.True(t, hasPythonOp, "Should have Python-specific operations when Python commands are detected")
			}
		})
	}
}