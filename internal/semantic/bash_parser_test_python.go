package semantic

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBashParserPythonCommands(t *testing.T) {
	parser := NewBashParser()

	testCases := []struct {
		script         string
		expectedPython bool
		expectedSafe   bool
	}{
		{"echo hello", false, true},
		{"python -c \"print('hello')\"", true, true},
		{"python3 -c \"import os; print('hello')\"", true, true},
		{"python -c \"__import__('os').system('rm -rf /')\"", true, false},
		{"cd /tmp && python3 script.py", true, true},
		{"python -c \"x = 5; print(x)\" && echo done", true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.script, func(t *testing.T) {
			cmd, err := parser.ParseArguments([]string{"-c", tc.script})
			require.NoError(t, err)
			bashCmd, ok := cmd.(*BashCommand)
			require.True(t, ok)

			// Test Python command detection
			hasPython := parser.hasPythonCommands(tc.script)
			assert.Equal(t, tc.expectedPython, hasPython, "Python detection should match expected")

			// Test semantic operations for Python safety
			if tc.expectedPython {
				ops, err := parser.GetSemanticOperations(bashCmd)
				require.NoError(t, err)
				assert.NotEmpty(t, ops)

				// Look for Python-specific operations
				hasPythonOp := false
				for _, op := range ops {
					if op.OperationType == OpExecute {
						if desc, ok := op.Parameters["description"].(string); ok && strings.Contains(desc, "Python") {
							hasPythonOp = true
							if safe, ok := op.Parameters["python_code_safe"].(bool); ok {
								assert.Equal(t, tc.expectedSafe, safe, "Python safety should match expected")
							}
							break
						}
					}
				}
				assert.True(t, hasPythonOp, "Should have Python-specific operations when Python commands are detected")
			}
		})
	}
}