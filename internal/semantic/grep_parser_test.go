package semantic

import (
	"testing"
)

func TestGrepParser(t *testing.T) {
	parser := &GrepParser{}

	testCases := []struct {
		name     string
		args     []string
		expected []SemanticOperation
		error    bool
	}{
		{
			name: "simple grep with pattern and file",
			args: []string{"pattern", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "grep",
						"pattern": "pattern",
					},
				},
			},
		},
		{
			name: "grep with -i option",
			args: []string{"-i", "pattern", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command":           "grep",
						"pattern":           "pattern",
						"case_insensitive": true,
					},
				},
			},
		},
		{
			name: "grep with -v option",
			args: []string{"-v", "pattern", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command":        "grep",
						"pattern":        "pattern",
						"invert_match":   true,
					},
				},
			},
		},
		{
			name: "grep with -e option",
			args: []string{"-e", "pattern", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "grep",
						"pattern": "pattern",
					},
				},
			},
		},
		{
			name: "grep with multiple files",
			args: []string{"pattern", "file1.txt", "file2.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file1.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "grep",
						"pattern": "pattern",
					},
				},
				{
					OperationType: OpRead,
					TargetPath:    "file2.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "grep",
						"pattern": "pattern",
					},
				},
			},
		},
		{
			name: "grep with stdin (no files)",
			args: []string{"pattern"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "/dev/stdin",
					Context:       "stdin",
					Parameters: map[string]interface{}{
						"command": "grep",
						"pattern": "pattern",
					},
				},
			},
		},
		{
			name: "grep with -f option (pattern file)",
			args: []string{"-f", "patterns.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "patterns.txt",
					Context:       "pattern_file",
					Parameters: map[string]interface{}{
						"command": "grep",
					},
				},
				{
					OperationType: OpRead,
					TargetPath:    "/dev/stdin",
					Context:       "stdin",
					Parameters: map[string]interface{}{
						"command": "grep",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parser.ParseArguments(tc.args)
			if tc.error {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseArguments failed: %v", err)
			}

			operations, err := parser.GetSemanticOperations(parsed)
			if err != nil {
				t.Fatalf("GetSemanticOperations failed: %v", err)
			}

			if len(operations) != len(tc.expected) {
				t.Errorf("Expected %d operations, got %d", len(tc.expected), len(operations))
			}

			for i, op := range operations {
				if op.OperationType != tc.expected[i].OperationType {
					t.Errorf("Operation %d: expected type %v, got %v", i, tc.expected[i].OperationType, op.OperationType)
				}
				if op.TargetPath != tc.expected[i].TargetPath {
					t.Errorf("Operation %d: expected path %q, got %q", i, tc.expected[i].TargetPath, op.TargetPath)
				}
				if op.Context != tc.expected[i].Context {
					t.Errorf("Operation %d: expected context %q, got %q", i, tc.expected[i].Context, op.Context)
				}

				// Check parameters
				expectedParams := tc.expected[i].Parameters
				for key, expectedValue := range expectedParams {
					if actualValue, ok := op.Parameters[key]; !ok {
						t.Errorf("Operation %d: missing parameter %q", i, key)
					} else if actualValue != expectedValue {
						t.Errorf("Operation %d: parameter %q: expected %v, got %v", i, key, expectedValue, actualValue)
					}
				}
			}
		})
	}
}