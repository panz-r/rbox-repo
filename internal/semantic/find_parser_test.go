package semantic

import (
	"testing"
)

func TestFindParser(t *testing.T) {
	parser := &FindParser{}

	testCases := []struct {
		name     string
		args     []string
		expected []SemanticOperation
		error    bool
	}{
		{
			name: "simple find with path",
			args: []string{"."},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".",
					Context:       "start_path",
					Parameters: map[string]interface{}{
						"command": "find",
					},
				},
			},
		},
		{
			name: "find with -name expression",
			args: []string{".", "-name", "*.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".",
					Context:       "start_path",
					Parameters: map[string]interface{}{
						"command": "find",
					},
				},
			},
		},
		{
			name: "find with -exec action (dangerous)",
			args: []string{".", "-name", "*.txt", "-exec", "rm", "{}", ";"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".",
					Context:       "start_path",
					Parameters: map[string]interface{}{
						"command": "find",
					},
				},
				{
					OperationType: OpExecute,
					TargetPath:    "rm",
					Context:       "exec_action",
					Parameters: map[string]interface{}{
						"command":   "find",
						"dangerous": true,
					},
				},
			},
		},
		{
			name: "find with -delete action (dangerous)",
			args: []string{".", "-name", "*.tmp", "-delete"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".",
					Context:       "start_path",
					Parameters: map[string]interface{}{
						"command": "find",
					},
				},
				{
					OperationType: OpExecute,
					TargetPath:    "*",
					Context:       "delete_action",
					Parameters: map[string]interface{}{
						"command":   "find",
						"dangerous": true,
					},
				},
			},
		},
		{
			name: "find with -maxdepth option",
			args: []string{".", "-maxdepth", "2", "-name", "*.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".",
					Context:       "start_path",
					Parameters: map[string]interface{}{
						"command": "find",
						"maxdepth": 2,
					},
				},
			},
		},
		{
			name: "find with multiple paths",
			args: []string{".", "/tmp", "-name", "*.log"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".",
					Context:       "start_path",
					Parameters: map[string]interface{}{
						"command": "find",
					},
				},
				{
					OperationType: OpRead,
					TargetPath:    "/tmp",
					Context:       "start_path",
					Parameters: map[string]interface{}{
						"command": "find",
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
			}
		})
	}
}