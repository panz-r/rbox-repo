package semantic

import (
	"testing"
)

func TestSortParser(t *testing.T) {
	parser := &SortParser{}

	testCases := []struct {
		name     string
		args     []string
		expected []SemanticOperation
		error    bool
	}{
		{
			name: "simple sort with file",
			args: []string{"file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "sort",
					},
				},
			},
		},
		{
			name: "sort with -r option",
			args: []string{"-r", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "sort",
						"reverse": true,
					},
				},
			},
		},
		{
			name: "sort with -n option",
			args: []string{"-n", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "sort",
						"numeric": true,
					},
				},
			},
		},
		{
			name: "sort with -o option (output file)",
			args: []string{"-o", "output.txt", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "sort",
					},
				},
				{
					OperationType: OpWrite,
					TargetPath:    "output.txt",
					Context:       "output_file",
					Parameters: map[string]interface{}{
						"command": "sort",
					},
				},
			},
		},
		{
			name: "sort with stdin (no files)",
			args: []string{},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "/dev/stdin",
					Context:       "stdin",
					Parameters: map[string]interface{}{
						"command": "sort",
					},
				},
			},
		},
		{
			name: "sort with multiple files",
			args: []string{"file1.txt", "file2.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file1.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "sort",
					},
				},
				{
					OperationType: OpRead,
					TargetPath:    "file2.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "sort",
					},
				},
			},
		},
		{
			name: "sort with combined options -rn",
			args: []string{"-rn", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
					Parameters: map[string]interface{}{
						"command": "sort",
						"reverse": true,
						"numeric": true,
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