package semantic

import (
	"testing"
)

func TestCatParser(t *testing.T) {
	parser := &CatParser{}

	testCases := []struct {
		name     string
		args     []string
		expected []SemanticOperation
		error    bool
	}{
		{
			name: "simple cat",
			args: []string{"file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
				},
			},
		},
		{
			name: "cat with multiple files",
			args: []string{"file1.txt", "file2.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file1.txt",
					Context:       "input_file",
				},
				{
					OperationType: OpRead,
					TargetPath:    "file2.txt",
					Context:       "input_file",
				},
			},
		},
		{
			name: "cat with no arguments (stdin)",
			args: []string{},
			error: true, // CatParser requires at least one argument
		},
		{
			name: "cat with options",
			args: []string{"-n", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "input_file",
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