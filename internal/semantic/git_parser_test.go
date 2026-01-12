package semantic

import (
	"testing"
)

func TestGitParser(t *testing.T) {
	parser := &GitParser{}

	testCases := []struct {
		name     string
		args     []string
		expected []SemanticOperation
		error    bool
	}{
		{
			name: "git log (read-only)",
			args: []string{"log"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".git",
					Context:       "git_read",
					Parameters: map[string]interface{}{
						"command":    "git",
						"subcommand": "log",
						"read_only":  true,
						"safe":       true,
					},
				},
				{
					OperationType: OpRead,
					TargetPath:    "*",
					Context:       "git_content_read",
					Parameters: map[string]interface{}{
						"command":    "git",
						"subcommand": "log",
					},
				},
			},
		},
		{
			name: "git status (read-only)",
			args: []string{"status"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".git",
					Context:       "git_read",
					Parameters: map[string]interface{}{
						"command":    "git",
						"subcommand": "status",
						"read_only":  true,
						"safe":       true,
					},
				},
			},
		},
		{
			name: "git add (writes to repo)",
			args: []string{"add", "file.txt"},
			expected: []SemanticOperation{
				{
					OperationType: OpWrite,
					TargetPath:    ".git",
					Context:       "git_write",
					Parameters: map[string]interface{}{
						"command":      "git",
						"subcommand":   "add",
						"read_only":    false,
						"affects_repo": true,
					},
				},
				{
					OperationType: OpRead,
					TargetPath:    "file.txt",
					Context:       "git_add",
					Parameters: map[string]interface{}{
						"command": "git",
						"staging": true,
					},
				},
			},
		},
		{
			name: "git commit (creates commit)",
			args: []string{"commit", "-m", "test"},
			expected: []SemanticOperation{
				{
					OperationType: OpWrite,
					TargetPath:    ".git",
					Context:       "git_write",
					Parameters: map[string]interface{}{
						"command":      "git",
						"subcommand":   "commit",
						"read_only":    false,
						"affects_repo": true,
					},
				},
				{
					OperationType: OpCreate,
					TargetPath:    ".git/objects",
					Context:       "git_commit",
					Parameters: map[string]interface{}{
						"command":    "git",
						"dangerous":  false,
					},
				},
			},
		},
		{
			name: "git push (affects remote)",
			args: []string{"push", "origin", "main"},
			expected: []SemanticOperation{
				{
					OperationType: OpWrite,
					TargetPath:    ".git",
					Context:       "git_write",
					Parameters: map[string]interface{}{
						"command":         "git",
						"subcommand":      "push",
						"read_only":       false,
						"affects_repo":    true,
						"affects_remote": true,
					},
				},
				{
					OperationType: OpExecute,
					TargetPath:    "network",
					Context:       "git_network",
					Parameters: map[string]interface{}{
						"command":    "git",
						"subcommand": "push",
						"network":    true,
						"dangerous":  true,
					},
				},
				{
					OperationType: OpExecute,
					TargetPath:    "remote",
					Context:       "git_push",
					Parameters: map[string]interface{}{
						"command":    "git",
						"dangerous":  true,
						"remote":     true,
					},
				},
			},
		},
		{
			name: "git pull (reads from remote)",
			args: []string{"pull", "origin", "main"},
			expected: []SemanticOperation{
				{
					OperationType: OpWrite,
					TargetPath:    ".git",
					Context:       "git_write",
					Parameters: map[string]interface{}{
						"command":         "git",
						"subcommand":      "pull",
						"read_only":       false,
						"affects_repo":    true,
						"affects_remote": true,
					},
				},
				{
					OperationType: OpExecute,
					TargetPath:    "network",
					Context:       "git_network",
					Parameters: map[string]interface{}{
						"command":    "git",
						"subcommand": "pull",
						"network":    true,
						"dangerous":  true,
					},
				},
				{
					OperationType: OpRead,
					TargetPath:    "remote",
					Context:       "git_fetch",
					Parameters: map[string]interface{}{
						"command": "git",
						"remote":   true,
					},
				},
			},
		},
		{
			name: "git checkout (can be dangerous)",
			args: []string{"checkout", "main"},
			expected: []SemanticOperation{
				{
					OperationType: OpWrite,
					TargetPath:    ".git",
					Context:       "git_write",
					Parameters: map[string]interface{}{
						"command":      "git",
						"subcommand":   "checkout",
						"read_only":    false,
						"affects_repo": true,
					},
				},
				{
					OperationType: OpEdit,
					TargetPath:    "*",
					Context:       "git_checkout",
					Parameters: map[string]interface{}{
						"command":   "git",
						"dangerous": true,
					},
				},
			},
		},
		{
			name: "git diff (read-only)",
			args: []string{"diff"},
			expected: []SemanticOperation{
				{
					OperationType: OpRead,
					TargetPath:    ".git",
					Context:       "git_read",
					Parameters: map[string]interface{}{
						"command":    "git",
						"subcommand": "diff",
						"read_only":  true,
						"safe":       true,
					},
				},
				{
					OperationType: OpRead,
					TargetPath:    "*",
					Context:       "git_content_read",
					Parameters: map[string]interface{}{
						"command":    "git",
						"subcommand": "diff",
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