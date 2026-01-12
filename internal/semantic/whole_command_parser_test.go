package semantic

import (
	"testing"
)

func TestWholeCommandParser(t *testing.T) {
	parser := NewWholeCommandParser()

	testCases := []struct {
		name        string
		commandLine string
		expectError bool
		checkFunc   func(t *testing.T, graph *OperationGraph)
	}{
		{
			name:        "simple cat command",
			commandLine: "cat file.txt",
			expectError: false,
			checkFunc: func(t *testing.T, graph *OperationGraph) {
				if graph.Command != "cat" {
					t.Errorf("Expected command 'cat', got '%s'", graph.Command)
				}
				if len(graph.Operations) != 1 {
					t.Errorf("Expected 1 operation, got %d", len(graph.Operations))
				}
				if graph.Operations[0].OperationType != OpRead {
					t.Errorf("Expected read operation, got %v", graph.Operations[0].OperationType)
				}
				if graph.Operations[0].TargetPath != "file.txt" {
					t.Errorf("Expected target 'file.txt', got '%s'", graph.Operations[0].TargetPath)
				}
				// Should have reasonable risk score for simple cat
				if graph.RiskScore > 60 {
					t.Errorf("Expected reasonable risk score for simple cat, got %d", graph.RiskScore)
				}
			},
		},
		{
			name:        "cat with redirection",
			commandLine: "cat file.txt > output.txt",
			expectError: false,
			checkFunc: func(t *testing.T, graph *OperationGraph) {
				if graph.Command != "cat" {
					t.Errorf("Expected command 'cat', got '%s'", graph.Command)
				}
				// Should have operations for both read and write
				if len(graph.Operations) != 2 {
					t.Errorf("Expected 2 operations (read + redirect), got %d", len(graph.Operations))
				}
				// Higher risk score due to redirection
				if graph.RiskScore < 40 {
					t.Errorf("Expected higher risk score for cat with redirection, got %d", graph.RiskScore)
				}
			},
		},
		{
			name:        "unknown command",
			commandLine: "unknown file.txt",
			expectError: false,
			checkFunc: func(t *testing.T, graph *OperationGraph) {
				if graph.Command != "unknown" {
					t.Errorf("Expected command 'unknown', got '%s'", graph.Command)
				}
				// Should have at least one operation (conservative)
				if len(graph.Operations) == 0 {
					t.Errorf("Expected at least one operation for unknown command")
				}
				// Should be marked as over-approximated
				if params, ok := graph.Operations[0].Parameters["over_approximated"]; !ok || params != true {
					t.Error("Expected operations to be marked as over-approximated")
				}
			},
		},
		{
			name:        "cat with multiple files",
			commandLine: "cat file1.txt file2.txt",
			expectError: false,
			checkFunc: func(t *testing.T, graph *OperationGraph) {
				if graph.Command != "cat" {
					t.Errorf("Expected command 'cat', got '%s'", graph.Command)
				}
				// Should have read operations for both files
				if len(graph.Operations) != 2 {
					t.Errorf("Expected 2 read operations, got %d", len(graph.Operations))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			graph, err := parser.ParseFullCommand(tc.commandLine)
			if tc.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseFullCommand failed: %v", err)
			}

			if tc.checkFunc != nil {
				tc.checkFunc(t, graph)
			}
		})
	}
}