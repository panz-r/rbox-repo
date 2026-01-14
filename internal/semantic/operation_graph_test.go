package semantic

import (
	"testing"
)

func TestOperationGraphGeneration(t *testing.T) {
	// Test CatParser operation graph generation
	catParser := &CatParser{}

	// Parse cat command
	parsed, err := catParser.ParseArguments([]string{"file1.txt", "file2.txt"})
	if err != nil {
		t.Fatalf("CatParser.ParseArguments failed: %v", err)
	}

	// Get operation graph
	graph, err := catParser.GetOperationGraph(parsed)
	if err != nil {
		t.Fatalf("CatParser.GetOperationGraph failed: %v", err)
	}

	// Verify graph structure
	if graph == nil {
		t.Fatal("Expected non-nil operation graph")
	}

	if graph.Command != "cat" {
		t.Errorf("Expected command 'cat', got '%s'", graph.Command)
	}

	if len(graph.Operations) != 2 {
		t.Errorf("Expected 2 operations, got %d", len(graph.Operations))
	}

	if graph.RiskScore <= 0 {
		t.Errorf("Expected positive risk score, got %d", graph.RiskScore)
	}

	// Verify operations are read operations
	for _, op := range graph.Operations {
		if op.OperationType != OpRead {
			t.Errorf("Expected read operation, got %v", op.OperationType)
		}
	}
}

func TestFindParserOperationGraph(t *testing.T) {
	// Test FindParser operation graph generation
	findParser := &FindParser{}

	// Parse find command
	parsed, err := findParser.ParseArguments([]string{".", "-name", "*.txt"})
	if err != nil {
		t.Fatalf("FindParser.ParseArguments failed: %v", err)
	}

	// Get operation graph
	graph, err := findParser.GetOperationGraph(parsed)
	if err != nil {
		t.Fatalf("FindParser.GetOperationGraph failed: %v", err)
	}

	// Verify graph structure
	if graph == nil {
		t.Fatal("Expected non-nil operation graph")
	}

	if graph.Command != "find" {
		t.Errorf("Expected command 'find', got '%s'", graph.Command)
	}

	if len(graph.Operations) != 1 {
		t.Errorf("Expected 1 operation, got %d", len(graph.Operations))
	}

	if graph.RiskScore <= 0 {
		t.Errorf("Expected positive risk score, got %d", graph.RiskScore)
	}
}

func TestGenericParserOperationGraph(t *testing.T) {
	// Test GenericParser operation graph generation
	genericParser := &GenericParser{}

	// Parse unknown command
	parsed, err := genericParser.ParseArguments([]string{"unknown_cmd", "file.txt"})
	if err != nil {
		t.Fatalf("GenericParser.ParseArguments failed: %v", err)
	}

	// Get operation graph
	graph, err := genericParser.GetOperationGraph(parsed)
	if err != nil {
		t.Fatalf("GenericParser.GetOperationGraph failed: %v", err)
	}

	// Verify graph structure
	if graph == nil {
		t.Fatal("Expected non-nil operation graph")
	}

	if graph.Command != "unknown_cmd" {
		t.Errorf("Expected command 'unknown_cmd', got '%s'", graph.Command)
	}

	if len(graph.Operations) != 1 {
		t.Errorf("Expected 1 operation, got %d", len(graph.Operations))
	}

	if graph.RiskScore <= 0 {
		t.Errorf("Expected positive risk score, got %d", graph.RiskScore)
	}

	// Verify operation is marked as over-approximated
	if len(graph.Operations) > 0 {
		if val, exists := graph.Operations[0].Parameters["over_approximated"]; !exists || val != true {
			t.Errorf("Expected operation to be marked as over-approximated")
		}
	}
}