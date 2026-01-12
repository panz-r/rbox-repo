package semantic

import (
	"testing"
)

func TestParserRegistry(t *testing.T) {
	registry := NewParserRegistry()

	// Test empty registry
	if len(registry.ListParsers()) != 0 {
		t.Error("Expected empty registry initially")
	}

	// Test registering a parser
	catParser := &CatParser{}
	registry.RegisterParser("cat", catParser)

	// Test retrieving the parser
	retrievedParser := registry.GetParser("cat")
	if retrievedParser != catParser {
		t.Error("Expected to retrieve the same cat parser instance")
	}

	// Test listing parsers
	parsers := registry.ListParsers()
	if len(parsers) != 1 || parsers[0] != "cat" {
		t.Error("Expected to list cat parser")
	}

	// Test unknown command returns generic parser
	unknownParser := registry.GetParser("unknown")
	if _, ok := unknownParser.(*GenericParser); !ok {
		t.Error("Expected generic parser for unknown command")
	}
}

func TestGenericParser(t *testing.T) {
	parser := &GenericParser{}

	testCases := []struct {
		name     string
		args     []string
		wantOps  int
		error    bool
	}{
		{
			name:    "simple command with file argument",
			args:    []string{"unknown", "file.txt"},
			wantOps: 1,
		},
		{
			name:    "command with multiple arguments",
			args:    []string{"unknown", "file1.txt", "file2.txt"},
			wantOps: 2,
		},
		{
			name:    "command with options and files",
			args:    []string{"unknown", "-v", "-f", "file.txt"},
			wantOps: 1, // Only file.txt should be processed
		},
		{
			name:    "command with no valid arguments",
			args:    []string{"unknown", "-v", "-f"},
			wantOps: 1, // Should create conservative operation
		},
		{
			name:    "empty arguments",
			args:    []string{},
			error:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parser.ParseArguments(tc.args)
			if tc.error {
				if err == nil {
					t.Error("Expected error for empty arguments")
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

			if len(operations) != tc.wantOps {
				t.Errorf("Expected %d operations, got %d", tc.wantOps, len(operations))
			}

			// Check that operations are marked as over-approximated
			for _, op := range operations {
				if params, ok := op.Parameters["over_approximated"]; !ok || params != true {
					t.Error("Expected operations to be marked as over-approximated")
				}
			}
		})
	}
}