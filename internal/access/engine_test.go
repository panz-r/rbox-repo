package access

import (
	"testing"

	"github.com/panz/openroutertest/internal/dsl"
)

func TestAccessControlEngine(t *testing.T) {
	// Create a test configuration
	config := dsl.AST{
		BaseDir: "/home/user/project",
		Rules: []dsl.AccessRule{
			{
				Command: "ls",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  "/home/user/project",
						Level: dsl.AccessAt,
					},
					{
						Path:  "/home/user/project/src",
						Level: dsl.AccessSub,
						Depth: 2,
					},
				},
			},
			{
				Command: "cat",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  "/home/user/project",
						Level: dsl.AccessAt,
					},
					{
						Path:  "/home/user/project",
						Level: dsl.AccessSuper,
						Depth: 1,
					},
				},
			},
		},
	}

	engine := NewAccessControlEngine(config)

	tests := []struct {
		cmd      string
		path     string
		opType   dsl.OperationType
		expected bool
	}{
		// ls tests
		{"ls", "/home/user/project/file.txt", dsl.OpRead, true},
		{"ls", "/home/user/project/src/subdir/file.txt", dsl.OpRead, true},
		{"ls", "/home/user/project/src/subdir/subdir2/file.txt", dsl.OpRead, true},
		{"ls", "/home/user/project/src/subdir/subdir2/subdir3/file.txt", dsl.OpRead, false}, // Too deep
		{"ls", "/home/user/other/file.txt", dsl.OpRead, false}, // Outside allowed paths

		// cat tests
		{"cat", "/home/user/project/file.txt", dsl.OpRead, true},
		{"cat", "/home/user/file.txt", dsl.OpRead, true}, // Parent directory
		{"cat", "/home/file.txt", dsl.OpRead, false},   // Too far up

		// Non-existent command
		{"rm", "/home/user/project/file.txt", dsl.OpRead, false},
	}

	for _, tt := range tests {
		canAccess, err := engine.CanAccess(tt.cmd, tt.path, tt.opType)
		if err != nil && tt.expected {
			t.Errorf("CanAccess(%s, %s, %s): unexpected error: %v", tt.cmd, tt.path, tt.opType, err)
			continue
		}

		if canAccess != tt.expected {
			t.Errorf("CanAccess(%s, %s, %s): expected %v, got %v", tt.cmd, tt.path, tt.opType, tt.expected, canAccess)
		}
	}
}

func TestTempFileManagement(t *testing.T) {
	config := dsl.AST{
		BaseDir: "/home/user/project",
		Rules: []dsl.AccessRule{
			{
				Command: "sort",
				Operations: []dsl.FileOperation{
					{
						OpType:   dsl.OpRedirect,
						Path:     "/tmp/readonlybox_*.txt",
						IsTemp:   true,
					},
					{
						OpType:      dsl.OpOverwrite,
						Path:        "/tmp/readonlybox_*.txt",
						IsTemp:      true,
						CreatedByUs: true,
					},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  "/home/user/project",
						Level: dsl.AccessAt,
					},
				},
			},
		},
	}

	engine := NewAccessControlEngine(config)

	// Test redirect to new temp file
	tempFile := "/tmp/readonlybox_result.txt"
	canAccess, err := engine.CanAccess("sort", tempFile, dsl.OpRedirect)
	if err != nil {
		t.Fatalf("CanAccess failed: %v", err)
	}
	if !canAccess {
		t.Error("Expected to be able to redirect to temp file")
	}

	// Register the temp file
	engine.RegisterTempFile(tempFile, 1024)

	// Test overwrite of our own temp file
	canAccess, err = engine.CanAccess("sort", tempFile, dsl.OpOverwrite)
	if err != nil {
		t.Fatalf("CanAccess failed: %v", err)
	}
	if !canAccess {
		t.Error("Expected to be able to overwrite our own temp file")
	}

	// Test overwrite of someone else's temp file
	otherTempFile := "/tmp/readonlybox_other.txt"
	canAccess, err = engine.CanAccess("sort", otherTempFile, dsl.OpOverwrite)
	if err != nil {
		t.Fatalf("CanAccess failed: %v", err)
	}
	if canAccess {
		t.Error("Should not be able to overwrite other temp files")
	}
}

func TestGetAllowedCommands(t *testing.T) {
	config := dsl.AST{
		Rules: []dsl.AccessRule{
			{Command: "ls"},
			{Command: "cat"},
			{Command: "grep"},
			{Command: "*"}, // wildcard
		},
	}

	engine := NewAccessControlEngine(config)
	commands := engine.GetAllowedCommands()

	if len(commands) != 3 {
		t.Fatalf("Expected 3 commands, got %d", len(commands))
	}

	expectedCommands := map[string]bool{
		"ls":   false,
		"cat":  false,
		"grep": false,
	}

	for _, cmd := range commands {
		if _, exists := expectedCommands[cmd]; !exists {
			t.Errorf("Unexpected command: %s", cmd)
		} else {
			expectedCommands[cmd] = true
		}
	}

	for cmd, found := range expectedCommands {
		if !found {
			t.Errorf("Expected command not found: %s", cmd)
		}
	}
}