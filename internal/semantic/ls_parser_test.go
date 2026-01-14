package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLsParser_ParseArguments(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectCmd   *LsCommand
	}{
		{
			name:        "basic ls",
			args:        []string{"ls"},
			expectError: false,
			expectCmd: &LsCommand{
				Directories: []string{"."},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "ls with directory",
			args:        []string{"ls", "/tmp"},
			expectError: false,
			expectCmd: &LsCommand{
				Directories: []string{"/tmp"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "ls with -l option",
			args:        []string{"ls", "-l"},
			expectError: false,
			expectCmd: &LsCommand{
				Directories: []string{"."},
				Options:     map[string]interface{}{"long_format": true},
				LongFormat:  true,
			},
		},
		{
			name:        "ls with -a option",
			args:        []string{"ls", "-a"},
			expectError: false,
			expectCmd: &LsCommand{
				Directories: []string{"."},
				Options:     map[string]interface{}{"all": true},
				ShowAll:     true,
				ShowHidden: true,
			},
		},
		{
			name:        "ls with -R option",
			args:        []string{"ls", "-R"},
			expectError: false,
			expectCmd: &LsCommand{
				Directories: []string{"."},
				Options:     map[string]interface{}{"recursive": true},
				Recursive:   true,
			},
		},
		{
			name:        "ls with combined options",
			args:        []string{"ls", "-lh"},
			expectError: false,
			expectCmd: &LsCommand{
				Directories: []string{"."},
				Options:     map[string]interface{}{"long_format": true, "human_readable": true},
				LongFormat:  true,
				HumanReadable: true,
			},
		},
		{
			name:        "ls with multiple directories",
			args:        []string{"ls", "/tmp", "/var"},
			expectError: false,
			expectCmd: &LsCommand{
				Directories: []string{"/tmp", "/var"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "ls with long options",
			args:        []string{"ls", "--all", "--human-readable"},
			expectError: false,
			expectCmd: &LsCommand{
				Directories: []string{"."},
				Options:     map[string]interface{}{"all": true, "human_readable": true},
				ShowAll:     true,
				ShowHidden: true,
				HumanReadable: true,
			},
		},
	}

	parser := &LsParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments(tt.args)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			lsCmd, ok := cmd.(*LsCommand)
			require.True(t, ok)

			assert.Equal(t, tt.expectCmd.Directories, lsCmd.Directories)
			assert.Equal(t, tt.expectCmd.LongFormat, lsCmd.LongFormat)
			assert.Equal(t, tt.expectCmd.ShowAll, lsCmd.ShowAll)
			assert.Equal(t, tt.expectCmd.Recursive, lsCmd.Recursive)
			assert.Equal(t, tt.expectCmd.HumanReadable, lsCmd.HumanReadable)

			// Check options map contains expected keys
			for k, v := range tt.expectCmd.Options {
				assert.Equal(t, v, lsCmd.Options[k])
			}
		})
	}
}

func TestLsParser_GetSemanticOperations(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *LsCommand
		expectError    bool
		expectMinOps   int
		expectPrecise  bool
		expectOverApprox bool
	}{
		{
			name:           "basic ls",
			cmd:            &LsCommand{Directories: []string{"."}},
			expectError:    false,
			expectMinOps:   1,
			expectPrecise:  true,
			expectOverApprox: false,
		},
		{
			name:           "ls with recursive",
			cmd:            &LsCommand{Directories: []string{"/tmp"}, Recursive: true},
			expectError:    false,
			expectMinOps:   2,
			expectPrecise:  true,
			expectOverApprox: true,
		},
		{
			name:           "ls with long format",
			cmd:            &LsCommand{Directories: []string{"/var"}, LongFormat: true},
			expectError:    false,
			expectMinOps:   2,
			expectPrecise:  true,
			expectOverApprox: false,
		},
		{
			name:           "ls with multiple directories",
			cmd:            &LsCommand{Directories: []string{"/tmp", "/var"}},
			expectError:    false,
			expectMinOps:   2,
			expectPrecise:  true,
			expectOverApprox: false,
		},
		{
			name:           "ls with recursive and long format",
			cmd:            &LsCommand{Directories: []string{"."}, Recursive: true, LongFormat: true},
			expectError:    false,
			expectMinOps:   3,
			expectPrecise:  true,
			expectOverApprox: true,
		},
	}

	parser := &LsParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, err := parser.GetSemanticOperations(tt.cmd)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(ops), tt.expectMinOps)

			hasPrecise := false
			hasOverApprox := false

			for _, op := range ops {
				if op.Parameters != nil {
					if precise, ok := op.Parameters["precise"].(bool); ok && precise {
						hasPrecise = true
					}
					if overApprox, ok := op.Parameters["over_approximated"].(bool); ok && overApprox {
						hasOverApprox = true
					}
				}
			}

			if tt.expectPrecise {
				assert.True(t, hasPrecise, "Expected at least one precise operation")
			}
			if tt.expectOverApprox {
				assert.True(t, hasOverApprox, "Expected at least one over-approximated operation")
			}

			// Verify operation types are correct
			for _, op := range ops {
				assert.Equal(t, OpRead, op.OperationType, "ls should only generate read operations")
			}
		})
	}
}

func TestLsParser_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		description string
	}{
		{
			name:        "empty args",
			args:        []string{},
			expectError: true,
			description: "Should fail with no command",
		},
		{
			name:        "ls with unknown option",
			args:        []string{"ls", "--unknown-option"},
			expectError: false,
			description: "Should handle unknown options gracefully",
		},
		{
			name:        "ls with complex combined options",
			args:        []string{"ls", "-lhRta"},
			expectError: false,
			description: "Should parse complex combined options",
		},
		{
			name:        "ls with directory containing spaces",
			args:        []string{"ls", "/tmp/dir with spaces"},
			expectError: false,
			description: "Should handle directories with spaces",
		},
	}

	parser := &LsParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments(tt.args)
			if tt.expectError {
				require.Error(t, err, tt.description)
				return
			}

			require.NoError(t, err, tt.description)
			assert.NotNil(t, cmd, "Command should not be nil")

			// Should be able to get semantic operations for any valid parse
			ops, err := parser.GetSemanticOperations(cmd)
			assert.NoError(t, err, "Should be able to get semantic operations")
			assert.NotEmpty(t, ops, "Should generate at least one operation")
		})
	}
}

func TestLsParser_Soundness(t *testing.T) {
	// Test that the parser maintains soundness guarantees
	// Soundness means: never under-approximate (never miss operations)
	// It's okay to over-approximate (be conservative)

	tests := []struct {
		name          string
		args          []string
		expectReadOps []string // paths we definitely expect to see read operations for
	}{
		{
			name:          "basic ls should read current directory",
			args:          []string{"ls"},
			expectReadOps: []string{"."},
		},
		{
			name:          "ls /tmp should read /tmp",
			args:          []string{"ls", "/tmp"},
			expectReadOps: []string{"/tmp"},
		},
		{
			name:          "ls -R should read directory and subdirectories",
			args:          []string{"ls", "-R", "/tmp"},
			expectReadOps: []string{"/tmp"}, // Should at least read /tmp
		},
	}

	parser := &LsParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments(tt.args)
			require.NoError(t, err)

			ops, err := parser.GetSemanticOperations(cmd)
			require.NoError(t, err)

			// Check that we have read operations for expected paths
			foundPaths := make(map[string]bool)
			for _, op := range ops {
				if op.OperationType == OpRead {
					foundPaths[op.TargetPath] = true
				}
			}

			// Verify all expected paths are covered
			for _, expectedPath := range tt.expectReadOps {
				// Check if exact path exists or if there's a pattern that would cover it
				hasExact := foundPaths[expectedPath]
				hasPattern := false
				for path := range foundPaths {
					if path == expectedPath+"/*" || path == expectedPath+"/.*" {
						hasPattern = true
						break
					}
				}

				assert.True(t, hasExact || hasPattern,
					"Expected read operation for path %s, got paths: %v", expectedPath, foundPaths)
			}
		})
	}
}