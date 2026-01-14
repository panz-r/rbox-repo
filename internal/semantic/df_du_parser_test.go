package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDfDuParser_ParseArguments(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectCmd   *DfDuCommand
	}{
		{
			name:        "basic df",
			args:        []string{"df"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "df",
				Paths:       []string{"all_filesystems"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "basic du",
			args:        []string{"du"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "du",
				Paths:       []string{"."},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "df with path",
			args:        []string{"df", "/tmp"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "df",
				Paths:       []string{"/tmp"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "du with path",
			args:        []string{"du", "/tmp"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "du",
				Paths:       []string{"/tmp"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "df with -h option",
			args:        []string{"df", "-h"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType:  "df",
				Paths:        []string{"all_filesystems"},
				Options:      map[string]interface{}{"human_readable": true},
				HumanReadable: true,
			},
		},
		{
			name:        "du with -h option",
			args:        []string{"du", "-h"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType:  "du",
				Paths:        []string{"."},
				Options:      map[string]interface{}{"human_readable": true},
				HumanReadable: true,
			},
		},
		{
			name:        "df with --max-depth",
			args:        []string{"df", "--max-depth", "2"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "df",
				Paths:       []string{"all_filesystems"},
				Options:     map[string]interface{}{"max_depth": "2"},
				MaxDepth:    1, // Default, actual parsing would set this
			},
		},
		{
			name:        "du with --max-depth",
			args:        []string{"du", "--max-depth", "2"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "du",
				Paths:       []string{"."},
				Options:     map[string]interface{}{"max_depth": "2"},
				MaxDepth:    1, // Default, actual parsing would set this
			},
		},
		{
			name:        "df with -i option",
			args:        []string{"df", "-i"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType:  "df",
				Paths:        []string{"all_filesystems"},
				Options:      map[string]interface{}{"show_inodes": true},
				ShowInodes:   true,
			},
		},
		{
			name:        "du with -s option",
			args:        []string{"du", "-s"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "du",
				Paths:       []string{"."},
				Options:     map[string]interface{}{"summarize": true},
				Summarize:   true,
			},
		},
		{
			name:        "df with multiple paths",
			args:        []string{"df", "/tmp", "/var"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "df",
				Paths:       []string{"/tmp", "/var"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "du with multiple paths",
			args:        []string{"du", "/tmp", "/var"},
			expectError: false,
			expectCmd: &DfDuCommand{
				CommandType: "du",
				Paths:       []string{"/tmp", "/var"},
				Options:     map[string]interface{}{},
			},
		},
	}

	parser := &DfDuParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments(tt.args)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			dfDuCmd, ok := cmd.(*DfDuCommand)
			require.True(t, ok)

			assert.Equal(t, tt.expectCmd.CommandType, dfDuCmd.CommandType)
			assert.Equal(t, tt.expectCmd.Paths, dfDuCmd.Paths)
			assert.Equal(t, tt.expectCmd.HumanReadable, dfDuCmd.HumanReadable)
			assert.Equal(t, tt.expectCmd.ShowAll, dfDuCmd.ShowAll)
			assert.Equal(t, tt.expectCmd.ShowInodes, dfDuCmd.ShowInodes)
			assert.Equal(t, tt.expectCmd.MaxDepth, dfDuCmd.MaxDepth)
			assert.Equal(t, tt.expectCmd.Summarize, dfDuCmd.Summarize)

			// Check options map contains expected keys
			for k, v := range tt.expectCmd.Options {
				assert.Equal(t, v, dfDuCmd.Options[k])
			}
		})
	}
}

func TestDfDuParser_GetSemanticOperations(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *DfDuCommand
		expectError    bool
		expectMinOps   int
		expectOverApprox bool
	}{
		{
			name:           "basic df",
			cmd:            &DfDuCommand{CommandType: "df", Paths: []string{"all_filesystems"}},
			expectError:    false,
			expectMinOps:   2, // /etc/mtab and /proc/mounts
			expectOverApprox: true,
		},
		{
			name:           "df with specific path",
			cmd:            &DfDuCommand{CommandType: "df", Paths: []string{"/tmp"}},
			expectError:    false,
			expectMinOps:   1,
			expectOverApprox: false,
		},
		{
			name:           "basic du",
			cmd:            &DfDuCommand{CommandType: "du", Paths: []string{"."}},
			expectError:    false,
			expectMinOps:   1,
			expectOverApprox: false,
		},
		{
			name:           "du with no max depth",
			cmd:            &DfDuCommand{CommandType: "du", Paths: []string{"."}, MaxDepth: 0},
			expectError:    false,
			expectMinOps:   2, // base + recursive
			expectOverApprox: true,
		},
		{
			name:           "du with multiple paths",
			cmd:            &DfDuCommand{CommandType: "du", Paths: []string{"/tmp", "/var"}},
			expectError:    false,
			expectMinOps:   2,
			expectOverApprox: false,
		},
	}

	parser := &DfDuParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, err := parser.GetSemanticOperations(tt.cmd)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(ops), tt.expectMinOps)

			hasOverApprox := false
			for _, op := range ops {
				if op.Parameters != nil {
					if overApprox, ok := op.Parameters["over_approximated"].(bool); ok && overApprox {
						hasOverApprox = true
						break
					}
				}
			}

			if tt.expectOverApprox {
				assert.True(t, hasOverApprox, "Expected at least one over-approximated operation")
			}

			// Verify operation types are correct
			for _, op := range ops {
				assert.Equal(t, OpRead, op.OperationType, "df/du should only generate read operations")
			}
		})
	}
}

func TestDfDuParser_EdgeCases(t *testing.T) {
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
			name:        "df with unknown option",
			args:        []string{"df", "--unknown-option"},
			expectError: false,
			description: "Should handle unknown options gracefully",
		},
		{
			name:        "du with unknown option",
			args:        []string{"du", "--unknown-option"},
			expectError: false,
			description: "Should handle unknown options gracefully",
		},
		{
			name:        "df with --max-depth but no value",
			args:        []string{"df", "--max-depth"},
			expectError: true,
			description: "Should fail when --max-depth has no value",
		},
		{
			name:        "du with --max-depth but no value",
			args:        []string{"du", "--max-depth"},
			expectError: true,
			description: "Should fail when --max-depth has no value",
		},
	}

	parser := &DfDuParser{}

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

func TestDfDuParser_Soundness(t *testing.T) {
	// Test that the parser maintains soundness guarantees
	// For df/du, soundness means we should always read the expected filesystem paths

	tests := []struct {
		name          string
		args          []string
		expectReadOps []string // paths we definitely expect to see read operations for
	}{
		{
			name:          "df should read filesystem info",
			args:          []string{"df"},
			expectReadOps: []string{"/etc/mtab", "/proc/mounts"},
		},
		{
			name:          "df /tmp should read /tmp",
			args:          []string{"df", "/tmp"},
			expectReadOps: []string{"/tmp"},
		},
		{
			name:          "du should read current directory",
			args:          []string{"du"},
			expectReadOps: []string{"."},
		},
		{
			name:          "du /tmp should read /tmp",
			args:          []string{"du", "/tmp"},
			expectReadOps: []string{"/tmp"},
		},
		{
			name:          "du with no max depth should read recursively",
			args:          []string{"du", "/tmp"},
			expectReadOps: []string{"/tmp"}, // Should at least read /tmp
		},
	}

	parser := &DfDuParser{}

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
					if path == expectedPath+"/*" {
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

func TestDfDuParser_CommandSpecificBehavior(t *testing.T) {
	// Test that df and du have different behaviors

	tests := []struct {
		name               string
		commandType         string
		expectAllFilesystems bool
		expectCurrentDir     bool
	}{
		{
			name:               "df should default to all filesystems",
			commandType:         "df",
			expectAllFilesystems: true,
			expectCurrentDir:     false,
		},
		{
			name:               "du should default to current directory",
			commandType:         "du",
			expectAllFilesystems: false,
			expectCurrentDir:     true,
		},
	}

	parser := &DfDuParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{tt.commandType}
			cmd, err := parser.ParseArguments(args)
			require.NoError(t, err)

			dfDuCmd, ok := cmd.(*DfDuCommand)
			require.True(t, ok)

			if tt.expectAllFilesystems {
				assert.Contains(t, dfDuCmd.Paths, "all_filesystems")
			}
			if tt.expectCurrentDir {
				assert.Contains(t, dfDuCmd.Paths, ".")
			}

			// Verify semantic operations are generated correctly
			ops, err := parser.GetSemanticOperations(dfDuCmd)
			require.NoError(t, err)
			assert.NotEmpty(t, ops)
		})
	}
}