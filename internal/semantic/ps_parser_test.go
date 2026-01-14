package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPsParser_ParseArguments(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectCmd   *PsCommand
	}{
		{
			name:        "basic ps",
			args:        []string{},
			expectError: false,
			expectCmd: &PsCommand{
				Options: map[string]interface{}{},
			},
		},
		{
			name:        "ps with -e option",
			args:        []string{"-e"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:   map[string]interface{}{"show_all": true},
				ShowAll:   true,
			},
		},
		{
			name:        "ps with -f option",
			args:        []string{"-f"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:     map[string]interface{}{"full_format": true},
				FullFormat:  true,
			},
		},
		{
			name:        "ps with -l option",
			args:        []string{"-l"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:     map[string]interface{}{"long_format": true},
				LongFormat:  true,
			},
		},
		{
			name:        "ps with -u option",
			args:        []string{"-u"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:     map[string]interface{}{"user_format": true},
				FullFormat:  true,
			},
		},
		{
			name:        "ps with -U option and user",
			args:        []string{"-U", "john"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:   map[string]interface{}{"user_spec": "john"},
				UserSpec:  "john",
			},
		},
		{
			name:        "ps with -p option and PIDs",
			args:        []string{"-p", "123,456"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:     map[string]interface{}{"process_ids": []string{"123", "456"}},
				ProcessIDs:  []string{"123", "456"},
			},
		},
		{
			name:        "ps with -T option",
			args:        []string{"-T"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:       map[string]interface{}{"show_threads": true},
				ShowThreads:   true,
			},
		},
		{
			name:        "ps with --forest option",
			args:        []string{"--forest"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:       map[string]interface{}{"show_forest": true},
				ShowForest:    true,
			},
		},
		{
			name:        "ps with --no-headers option",
			args:        []string{"--no-headers"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:     map[string]interface{}{"no_headers": true},
				NoHeaders:   true,
			},
		},
		{
			name:        "ps with multiple options",
			args:        []string{"-e", "-f", "-l"},
			expectError: false,
			expectCmd: &PsCommand{
				Options:      map[string]interface{}{"show_all": true, "full_format": true, "long_format": true},
				ShowAll:      true,
				FullFormat:   true,
				LongFormat:   true,
			},
		},
	}

	parser := &PsParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments(tt.args)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			psCmd, ok := cmd.(*PsCommand)
			require.True(t, ok)

			assert.Equal(t, tt.expectCmd.ShowAll, psCmd.ShowAll)
			assert.Equal(t, tt.expectCmd.FullFormat, psCmd.FullFormat)
			assert.Equal(t, tt.expectCmd.LongFormat, psCmd.LongFormat)
			assert.Equal(t, tt.expectCmd.UserSpec, psCmd.UserSpec)
			assert.Equal(t, tt.expectCmd.ProcessIDs, psCmd.ProcessIDs)
			assert.Equal(t, tt.expectCmd.ShowThreads, psCmd.ShowThreads)
			assert.Equal(t, tt.expectCmd.ShowForest, psCmd.ShowForest)
			assert.Equal(t, tt.expectCmd.NoHeaders, psCmd.NoHeaders)

			// Check options map contains expected keys
			for k, v := range tt.expectCmd.Options {
				assert.Equal(t, v, psCmd.Options[k])
			}
		})
	}
}

func TestPsParser_GetSemanticOperations(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *PsCommand
		expectError    bool
		expectMinOps   int
		expectOverApprox bool
		expectPrecise   bool
	}{
		{
			name:           "basic ps",
			cmd:            &PsCommand{},
			expectError:    false,
			expectMinOps:   1,
			expectOverApprox: true,
			expectPrecise:   false,
		},
		{
			name:           "ps with specific PIDs",
			cmd:            &PsCommand{ProcessIDs: []string{"123", "456"}},
			expectError:    false,
			expectMinOps:   3, // 1 for all processes + 2 for specific PIDs
			expectOverApprox: true,
			expectPrecise:   true,
		},
		{
			name:           "ps with show all",
			cmd:            &PsCommand{ShowAll: true},
			expectError:    false,
			expectMinOps:   2, // 1 for all processes + 1 for all process status
			expectOverApprox: true,
			expectPrecise:   false,
		},
		{
			name:           "ps with user spec",
			cmd:            &PsCommand{UserSpec: "john"},
			expectError:    false,
			expectMinOps:   1,
			expectOverApprox: true,
			expectPrecise:   false,
		},
	}

	parser := &PsParser{}

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
			hasPrecise := false

			for _, op := range ops {
				if op.Parameters != nil {
					if overApprox, ok := op.Parameters["over_approximated"].(bool); ok && overApprox {
						hasOverApprox = true
					}
					if precise, ok := op.Parameters["precise"].(bool); ok && precise {
						hasPrecise = true
					}
				}
			}

			if tt.expectOverApprox {
				assert.True(t, hasOverApprox, "Expected at least one over-approximated operation")
			}
			if tt.expectPrecise {
				assert.True(t, hasPrecise, "Expected at least one precise operation")
			}

			// Verify operation types are correct
			for _, op := range ops {
				assert.Equal(t, OpRead, op.OperationType, "ps should only generate read operations")
			}
		})
	}
}

func TestPsParser_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		description string
	}{
		{
			name:        "ps with unknown option",
			args:        []string{"--unknown-option"},
			expectError: false,
			description: "Should handle unknown options gracefully",
		},
		{
			name:        "ps with -p but no PIDs",
			args:        []string{"-p"},
			expectError: true,
			description: "Should fail when -p has no PIDs",
		},
		{
			name:        "ps with -U but no user",
			args:        []string{"-U"},
			expectError: true,
			description: "Should fail when -U has no user",
		},
		{
			name:        "ps with multiple -p options",
			args:        []string{"-p", "123", "-p", "456"},
			expectError: false,
			description: "Should handle multiple -p options (only first used)",
		},
	}

	parser := &PsParser{}

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

func TestPsParser_Soundness(t *testing.T) {
	// Test that the parser maintains soundness guarantees
	// For ps, soundness means we should always read /proc/* for basic ps
	// and be conservative about what processes might be accessed

	tests := []struct {
		name          string
		args          []string
		expectReadOps []string // paths we definitely expect to see read operations for
	}{
		{
			name:          "basic ps should read /proc/*",
			args:          []string{},
			expectReadOps: []string{"/proc/*"},
		},
		{
			name:          "ps -e should read /proc/* and /proc/*/status",
			args:          []string{"-e"},
			expectReadOps: []string{"/proc/*", "/proc/*/status"},
		},
		{
			name:          "ps -p should read specific PID and /proc/*",
			args:          []string{"-p", "123"},
			expectReadOps: []string{"/proc/*", "/proc/123"},
		},
	}

	parser := &PsParser{}

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
					if path == expectedPath {
						hasExact = true
						break
					}
				}

				assert.True(t, hasExact || hasPattern,
					"Expected read operation for path %s, got paths: %v", expectedPath, foundPaths)
			}
		})
	}
}

func TestPsParser_DangerousOperations(t *testing.T) {
	// Test that ps operations are properly marked as potentially dangerous
	// when they access sensitive process information

	tests := []struct {
		name               string
		args               []string
		expectDangerousOps bool
	}{
		{
			name:               "basic ps should not be dangerous",
			args:               []string{},
			expectDangerousOps: false,
		},
		{
			name:               "ps -e should be dangerous (reads all processes)",
			args:               []string{"-e"},
			expectDangerousOps: true,
		},
		{
			name:               "ps -p should not be dangerous (specific PIDs)",
			args:               []string{"-p", "123"},
			expectDangerousOps: false,
		},
	}

	parser := &PsParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments(tt.args)
			require.NoError(t, err)

			ops, err := parser.GetSemanticOperations(cmd)
			require.NoError(t, err)

			hasDangerous := false
			for _, op := range ops {
				if op.Parameters != nil {
					if dangerous, ok := op.Parameters["dangerous"].(bool); ok && dangerous {
						hasDangerous = true
						break
					}
				}
			}

			assert.Equal(t, tt.expectDangerousOps, hasDangerous,
				"Dangerous operation flag mismatch")
		})
	}
}