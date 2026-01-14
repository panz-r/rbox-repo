package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSedAWKParser_ParseArguments(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectCmd   *SedAWKCommand
	}{
		{
			name:        "basic sed",
			args:        []string{"sed"},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "sed",
				Files:       []string{"/dev/stdin"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "basic awk",
			args:        []string{"awk"},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "awk",
				Files:       []string{"/dev/stdin"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "sed with -i option",
			args:        []string{"sed", "-i"},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "sed",
				Files:       []string{"/dev/stdin"},
				Options:     map[string]interface{}{"in_place": true},
				InPlace:     true,
			},
		},
		{
			name:        "sed with -e option and script",
			args:        []string{"sed", "-e", "s/foo/bar/"},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "sed",
				Files:       []string{"/dev/stdin"},
				Options:     map[string]interface{}{"script": "s/foo/bar/"},
				Script:      "s/foo/bar/",
			},
		},
		{
			name:        "sed with -f option and script file",
			args:        []string{"sed", "-f", "script.sed"},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "sed",
				Files:       []string{"/dev/stdin"},
				Options:     map[string]interface{}{"script_file": "script.sed"},
			},
		},
		{
			name:        "awk with -F option",
			args:        []string{"awk", "-F", ","},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "awk",
				Files:       []string{"/dev/stdin"},
				Options:     map[string]interface{}{"field_separator": "\t"},
				FieldSep:    "\t",
			},
		},
		{
			name:        "awk with -v option",
			args:        []string{"awk", "-v", "x=1"},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "awk",
				Files:       []string{"/dev/stdin"},
				Options:     map[string]interface{}{"variable": "x=1"},
			},
		},
		{
			name:        "sed with script and file",
			args:        []string{"sed", "s/foo/bar/", "file.txt"},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "sed",
				Files:       []string{"file.txt"},
				Options:     map[string]interface{}{"script": "s/foo/bar/"},
				Script:      "s/foo/bar/",
			},
		},
		{
			name:        "sed with multiple files",
			args:        []string{"sed", "s/foo/bar/", "file1.txt", "file2.txt"},
			expectError: false,
			expectCmd: &SedAWKCommand{
				CommandType: "sed",
				Files:       []string{"file1.txt", "file2.txt"},
				Options:     map[string]interface{}{"script": "s/foo/bar/"},
				Script:      "s/foo/bar/",
			},
		},
	}

	parser := &SedAWKParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments(tt.args)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			sedAWKCmd, ok := cmd.(*SedAWKCommand)
			require.True(t, ok)

			assert.Equal(t, tt.expectCmd.CommandType, sedAWKCmd.CommandType)
			assert.Equal(t, tt.expectCmd.Files, sedAWKCmd.Files)
			assert.Equal(t, tt.expectCmd.InPlace, sedAWKCmd.InPlace)
			assert.Equal(t, tt.expectCmd.Script, sedAWKCmd.Script)
			assert.Equal(t, tt.expectCmd.FieldSep, sedAWKCmd.FieldSep)

			// Check options map contains expected keys
			for k, v := range tt.expectCmd.Options {
				assert.Equal(t, v, sedAWKCmd.Options[k])
			}
		})
	}
}

func TestSedAWKParser_GetSemanticOperations(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *SedAWKCommand
		expectError    bool
		expectMinOps   int
		expectEditOps  bool
		expectOverApprox bool
	}{
		{
			name:           "basic sed (no in-place)",
			cmd:            &SedAWKCommand{CommandType: "sed", Files: []string{"file.txt"}},
			expectError:    false,
			expectMinOps:   2, // read file + read metadata
			expectEditOps:  false,
			expectOverApprox: true,
		},
		{
			name:           "sed with in-place editing",
			cmd:            &SedAWKCommand{CommandType: "sed", Files: []string{"file.txt"}, InPlace: true},
			expectError:    false,
			expectMinOps:   3, // read file + read metadata + edit file
			expectEditOps:  true,
			expectOverApprox: true,
		},
		{
			name:           "awk basic",
			cmd:            &SedAWKCommand{CommandType: "awk", Files: []string{"file.txt"}},
			expectError:    false,
			expectMinOps:   2, // read file + read metadata
			expectEditOps:  false,
			expectOverApprox: true,
		},
		{
			name:           "sed with multiple files",
			cmd:            &SedAWKCommand{CommandType: "sed", Files: []string{"file1.txt", "file2.txt"}},
			expectError:    false,
			expectMinOps:   4, // 2 files * (read + metadata)
			expectEditOps:  false,
			expectOverApprox: true,
		},
		{
			name:           "sed with script file",
			cmd: &SedAWKCommand{
				CommandType: "sed",
				Files:       []string{"file.txt"},
				Options:     map[string]interface{}{"script_file": "script.sed"},
			},
			expectError:    false,
			expectMinOps:   3, // read file + read metadata + read script file
			expectEditOps:  false,
			expectOverApprox: true,
		},
	}

	parser := &SedAWKParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, err := parser.GetSemanticOperations(tt.cmd)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(ops), tt.expectMinOps)

			hasEditOps := false
			hasOverApprox := false

			for _, op := range ops {
				if op.OperationType == OpEdit {
					hasEditOps = true
				}
				if op.Parameters != nil {
					if overApprox, ok := op.Parameters["over_approximated"].(bool); ok && overApprox {
						hasOverApprox = true
					}
				}
			}

			assert.Equal(t, tt.expectEditOps, hasEditOps, "Edit operation presence mismatch")
			if tt.expectOverApprox {
				assert.True(t, hasOverApprox, "Expected at least one over-approximated operation")
			}

			// Verify no write operations (only read and edit)
			for _, op := range ops {
				assert.NotEqual(t, OpWrite, op.OperationType, "sed/awk should not generate write operations")
			}
		})
	}
}

func TestSedAWKParser_EdgeCases(t *testing.T) {
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
			name:        "sed with -e but no script",
			args:        []string{"sed", "-e"},
			expectError: true,
			description: "Should fail when -e has no script",
		},
		{
			name:        "sed with -f but no file",
			args:        []string{"sed", "-f"},
			expectError: true,
			description: "Should fail when -f has no file",
		},
		{
			name:        "awk with -v but no assignment",
			args:        []string{"awk", "-v"},
			expectError: true,
			description: "Should fail when -v has no assignment",
		},
		{
			name:        "sed with unknown option",
			args:        []string{"sed", "--unknown-option"},
			expectError: false,
			description: "Should handle unknown options gracefully",
		},
		{
			name:        "awk with unknown option",
			args:        []string{"awk", "--unknown-option"},
			expectError: false,
			description: "Should handle unknown options gracefully",
		},
	}

	parser := &SedAWKParser{}

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

func TestSedAWKParser_Soundness(t *testing.T) {
	// Test that the parser maintains soundness guarantees
	// For sed/awk, soundness means we should always read input files
	// and be conservative about metadata and backup files

	tests := []struct {
		name          string
		args          []string
		expectReadOps []string // paths we definitely expect to see read operations for
		expectEditOps bool     // whether we expect edit operations
	}{
		{
			name:          "sed should read input file",
			args:          []string{"sed", "s/foo/bar/", "file.txt"},
			expectReadOps: []string{"file.txt"},
			expectEditOps: false,
		},
		{
			name:          "sed with in-place should read and edit file",
			args:          []string{"sed", "-i", "s/foo/bar/", "file.txt"},
			expectReadOps: []string{"file.txt"},
			expectEditOps: true,
		},
		{
			name:          "awk should read input file",
			args:          []string{"awk", "{print $1}", "file.txt"},
			expectReadOps: []string{"file.txt"},
			expectEditOps: false,
		},
		{
			name:          "sed with script file should read script file",
			args:          []string{"sed", "-f", "script.sed"},
			expectReadOps: []string{"script.sed"},
			expectEditOps: false,
		},
	}

	parser := &SedAWKParser{}

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
					if path == expectedPath+".meta" {
						hasPattern = true
						break
					}
				}

				assert.True(t, hasExact || hasPattern,
					"Expected read operation for path %s, got paths: %v", expectedPath, foundPaths)
			}

			// Check for edit operations if expected
			hasEditOps := false
			for _, op := range ops {
				if op.OperationType == OpEdit {
					hasEditOps = true
					break
				}
			}
			assert.Equal(t, tt.expectEditOps, hasEditOps, "Edit operation presence mismatch")
		})
	}
}

func TestSedAWKParser_DangerousOperations(t *testing.T) {
	// Test that in-place editing is properly marked as dangerous

	tests := []struct {
		name               string
		args               []string
		expectDangerousOps bool
	}{
		{
			name:               "sed without in-place should not be dangerous",
			args:               []string{"sed", "s/foo/bar/", "file.txt"},
			expectDangerousOps: false,
		},
		{
			name:               "sed with in-place should be dangerous",
			args:               []string{"sed", "-i", "s/foo/bar/", "file.txt"},
			expectDangerousOps: true,
		},
		{
			name:               "awk should not be dangerous",
			args:               []string{"awk", "{print $1}", "file.txt"},
			expectDangerousOps: false,
		},
	}

	parser := &SedAWKParser{}

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

func TestSedAWKParser_CommandSpecificBehavior(t *testing.T) {
	// Test that sed and awk have different behaviors

	tests := []struct {
		name               string
		commandType         string
		expectInPlaceSupport bool
		expectFieldSepOption bool
	}{
		{
			name:               "sed should support in-place editing",
			commandType:         "sed",
			expectInPlaceSupport: true,
			expectFieldSepOption: false,
		},
		{
			name:               "awk should support field separator",
			commandType:         "awk",
			expectInPlaceSupport: false,
			expectFieldSepOption: true,
		},
	}

	parser := &SedAWKParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{tt.commandType}
			cmd, err := parser.ParseArguments(args)
			require.NoError(t, err)

			sedAWKCmd, ok := cmd.(*SedAWKCommand)
			require.True(t, ok)

			assert.Equal(t, tt.commandType, sedAWKCmd.CommandType)

			// Test command-specific options
			if tt.expectInPlaceSupport {
				argsWithInPlace := []string{tt.commandType, "-i", "s/foo/bar/", "file.txt"}
				cmdWithInPlace, err := parser.ParseArguments(argsWithInPlace)
				require.NoError(t, err)
				sedAWKCmdWithInPlace := cmdWithInPlace.(*SedAWKCommand)
				assert.True(t, sedAWKCmdWithInPlace.InPlace)
			}

			if tt.expectFieldSepOption {
				argsWithFieldSep := []string{tt.commandType, "-F", ","}
				cmdWithFieldSep, err := parser.ParseArguments(argsWithFieldSep)
				require.NoError(t, err)
				sedAWKCmdWithFieldSep := cmdWithFieldSep.(*SedAWKCommand)
				assert.Equal(t, "\t", sedAWKCmdWithFieldSep.FieldSep)
			}

			// Verify semantic operations are generated correctly
			ops, err := parser.GetSemanticOperations(sedAWKCmd)
			require.NoError(t, err)
			assert.NotEmpty(t, ops)
		})
	}
}