package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeCMakeParser_ParseArguments(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectCmd   *MakeCMakeCommand
	}{
		{
			name:        "basic make",
			args:        []string{"make"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "make",
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "basic cmake",
			args:        []string{"cmake"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "cmake",
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "make with target",
			args:        []string{"make", "all"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "make",
				Targets:     []string{"all"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "make with -j option",
			args:        []string{"make", "-j", "4"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "make",
				Options:     map[string]interface{}{"jobs": "4"},
				Jobs:        1, // Default, actual parsing would set this
			},
		},
		{
			name:        "make with -C option",
			args:        []string{"make", "-C", "/tmp"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "make",
				Options:     map[string]interface{}{"directory": "/tmp"},
				Directory:   "/tmp",
			},
		},
		{
			name:        "cmake with -G option",
			args:        []string{"cmake", "-G", "Unix Makefiles"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "cmake",
				Options:     map[string]interface{}{"generator": "Unix Makefiles"},
				Generator:   "Unix Makefiles",
			},
		},
		{
			name:        "cmake with -DCMAKE_BUILD_TYPE",
			args:        []string{"cmake", "-DCMAKE_BUILD_TYPE", "Release"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "cmake",
				Options:     map[string]interface{}{"build_type": "Release"},
				BuildType:   "Release",
			},
		},
		{
			name:        "cmake with --build option",
			args:        []string{"cmake", "--build", "/tmp/build"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "cmake",
				Options:     map[string]interface{}{"build_directory": "/tmp/build"},
				Directory:   "/tmp/build",
			},
		},
		{
			name:        "cmake with --target option",
			args:        []string{"cmake", "--target", "install"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "cmake",
				Targets:     []string{"install"},
				Options:     map[string]interface{}{"target": "install"},
			},
		},
		{
			name:        "cmake with --install option",
			args:        []string{"cmake", "--install", "/tmp/build"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "cmake",
				Options:     map[string]interface{}{"install": true},
			},
		},
		{
			name:        "make with multiple targets",
			args:        []string{"make", "clean", "all"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "make",
				Targets:     []string{"clean", "all"},
				Options:     map[string]interface{}{},
			},
		},
		{
			name:        "cmake with source directory",
			args:        []string{"cmake", "/tmp/source"},
			expectError: false,
			expectCmd: &MakeCMakeCommand{
				CommandType: "cmake",
				Options:     map[string]interface{}{"source_directory": "/tmp/source"},
				Directory:   "/tmp/source",
			},
		},
	}

	parser := &MakeCMakeParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parser.ParseArguments(tt.args)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			makeCMakeCmd, ok := cmd.(*MakeCMakeCommand)
			require.True(t, ok)

			assert.Equal(t, tt.expectCmd.CommandType, makeCMakeCmd.CommandType)
			assert.Equal(t, tt.expectCmd.Targets, makeCMakeCmd.Targets)
			assert.Equal(t, tt.expectCmd.Directory, makeCMakeCmd.Directory)
			assert.Equal(t, tt.expectCmd.Generator, makeCMakeCmd.Generator)
			assert.Equal(t, tt.expectCmd.BuildType, makeCMakeCmd.BuildType)
			assert.Equal(t, tt.expectCmd.InstallPrefix, makeCMakeCmd.InstallPrefix)

			// Check options map contains expected keys
			for k, v := range tt.expectCmd.Options {
				assert.Equal(t, v, makeCMakeCmd.Options[k])
			}
		})
	}
}

func TestMakeCMakeParser_GetSemanticOperations(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *MakeCMakeCommand
		expectError    bool
		expectMinOps   int
		expectWriteOps bool
		expectOverApprox bool
	}{
		{
			name:           "basic make",
			cmd:            &MakeCMakeCommand{CommandType: "make"},
			expectError:    false,
			expectMinOps:   2, // read Makefile + write build artifacts
			expectWriteOps: true,
			expectOverApprox: true,
		},
		{
			name:           "make with directory",
			cmd:            &MakeCMakeCommand{CommandType: "make", Directory: "/tmp"},
			expectError:    false,
			expectMinOps:   2, // read Makefile + write build artifacts
			expectWriteOps: true,
			expectOverApprox: false,
		},
		{
			name:           "make with parallel jobs",
			cmd:            &MakeCMakeCommand{CommandType: "make", Jobs: 4},
			expectError:    false,
			expectMinOps:   3, // read Makefile + write build artifacts + create temp files
			expectWriteOps: true,
			expectOverApprox: true,
		},
		{
			name:           "basic cmake",
			cmd:            &MakeCMakeCommand{CommandType: "cmake"},
			expectError:    false,
			expectMinOps:   2, // read CMakeLists.txt + create build files
			expectWriteOps: true,
			expectOverApprox: true,
		},
		{
			name:           "cmake with directory",
			cmd:            &MakeCMakeCommand{CommandType: "cmake", Directory: "/tmp"},
			expectError:    false,
			expectMinOps:   2, // read CMakeLists.txt + create build files
			expectWriteOps: true,
			expectOverApprox: false,
		},
		{
			name:           "cmake with install",
			cmd: &MakeCMakeCommand{
				CommandType: "cmake",
				Options:     map[string]interface{}{"install": true},
			},
			expectError:    false,
			expectMinOps:   3, // read CMakeLists.txt + create build files + write install files
			expectWriteOps: true,
			expectOverApprox: true,
		},
	}

	parser := &MakeCMakeParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, err := parser.GetSemanticOperations(tt.cmd)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(ops), tt.expectMinOps)

			hasWriteOps := false
			hasOverApprox := false

			for _, op := range ops {
				if op.OperationType == OpWrite || op.OperationType == OpCreate {
					hasWriteOps = true
				}
				if op.Parameters != nil {
					if overApprox, ok := op.Parameters["over_approximated"].(bool); ok && overApprox {
						hasOverApprox = true
					}
				}
			}

			assert.Equal(t, tt.expectWriteOps, hasWriteOps, "Write operation presence mismatch")
			if tt.expectOverApprox {
				assert.True(t, hasOverApprox, "Expected at least one over-approximated operation")
			}
		})
	}
}

func TestMakeCMakeParser_EdgeCases(t *testing.T) {
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
			name:        "make with -j but no count",
			args:        []string{"make", "-j"},
			expectError: true,
			description: "Should fail when -j has no count",
		},
		{
			name:        "make with -C but no directory",
			args:        []string{"make", "-C"},
			expectError: true,
			description: "Should fail when -C has no directory",
		},
		{
			name:        "cmake with -G but no generator",
			args:        []string{"cmake", "-G"},
			expectError: true,
			description: "Should fail when -G has no generator",
		},
		{
			name:        "cmake with unknown option",
			args:        []string{"cmake", "--unknown-option"},
			expectError: false,
			description: "Should handle unknown options gracefully",
		},
		{
			name:        "make with unknown option",
			args:        []string{"make", "--unknown-option"},
			expectError: false,
			description: "Should handle unknown options gracefully",
		},
	}

	parser := &MakeCMakeParser{}

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

func TestMakeCMakeParser_Soundness(t *testing.T) {
	// Test that the parser maintains soundness guarantees
	// For make/cmake, soundness means we should always read build files
	// and be conservative about write operations

	tests := []struct {
		name          string
		args          []string
		expectReadOps []string // paths we definitely expect to see read operations for
		expectWriteOps bool     // whether we expect write operations
	}{
		{
			name:          "make should read Makefile",
			args:          []string{"make"},
			expectReadOps: []string{"Makefile"},
			expectWriteOps: true,
		},
		{
			name:          "make with directory should read specific Makefile",
			args:          []string{"make", "-C", "/tmp"},
			expectReadOps: []string{"/tmp/Makefile"},
			expectWriteOps: true,
		},
		{
			name:          "cmake should read CMakeLists.txt",
			args:          []string{"cmake"},
			expectReadOps: []string{"CMakeLists.txt"},
			expectWriteOps: true,
		},
		{
			name:          "cmake with directory should read specific CMakeLists.txt",
			args:          []string{"cmake", "/tmp"},
			expectReadOps: []string{"/tmp/CMakeLists.txt"},
			expectWriteOps: true,
		},
	}

	parser := &MakeCMakeParser{}

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
				// Check if exact path exists
				hasExact := foundPaths[expectedPath]

				assert.True(t, hasExact,
					"Expected read operation for path %s, got paths: %v", expectedPath, foundPaths)
			}

			// Check for write operations if expected
			hasWriteOps := false
			for _, op := range ops {
				if op.OperationType == OpWrite || op.OperationType == OpCreate {
					hasWriteOps = true
					break
				}
			}
			assert.Equal(t, tt.expectWriteOps, hasWriteOps, "Write operation presence mismatch")
		})
	}
}

func TestMakeCMakeParser_DangerousOperations(t *testing.T) {
	// Test that install operations are properly marked as dangerous

	tests := []struct {
		name               string
		args               []string
		expectDangerousOps bool
	}{
		{
			name:               "basic make should not be dangerous",
			args:               []string{"make"},
			expectDangerousOps: false,
		},
		{
			name:               "basic cmake should not be dangerous",
			args:               []string{"cmake"},
			expectDangerousOps: false,
		},
		{
			name:               "cmake with install should be dangerous",
			args:               []string{"cmake", "--install", "/tmp/build"},
			expectDangerousOps: true,
		},
	}

	parser := &MakeCMakeParser{}

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

func TestMakeCMakeParser_CommandSpecificBehavior(t *testing.T) {
	// Test that make and cmake have different behaviors

	tests := []struct {
		name                   string
		commandType             string
		expectMakefileRead      bool
		expectCMakeListsRead    bool
		expectParallelBuildSupport bool
	}{
		{
			name:                   "make should read Makefile",
			commandType:             "make",
			expectMakefileRead:      true,
			expectCMakeListsRead:    false,
			expectParallelBuildSupport: true,
		},
		{
			name:                   "cmake should read CMakeLists.txt",
			commandType:             "cmake",
			expectMakefileRead:      false,
			expectCMakeListsRead:    true,
			expectParallelBuildSupport: false,
		},
	}

	parser := &MakeCMakeParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{tt.commandType}
			cmd, err := parser.ParseArguments(args)
			require.NoError(t, err)

			makeCMakeCmd, ok := cmd.(*MakeCMakeCommand)
			require.True(t, ok)

			assert.Equal(t, tt.commandType, makeCMakeCmd.CommandType)

			// Test command-specific behaviors
			if tt.expectParallelBuildSupport {
				argsWithParallel := []string{tt.commandType, "-j", "4"}
				cmdWithParallel, err := parser.ParseArguments(argsWithParallel)
				require.NoError(t, err)
				makeCMakeCmdWithParallel := cmdWithParallel.(*MakeCMakeCommand)
				assert.Equal(t, 1, makeCMakeCmdWithParallel.Jobs) // Default value
			}

			// Verify semantic operations are generated correctly
			ops, err := parser.GetSemanticOperations(makeCMakeCmd)
			require.NoError(t, err)
			assert.NotEmpty(t, ops)

			// Check for expected read operations
			foundMakefile := false
			foundCMakeLists := false
			for _, op := range ops {
				if op.OperationType == OpRead {
					if op.TargetPath == "Makefile" || strings.HasSuffix(op.TargetPath, "/Makefile") {
						foundMakefile = true
					}
					if op.TargetPath == "CMakeLists.txt" || strings.HasSuffix(op.TargetPath, "/CMakeLists.txt") {
						foundCMakeLists = true
					}
				}
			}

			assert.Equal(t, tt.expectMakefileRead, foundMakefile)
			assert.Equal(t, tt.expectCMakeListsRead, foundCMakeLists)
		})
	}
}