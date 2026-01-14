package semantic

import (
	"fmt"
	"strings"
)

// MakeCMakeCommand represents a parsed make or cmake command
type MakeCMakeCommand struct {
	CommandType string // "make" or "cmake"
	Targets     []string
	Options     map[string]interface{}
	Jobs        int
	Directory   string
	Generator   string
	BuildType   string
	InstallPrefix string
}

// MakeCMakeParser parses make and cmake commands
type MakeCMakeParser struct{}

// ParseArguments implements CommandParser for make/cmake commands
func (m *MakeCMakeParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for make/cmake parser")
	}

	cmd := &MakeCMakeCommand{
		CommandType: args[0], // "make" or "cmake"
		Options:     make(map[string]interface{}),
	}

	i := 1
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-j":
			// Jobs count follows
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing jobs count after -j")
			}
			// Simple parsing - in real implementation would use strconv.Atoi
			cmd.Jobs = 1 // Default
			cmd.Options["jobs"] = args[i+1]
			i += 2
			continue
		case "-C":
			// Directory follows
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing directory after -C")
			}
			cmd.Directory = args[i+1]
			cmd.Options["directory"] = args[i+1]
			i += 2
			continue
		case "-G":
			// Generator follows (cmake)
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing generator after -G")
			}
			cmd.Generator = args[i+1]
			cmd.Options["generator"] = args[i+1]
			i += 2
			continue
		case "-DCMAKE_BUILD_TYPE":
			// Build type follows (cmake)
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing build type after -DCMAKE_BUILD_TYPE")
			}
			cmd.BuildType = args[i+1]
			cmd.Options["build_type"] = args[i+1]
			i += 2
			continue
		case "-DCMAKE_INSTALL_PREFIX":
			// Install prefix follows (cmake)
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing install prefix after -DCMAKE_INSTALL_PREFIX")
			}
			cmd.InstallPrefix = args[i+1]
			cmd.Options["install_prefix"] = args[i+1]
			i += 2
			continue
		case "--build":
			// Build directory follows (cmake)
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing build directory after --build")
			}
			cmd.Directory = args[i+1]
			cmd.Options["build_directory"] = args[i+1]
			i += 2
			continue
		case "--target":
			// Target follows (cmake)
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing target after --target")
			}
			cmd.Targets = append(cmd.Targets, args[i+1])
			cmd.Options["target"] = args[i+1]
			i += 2
			continue
		case "--install":
			cmd.Options["install"] = true
		case "--clean-first":
			cmd.Options["clean_first"] = true
		case "--":
			i++
			break
		default:
			// Handle other options
			cmd.Options[opt] = true
		}
		i++
	}

	// Remaining arguments are targets (for make) or other arguments
	if i < len(args) {
		if cmd.CommandType == "make" {
			cmd.Targets = args[i:]
		} else if cmd.CommandType == "cmake" {
			// For cmake, remaining args could be source directory
			if len(cmd.Directory) == 0 {
				cmd.Directory = args[i]
				cmd.Options["source_directory"] = args[i]
			}
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for make/cmake commands
func (m *MakeCMakeParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*MakeCMakeCommand)
	if !ok {
		return nil, fmt.Errorf("invalid make/cmake command type")
	}

	operations := make([]SemanticOperation, 0)

	if cmd.CommandType == "make" {
		// Make reads Makefiles - this is precise if we know the directory
		if cmd.Directory != "" {
			operations = append(operations, SemanticOperation{
				OperationType: OpRead,
				TargetPath:    cmd.Directory + "/Makefile",
				Context:       "makefile_read",
				Parameters: map[string]interface{}{
					"command": "make",
					"targets":  cmd.Targets,
					"precise":   true, // We know exactly which Makefile
				},
			})
		} else {
			// Conservative: we don't know which Makefile will be used
			operations = append(operations, SemanticOperation{
				OperationType: OpRead,
				TargetPath:    "Makefile",
				Context:       "makefile_read",
				Parameters: map[string]interface{}{
					"command": "make",
					"targets":  cmd.Targets,
					"over_approximated": true, // Conservative: unknown Makefile location
				},
			})
		}

		// Make can write build artifacts - this is always conservative
		operations = append(operations, SemanticOperation{
			OperationType: OpWrite,
			TargetPath:    ".",
			Context:       "build_artifacts",
			Parameters: map[string]interface{}{
				"command": "make",
				"targets":  cmd.Targets,
				"over_approximated": true, // Conservative: we don't know all build outputs
			},
		})

		// If parallel jobs are specified, this might create more temporary files
		if cmd.Jobs > 1 {
			operations = append(operations, SemanticOperation{
				OperationType: OpCreate,
				TargetPath:    "./tmp/*",
				Context:       "parallel_build_temp",
				Parameters: map[string]interface{}{
					"command": "make",
					"jobs":    cmd.Jobs,
					"over_approximated": true, // Conservative: unknown temp files
				},
			})
		}

	} else if cmd.CommandType == "cmake" {
		// CMake reads CMakeLists.txt
		if cmd.Directory != "" {
			// If source directory is specified, read from there
			operations = append(operations, SemanticOperation{
				OperationType: OpRead,
				TargetPath:    cmd.Directory + "/CMakeLists.txt",
				Context:       "cmake_read",
				Parameters: map[string]interface{}{
					"command": "cmake",
					"generator": cmd.Generator,
					"precise":   true, // We know exactly which CMakeLists.txt
				},
			})
		} else {
			// Conservative: we don't know which CMakeLists.txt will be used
			operations = append(operations, SemanticOperation{
				OperationType: OpRead,
				TargetPath:    "CMakeLists.txt",
				Context:       "cmake_read",
				Parameters: map[string]interface{}{
					"command": "cmake",
					"generator": cmd.Generator,
					"over_approximated": true, // Conservative: unknown location
				},
			})
		}

		// CMake writes build files - this is precise if we know the build directory
		if cmd.Directory != "" {
			operations = append(operations, SemanticOperation{
				OperationType: OpCreate,
				TargetPath:    cmd.Directory,
				Context:       "build_files",
				Parameters: map[string]interface{}{
					"command": "cmake",
					"generator": cmd.Generator,
					"precise":   true, // We know exactly where build files go
				},
			})
		} else {
			operations = append(operations, SemanticOperation{
				OperationType: OpCreate,
				TargetPath:    "build",
				Context:       "build_files",
				Parameters: map[string]interface{}{
					"command": "cmake",
					"generator": cmd.Generator,
					"over_approximated": true, // Conservative: unknown build dir
				},
			})
		}

		// If install is requested, add install operations
		if _, ok := cmd.Options["install"]; ok {
			installPath := cmd.InstallPrefix
			if installPath == "" {
				installPath = "/usr/local"
			}
			operations = append(operations, SemanticOperation{
				OperationType: OpWrite,
				TargetPath:    installPath + "/*",
				Context:       "install",
				Parameters: map[string]interface{}{
					"command": "cmake",
					"dangerous": true,
					"over_approximated": true, // Conservative: we don't know all install paths
				},
			})
		}
	}

	return operations, nil
}