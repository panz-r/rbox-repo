package semantic

import (
	"fmt"
	"strings"
)

// ScpCommand represents a parsed scp command
type ScpCommand struct {
	Options     map[string]interface{}
	Operation   string // "copy_to_remote", "copy_from_remote", "copy_remote_to_remote"
	Sources     []string
	Destination string
	Port        string
	IdentityFile string
	Recursive   bool
	Preserve    bool
	Verbose     bool
	Quiet       bool
	Limit       string
}

// ScpParser parses scp commands
type ScpParser struct {
	utils *ParserUtils
}

// NewScpParser creates a new ScpParser
func NewScpParser() *ScpParser {
	return &ScpParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for scp commands
func (s *ScpParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for scp parser")
	}

	cmd := &ScpCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-P":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing port after -P")
			}
			cmd.Port = args[i+1]
			cmd.Options["port"] = args[i+1]
			i += 2
			continue
		case "-i":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing identity file after -i")
			}
			cmd.IdentityFile = args[i+1]
			cmd.Options["identity_file"] = args[i+1]
			i += 2
			continue
		case "-r", "--recursive":
			cmd.Recursive = true
			cmd.Options["recursive"] = true
		case "-p", "--preserve":
			cmd.Preserve = true
			cmd.Options["preserve"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "-q", "--quiet":
			cmd.Quiet = true
			cmd.Options["quiet"] = true
		case "-l":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing limit after -l")
			}
			cmd.Limit = args[i+1]
			cmd.Options["limit"] = args[i+1]
			i += 2
			continue
		case "--":
			i++
			break
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'r':
						cmd.Recursive = true
						cmd.Options["recursive"] = true
					case 'p':
						cmd.Preserve = true
						cmd.Options["preserve"] = true
					case 'v':
						cmd.Verbose = true
						cmd.Options["verbose"] = true
					case 'q':
						cmd.Quiet = true
						cmd.Options["quiet"] = true
					}
				}
			}
		}
		i++
	}

	// Parse sources and destination
	if i < len(args) {
		// Last argument is destination, rest are sources
		if i+1 < len(args) {
			cmd.Sources = args[i : len(args)-1]
			cmd.Destination = args[len(args)-1]
		} else {
			return nil, fmt.Errorf("missing destination for scp command")
		}
	} else {
		return nil, fmt.Errorf("missing source and destination for scp command")
	}

	// Determine operation type
	if len(cmd.Sources) > 0 && len(cmd.Destination) > 0 {
		if s.isRemotePath(cmd.Sources[0]) && s.isRemotePath(cmd.Destination) {
			cmd.Operation = "copy_remote_to_remote"
		} else if s.isRemotePath(cmd.Destination) {
			cmd.Operation = "copy_to_remote"
		} else if s.isRemotePath(cmd.Sources[0]) {
			cmd.Operation = "copy_from_remote"
		} else {
			return nil, fmt.Errorf("invalid scp operation: both source and destination are local")
		}
	}

	return cmd, nil
}

// isRemotePath checks if a path is a remote path (user@host:path)
func (s *ScpParser) isRemotePath(path string) bool {
	return strings.Contains(path, "@") && strings.Contains(path, ":")
}

// GetSemanticOperations implements CommandParser for scp commands
func (s *ScpParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*ScpCommand)
	if !ok {
		return nil, fmt.Errorf("invalid scp command type")
	}

	builder := s.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	// SCP always reads configuration and known hosts
	builder.AddReadOperation("/etc/ssh/ssh_config", "ssh_config")
		
			builder = builder.WithParameter("command", "scp")
		
			builder = builder.WithParameter("over_approximated", true)

	builder.AddReadOperation("~/.ssh/known_hosts", "known_hosts")
		
			builder = builder.WithParameter("command", "scp")
		
			builder = builder.WithParameter("over_approximated", true)

	// Read identity file if specified
	if cmd.IdentityFile != "" {
		builder.AddReadOperation(cmd.IdentityFile, "identity_file")
			
			builder = builder.WithParameter("command", "scp")
			
			builder = builder.WithParameter("precise", true)
			
			builder = builder.WithParameter("dangerous", true)
	} else {
		builder.AddReadOperation("~/.ssh/id_rsa", "default_identity")
			
			builder = builder.WithParameter("command", "scp")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("dangerous", true)
	}

	// Handle different operation types
	switch cmd.Operation {
	case "copy_to_remote":
		// Read local source files
		for _, source := range cmd.Sources {
			builder.AddReadOperation(source, "local_source_read")
				
			builder = builder.WithParameter("command", "scp")
				
			builder = builder.WithParameter("operation", "copy_to_remote")

			// Read metadata if preserving
			if cmd.Preserve {
				builder.AddReadOperation(source+".meta", "source_metadata")
					
			builder = builder.WithParameter("command", "scp")
					
			builder = builder.WithParameter("over_approximated", true)
			}

			// If recursive, read directory contents
			if cmd.Recursive && s.isDirectory(source) {
				builder.AddReadOperation(source+"/*", "recursive_source_read")
					
			builder = builder.WithParameter("command", "scp")
					
			builder = builder.WithParameter("over_approximated", true)
			}
		}

		// Write to remote destination (dangerous)
		builder.AddWriteOperation("network:"+s.getRemoteHost(cmd.Destination)+":"+s.getRemotePort(cmd)+"/"+s.getRemotePath(cmd.Destination), "remote_write")
			
			builder = builder.WithParameter("command", "scp")
			
			builder = builder.WithParameter("operation", "copy_to_remote")
			
			builder = builder.WithParameter("dangerous", true)
			
			builder = builder.WithParameter("high_risk", true)

		// If recursive, write directory contents
		if cmd.Recursive {
			builder.AddWriteOperation("network:"+s.getRemoteHost(cmd.Destination)+":"+s.getRemotePort(cmd)+"/"+s.getRemotePath(cmd.Destination)+"/*", "recursive_remote_write")
				
			builder = builder.WithParameter("command", "scp")
				
			builder = builder.WithParameter("operation", "copy_to_remote")
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("high_risk", true)
				
			builder = builder.WithParameter("over_approximated", true)
		}

	case "copy_from_remote":
		// Read from remote source (dangerous)
		for _, source := range cmd.Sources {
			builder.AddReadOperation("network:"+s.getRemoteHost(source)+":"+s.getRemotePort(cmd)+"/"+s.getRemotePath(source), "remote_source_read")
				
			builder = builder.WithParameter("command", "scp")
				
			builder = builder.WithParameter("operation", "copy_from_remote")
				
			builder = builder.WithParameter("dangerous", true)

			// If recursive, read directory contents
			if cmd.Recursive {
				builder.AddReadOperation("network:"+s.getRemoteHost(source)+":"+s.getRemotePort(cmd)+"/"+s.getRemotePath(source)+"/*", "recursive_remote_read")
					
			builder = builder.WithParameter("command", "scp")
					
			builder = builder.WithParameter("operation", "copy_from_remote")
					
			builder = builder.WithParameter("dangerous", true)
					
			builder = builder.WithParameter("over_approximated", true)
			}
		}

		// Write to local destination
		builder.AddWriteOperation(cmd.Destination, "local_destination_write")
			
			builder = builder.WithParameter("command", "scp")
			
			builder = builder.WithParameter("operation", "copy_from_remote")
			
			builder = builder.WithParameter("dangerous", true)

		// If recursive, write directory contents
		if cmd.Recursive {
			builder.AddWriteOperation(cmd.Destination+"/*", "recursive_local_write")
				
			builder = builder.WithParameter("command", "scp")
				
			builder = builder.WithParameter("operation", "copy_from_remote")
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("over_approximated", true)
		}

	case "copy_remote_to_remote":
		// Read from remote source (dangerous)
		for _, source := range cmd.Sources {
			builder.AddReadOperation("network:"+s.getRemoteHost(source)+":"+s.getRemotePort(cmd)+"/"+s.getRemotePath(source), "remote_source_read")
				
			builder = builder.WithParameter("command", "scp")
				
			builder = builder.WithParameter("operation", "copy_remote_to_remote")
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("high_risk", true)

			// If recursive, read directory contents
			if cmd.Recursive {
				builder.AddReadOperation("network:"+s.getRemoteHost(source)+":"+s.getRemotePort(cmd)+"/"+s.getRemotePath(source)+"/*", "recursive_remote_read")
					
			builder = builder.WithParameter("command", "scp")
					
			builder = builder.WithParameter("operation", "copy_remote_to_remote")
					
			builder = builder.WithParameter("dangerous", true)
					
			builder = builder.WithParameter("high_risk", true)
					
			builder = builder.WithParameter("over_approximated", true)
			}
		}

		// Write to remote destination (dangerous)
		builder.AddWriteOperation("network:"+s.getRemoteHost(cmd.Destination)+":"+s.getRemotePort(cmd)+"/"+s.getRemotePath(cmd.Destination), "remote_write")
			
			builder = builder.WithParameter("command", "scp")
			
			builder = builder.WithParameter("operation", "copy_remote_to_remote")
			
			builder = builder.WithParameter("dangerous", true)
			
			builder = builder.WithParameter("high_risk", true)

		// If recursive, write directory contents
		if cmd.Recursive {
			builder.AddWriteOperation("network:"+s.getRemoteHost(cmd.Destination)+":"+s.getRemotePort(cmd)+"/"+s.getRemotePath(cmd.Destination)+"/*", "recursive_remote_write")
				
			builder = builder.WithParameter("command", "scp")
				
			builder = builder.WithParameter("operation", "copy_remote_to_remote")
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("high_risk", true)
				
			builder = builder.WithParameter("over_approximated", true)
		}
	}

	// Handle verbose output
	if cmd.Verbose {
		builder.AddWriteOperation("/dev/stdout", "verbose_output")
			
			builder = builder.WithParameter("command", "scp")
			
			builder = builder.WithParameter("verbose", true)
	}

	// Handle quiet mode
	if cmd.Quiet {
		builder.AddReadOperation("/dev/null", "quiet_suppression")
			
			builder = builder.WithParameter("command", "scp")
			
			builder = builder.WithParameter("quiet", true)
	}

	operations = builder.Build()

	return operations, nil
}

// getRemoteHost extracts the host from a remote path (user@host:path)
func (s *ScpParser) getRemoteHost(path string) string {
	if strings.Contains(path, "@") {
		parts := strings.Split(path, "@")
		if len(parts) > 1 {
			return strings.Split(parts[1], ":")[0]
		}
	}
	return ""
}

// getRemotePort returns the port for the SCP connection
func (s *ScpParser) getRemotePort(cmd *ScpCommand) string {
	if cmd.Port != "" {
		return cmd.Port
	}
	return "22" // Default SSH/SCP port
}

// getRemotePath extracts the path from a remote path (user@host:path)
func (s *ScpParser) getRemotePath(path string) string {
	if strings.Contains(path, ":") {
		parts := strings.Split(path, ":")
		if len(parts) > 1 {
			return strings.Join(parts[1:], ":")
		}
	}
	return path
}

// isDirectory checks if a path is likely a directory (simple heuristic)
func (s *ScpParser) isDirectory(path string) bool {
	return strings.HasSuffix(path, "/") || !strings.Contains(path, ".")
}
// GetOperationGraph implements the enhanced CommandParser interface for scp commands
func (p *ScpParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*ScpCommand)
	if !ok {
		return nil, fmt.Errorf("invalid scp command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("scp", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for scp commands
