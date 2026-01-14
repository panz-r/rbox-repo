package semantic

import (
	"fmt"
	"strings"
)

// RsyncCommand represents a parsed rsync command
type RsyncCommand struct {
	Options        map[string]interface{}
	Sources        []string
	Destination    string
	Operation      string // "local", "push", "pull", "daemon"
	Recursive      bool
	Archive        bool
	DryRun         bool
	Verbose        bool
	Quiet          bool
	Delete         bool
	Exclude        []string
	Include        []string
	bwlimit        string
	port           string
	progress       bool
	partial        bool
	force          bool
	existing       bool
	ignoreExisting bool
	update         bool
}

// RsyncParser parses rsync commands
type RsyncParser struct {
	utils *ParserUtils
}

// NewRsyncParser creates a new RsyncParser
func NewRsyncParser() *RsyncParser {
	return &RsyncParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for rsync commands
func (r *RsyncParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for rsync parser")
	}

	cmd := &RsyncCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-r", "--recursive":
			cmd.Recursive = true
			cmd.Options["recursive"] = true
		case "-a", "--archive":
			cmd.Archive = true
			cmd.Options["archive"] = true
		case "-n", "--dry-run":
			cmd.DryRun = true
			cmd.Options["dry_run"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "-q", "--quiet":
			cmd.Quiet = true
			cmd.Options["quiet"] = true
		case "--delete":
			cmd.Delete = true
			cmd.Options["delete"] = true
		case "--bwlimit":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing value after --bwlimit")
			}
			cmd.bwlimit = args[i+1]
			cmd.Options["bwlimit"] = args[i+1]
			i += 2
			continue
		case "--port":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing value after --port")
			}
			cmd.port = args[i+1]
			cmd.Options["port"] = args[i+1]
			i += 2
			continue
		case "--progress":
			cmd.progress = true
			cmd.Options["progress"] = true
		case "--partial":
			cmd.partial = true
			cmd.Options["partial"] = true
		case "-f", "--force":
			cmd.force = true
			cmd.Options["force"] = true
		case "--existing":
			cmd.existing = true
			cmd.Options["existing"] = true
		case "--ignore-existing":
			cmd.ignoreExisting = true
			cmd.Options["ignore_existing"] = true
		case "-u", "--update":
			cmd.update = true
			cmd.Options["update"] = true
		case "--exclude":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing pattern after --exclude")
			}
			cmd.Exclude = append(cmd.Exclude, args[i+1])
			cmd.Options["exclude"] = args[i+1]
			i += 2
			continue
		case "--include":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing pattern after --include")
			}
			cmd.Include = append(cmd.Include, args[i+1])
			cmd.Options["include"] = args[i+1]
			i += 2
			continue
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'r':
						cmd.Recursive = true
					case 'a':
						cmd.Archive = true
					case 'n':
						cmd.DryRun = true
					case 'v':
						cmd.Verbose = true
					case 'q':
						cmd.Quiet = true
					case 'u':
						cmd.update = true
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
			return nil, fmt.Errorf("missing destination for rsync command")
		}
	} else {
		return nil, fmt.Errorf("missing source and destination for rsync command")
	}

	// Determine operation type
	if len(cmd.Sources) > 0 && len(cmd.Destination) > 0 {
		if r.isRemotePath(cmd.Sources[0]) && r.isRemotePath(cmd.Destination) {
			cmd.Operation = "daemon"
		} else if r.isRemotePath(cmd.Destination) {
			cmd.Operation = "push"
		} else if r.isRemotePath(cmd.Sources[0]) {
			cmd.Operation = "pull"
		} else {
			cmd.Operation = "local"
		}
	}

	return cmd, nil
}

// isRemotePath checks if a path is a remote path (user@host:path or ::)
func (r *RsyncParser) isRemotePath(path string) bool {
	return strings.Contains(path, "@") && strings.Contains(path, ":") ||
		strings.HasSuffix(path, "::")
}

// GetSemanticOperations implements CommandParser for rsync commands
func (r *RsyncParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*RsyncCommand)
	if !ok {
		return nil, fmt.Errorf("invalid rsync command type")
	}

	builder := r.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	// rsync is always dangerous - it can copy/move files
	// Handle different operation types
	switch cmd.Operation {
	case "local":
		// Local copy operation
		for _, source := range cmd.Sources {
			// Read source
			builder.AddReadOperation(source, "local_source_read")
			builder = builder.WithParameter("command", "rsync")
			builder = builder.WithParameter("operation", "local")
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("precise", true)

			// If recursive or archive, read directory contents
			if cmd.Recursive || cmd.Archive {
				builder.AddReadOperation(source+"/*", "local_source_recursive")
				builder = builder.WithParameter("command", "rsync")
				builder = builder.WithParameter("over_approximated", true)
			}
		}

		// Write to destination
		builder.AddWriteOperation(cmd.Destination, "local_destination_write")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("operation", "local")
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("precise", true)

		// If recursive, write directory contents
		if cmd.Recursive || cmd.Archive {
			builder.AddWriteOperation(cmd.Destination+"/*", "local_destination_recursive")
			builder = builder.WithParameter("command", "rsync")
			builder = builder.WithParameter("over_approximated", true)
		}

	case "push":
		// Push to remote - read local, write to remote
		for _, source := range cmd.Sources {
			builder.AddReadOperation(source, "local_source_read")
			builder = builder.WithParameter("command", "rsync")
			builder = builder.WithParameter("operation", "push")
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)

			if cmd.Recursive || cmd.Archive {
				builder.AddReadOperation(source+"/*", "local_source_recursive")
				builder = builder.WithParameter("command", "rsync")
				builder = builder.WithParameter("over_approximated", true)
			}
		}

		// Write to remote destination
		builder.AddWriteOperation("network:"+r.getRemoteHost(cmd.Destination)+"/"+r.getRemotePath(cmd.Destination), "remote_destination_write")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("operation", "push")
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)

		if cmd.Recursive || cmd.Archive {
			builder.AddWriteOperation("network:"+r.getRemoteHost(cmd.Destination)+"/"+r.getRemotePath(cmd.Destination)+"/*", "remote_destination_recursive")
			builder = builder.WithParameter("command", "rsync")
			builder = builder.WithParameter("over_approximated", true)
		}

	case "pull":
		// Pull from remote - read remote, write local
		for _, source := range cmd.Sources {
			builder.AddReadOperation("network:"+r.getRemoteHost(source)+"/"+r.getRemotePath(source), "remote_source_read")
			builder = builder.WithParameter("command", "rsync")
			builder = builder.WithParameter("operation", "pull")
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)

			if cmd.Recursive || cmd.Archive {
				builder.AddReadOperation("network:"+r.getRemoteHost(source)+"/"+r.getRemotePath(source)+"/*", "remote_source_recursive")
				builder = builder.WithParameter("command", "rsync")
				builder = builder.WithParameter("over_approximated", true)
			}
		}

		// Write to local destination
		builder.AddWriteOperation(cmd.Destination, "local_destination_write")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("operation", "pull")
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("precise", true)

		if cmd.Recursive || cmd.Archive {
			builder.AddWriteOperation(cmd.Destination+"/*", "local_destination_recursive")
			builder = builder.WithParameter("command", "rsync")
			builder = builder.WithParameter("over_approximated", true)
		}

	case "daemon":
		// Daemon mode - remote to remote
		for _, source := range cmd.Sources {
			builder.AddReadOperation("network:"+r.getRemoteHost(source)+"/"+r.getRemotePath(source), "remote_source_read")
			builder = builder.WithParameter("command", "rsync")
			builder = builder.WithParameter("operation", "daemon")
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)
		}

		builder.AddWriteOperation("network:"+r.getRemoteHost(cmd.Destination)+"/"+r.getRemotePath(cmd.Destination), "remote_destination_write")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("operation", "daemon")
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)
	}

	// Handle delete option - very dangerous
	if cmd.Delete {
		builder.AddWriteOperation("*", "rsync_delete")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("delete", true)
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)
		builder = builder.WithParameter("over_approximated", true)
	}

	// Handle force option
	if cmd.force {
		builder.AddWriteOperation(cmd.Destination, "rsync_force")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("force", true)
		builder = builder.WithParameter("over_approximated", true)
	}

	// Handle partial option - might leave partial files
	if cmd.partial {
		builder.AddCreateOperation(cmd.Destination+".partial", "rsync_partial")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("over_approximated", true)
	}

	// Handle verbose output
	if cmd.Verbose {
		builder.AddWriteOperation("/dev/stdout", "verbose_output")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("verbose", true)
	}

	// Handle quiet mode
	if cmd.Quiet {
		builder.AddReadOperation("/dev/null", "quiet_suppression")
		builder = builder.WithParameter("command", "rsync")
		builder = builder.WithParameter("quiet", true)
	}

	operations = builder.Build()

	return operations, nil
}

// getRemoteHost extracts the host from a remote path (user@host:path)
func (r *RsyncParser) getRemoteHost(path string) string {
	if strings.Contains(path, "@") {
		parts := strings.Split(path, "@")
		if len(parts) > 1 {
			hostParts := strings.Split(parts[1], ":")
			return hostParts[0]
		}
	}
	return ""
}

// getRemotePath extracts the path from a remote path (user@host:path)
func (r *RsyncParser) getRemotePath(path string) string {
	if strings.Contains(path, ":") {
		parts := strings.SplitN(path, ":", 2)
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return path
}

// GetOperationGraph implements the enhanced CommandParser interface for rsync commands
func (p *RsyncParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*RsyncCommand)
	if !ok {
		return nil, fmt.Errorf("invalid rsync command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("rsync", operations, []SemanticOperation{})

	return graph, nil
}
