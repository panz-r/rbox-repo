package semantic

import (
	"fmt"
	"strings"
)

// SshCommand represents a parsed ssh command
type SshCommand struct {
	Options     map[string]interface{}
	User        string
	Host        string
	Port        string
	Command     string
	IdentityFile string
	ConfigFile  string
	Verbose     bool
	Quiet       bool
	StrictHostKeyChecking bool
	ForwardAgent bool
	ForwardX11   bool
}

// SshParser parses ssh commands
type SshParser struct {
	utils *ParserUtils
}

// NewSshParser creates a new SshParser
func NewSshParser() *SshParser {
	return &SshParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for ssh commands
func (s *SshParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for ssh parser")
	}

	cmd := &SshCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-p":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing port after -p")
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
		case "-F":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing config file after -F")
			}
			cmd.ConfigFile = args[i+1]
			cmd.Options["config_file"] = args[i+1]
			i += 2
			continue
		case "-l":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing user after -l")
			}
			cmd.User = args[i+1]
			cmd.Options["user"] = args[i+1]
			i += 2
			continue
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "-q", "--quiet":
			cmd.Quiet = true
			cmd.Options["quiet"] = true
		case "-o":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing option after -o")
			}
			option := args[i+1]
			if strings.Contains(option, "StrictHostKeyChecking=") {
				cmd.StrictHostKeyChecking = strings.Contains(option, "=yes")
				cmd.Options["strict_host_key_checking"] = cmd.StrictHostKeyChecking
			} else if strings.Contains(option, "ForwardAgent=") {
				cmd.ForwardAgent = strings.Contains(option, "=yes")
				cmd.Options["forward_agent"] = cmd.ForwardAgent
			} else if strings.Contains(option, "ForwardX11=") {
				cmd.ForwardX11 = strings.Contains(option, "=yes")
				cmd.Options["forward_x11"] = cmd.ForwardX11
			}
			i += 2
			continue
		case "-A":
			cmd.ForwardAgent = true
			cmd.Options["forward_agent"] = true
		case "-X":
			cmd.ForwardX11 = true
			cmd.Options["forward_x11"] = true
		case "--":
			i++
			break
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'v':
						cmd.Verbose = true
						cmd.Options["verbose"] = true
					case 'q':
						cmd.Quiet = true
						cmd.Options["quiet"] = true
					case 'A':
						cmd.ForwardAgent = true
						cmd.Options["forward_agent"] = true
					case 'X':
						cmd.ForwardX11 = true
						cmd.Options["forward_x11"] = true
					}
				}
			}
		}
		i++
	}

	// Parse user@host
	if i < len(args) {
		hostArg := args[i]
		if strings.Contains(hostArg, "@") {
			parts := strings.Split(hostArg, "@")
			cmd.User = parts[0]
			cmd.Host = parts[1]
			cmd.Options["user"] = parts[0]
			cmd.Options["host"] = parts[1]
		} else {
			cmd.Host = hostArg
			cmd.Options["host"] = hostArg
		}
		i++
	} else {
		return nil, fmt.Errorf("missing host specification")
	}

	// Parse command
	if i < len(args) {
		cmd.Command = strings.Join(args[i:], " ")
		cmd.Options["command"] = cmd.Command
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for ssh commands
func (s *SshParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*SshCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ssh command type")
	}

	builder := s.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	// SSH always reads configuration and known hosts
	builder.AddReadOperation("/etc/ssh/ssh_config", "ssh_config")
		
			builder = builder.WithParameter("command", "ssh")
		
			builder = builder.WithParameter("over_approximated", true)

	builder.AddReadOperation("~/.ssh/known_hosts", "known_hosts")
		
			builder = builder.WithParameter("command", "ssh")
		
			builder = builder.WithParameter("over_approximated", true)

	// Read user-specific config if specified
	if cmd.ConfigFile != "" {
		builder.AddReadOperation(cmd.ConfigFile, "user_config")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("precise", true)
	} else {
		builder.AddReadOperation("~/.ssh/config", "default_user_config")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
	}

	// Read identity file if specified
	if cmd.IdentityFile != "" {
		builder.AddReadOperation(cmd.IdentityFile, "identity_file")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("precise", true)
			
			builder = builder.WithParameter("dangerous", true) // Identity files are sensitive
	} else {
		builder.AddReadOperation("~/.ssh/id_rsa", "default_identity")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("dangerous", true)

		builder.AddReadOperation("~/.ssh/id_dsa", "default_identity_dsa")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("dangerous", true)

		builder.AddReadOperation("~/.ssh/id_ecdsa", "default_identity_ecdsa")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("dangerous", true)

		builder.AddReadOperation("~/.ssh/id_ed25519", "default_identity_ed25519")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("dangerous", true)
	}

	// SSH connects to remote host - this is a network operation
	if cmd.Host != "" {
		builder.AddReadOperation("network:"+cmd.Host+":"+s.getPort(cmd), "network_connection")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("host", cmd.Host)
			
			builder = builder.WithParameter("user", cmd.User)
			
			builder = builder.WithParameter("dangerous", true) // Network connections are dangerous
			
			builder = builder.WithParameter("over_approximated", true)

		// If a command is specified, execute it remotely
		if cmd.Command != "" {
			builder.AddWriteOperation("network:"+cmd.Host+":"+s.getPort(cmd)+"/exec", "remote_command")
				
			builder = builder.WithParameter("command", "ssh")
				
			builder = builder.WithParameter("remote_command", cmd.Command)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("high_risk", true) // Remote command execution is high risk
				
			builder = builder.WithParameter("over_approximated", true)

			// Remote command might read/write files on remote system (conservative)
			builder.AddReadOperation("network:"+cmd.Host+":"+s.getPort(cmd)+"/fs/*", "remote_filesystem_read")
				
			builder = builder.WithParameter("command", "ssh")
				
			builder = builder.WithParameter("over_approximated", true)
				
			builder = builder.WithParameter("dangerous", true)

			builder.AddWriteOperation("network:"+cmd.Host+":"+s.getPort(cmd)+"/fs/*", "remote_filesystem_write")
				
			builder = builder.WithParameter("command", "ssh")
				
			builder = builder.WithParameter("over_approximated", true)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("high_risk", true)
		}

		// SSH might create temporary files
		builder.AddCreateOperation("/tmp/ssh*", "temp_files")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
	}

	// Handle agent forwarding
	if cmd.ForwardAgent {
		builder.AddReadOperation("/tmp/ssh-*", "agent_socket")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("dangerous", true)

		builder.AddWriteOperation("/tmp/ssh-*", "agent_socket_create")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("dangerous", true)
	}

	// Handle X11 forwarding
	if cmd.ForwardX11 {
		builder.AddReadOperation("/tmp/.X11-unix/*", "x11_socket")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)

		builder.AddWriteOperation("/tmp/.X11-unix/*", "x11_socket_create")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("over_approximated", true)
	}

	// Handle verbose output
	if cmd.Verbose {
		builder.AddWriteOperation("/dev/stdout", "verbose_output")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("verbose", true)
	}

	// Handle quiet mode
	if cmd.Quiet {
		builder.AddReadOperation("/dev/null", "quiet_suppression")
			
			builder = builder.WithParameter("command", "ssh")
			
			builder = builder.WithParameter("quiet", true)
	}

	operations = builder.Build()

	return operations, nil
}

// getPort returns the port for the SSH connection
func (s *SshParser) getPort(cmd *SshCommand) string {
	if cmd.Port != "" {
		return cmd.Port
	}
	return "22" // Default SSH port
}
// GetOperationGraph implements the enhanced CommandParser interface for ssh commands
func (p *SshParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*SshCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ssh command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("ssh", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for ssh commands
