package semantic

import (
	"fmt"
	"strings"
)

// NcCommand represents a parsed nc (netcat) command
type NcCommand struct {
	Options     map[string]interface{}
	Operation   string // "listen", "connect", "scan"
	Listen      bool   // -l listen mode
	Verbose     bool   // -v verbose
	VeryVerbose bool   // -vv very verbose
	TCP         bool   // -t TCP (default)
	UDP         bool   // -u UDP
	Numeric     bool   // -n numeric only (no DNS)
	KeepOpen    bool   // -k keep listening
	Zero        bool   // -z zero-I/O mode (scan)
	Interval    string // -i interval
	Timeout     string // -w timeout
	SourcePort  string // -p source port
	SourceAddr  string // -s source address
	TargetHost  string
	TargetPort  string
	Command     string // -e execute command
}

// NcParser parses nc (netcat) commands
type NcParser struct {
	utils *ParserUtils
}

// NewNcParser creates a new NcParser
func NewNcParser() *NcParser {
	return &NcParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for nc commands
func (n *NcParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for nc parser")
	}

	cmd := &NcCommand{
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
		case "-l", "--listen":
			cmd.Listen = true
			cmd.Options["listen"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "-vv":
			cmd.VeryVerbose = true
			cmd.Options["very_verbose"] = true
		case "-t", "--tcp":
			cmd.TCP = true
			cmd.Options["tcp"] = true
		case "-u", "--udp":
			cmd.UDP = true
			cmd.Options["udp"] = true
		case "-n", "--numeric":
			cmd.Numeric = true
			cmd.Options["numeric"] = true
		case "-k", "--keep-open":
			cmd.KeepOpen = true
			cmd.Options["keep_open"] = true
		case "-z", "--zero":
			cmd.Zero = true
			cmd.Options["zero"] = true
		case "-i":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing interval after -i")
			}
			cmd.Interval = args[i+1]
			cmd.Options["interval"] = args[i+1]
			i += 2
			continue
		case "-w":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing timeout after -w")
			}
			cmd.Timeout = args[i+1]
			cmd.Options["timeout"] = args[i+1]
			i += 2
			continue
		case "-p":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing port after -p")
			}
			cmd.SourcePort = args[i+1]
			cmd.Options["source_port"] = args[i+1]
			i += 2
			continue
		case "-s":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing address after -s")
			}
			cmd.SourceAddr = args[i+1]
			cmd.Options["source_address"] = args[i+1]
			i += 2
			continue
		case "-e", "--exec":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing command after -e")
			}
			cmd.Command = args[i+1]
			cmd.Options["exec"] = args[i+1]
			i += 2
			continue
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'l':
						cmd.Listen = true
					case 'v':
						cmd.Verbose = true
					case 'u':
						cmd.UDP = true
					case 'n':
						cmd.Numeric = true
					case 'k':
						cmd.KeepOpen = true
					case 'z':
						cmd.Zero = true
					}
				}
			}
		}
		i++
	}

	// Parse target host and port
	if i < len(args) {
		arg := args[i]
		i++

		// Check if it's a port only (listening mode)
		if cmd.Listen {
			if n.isPortNumber(arg) {
				cmd.TargetPort = arg
			} else {
				cmd.TargetHost = arg
			}
		} else {
			// Connection mode
			if strings.Contains(arg, ":") {
				// host:port format
				parts := strings.SplitN(arg, ":", 2)
				cmd.TargetHost = parts[0]
				if len(parts) > 1 {
					cmd.TargetPort = parts[1]
				}
			} else {
				// Just a host, port might be next
				cmd.TargetHost = arg
			}
		}
	}

	// If port is still not set and we have more args
	if cmd.TargetPort == "" && i < len(args) {
		if n.isPortNumber(args[i]) {
			cmd.TargetPort = args[i]
		}
	}

	// Determine operation type
	if cmd.Listen {
		cmd.Operation = "listen"
	} else if cmd.Zero {
		cmd.Operation = "scan"
	} else if cmd.Command != "" {
		cmd.Operation = "exec"
	} else {
		cmd.Operation = "connect"
	}

	return cmd, nil
}

// isPortNumber checks if a string is a valid port number
func (n *NcParser) isPortNumber(s string) bool {
	if len(s) == 0 || len(s) > 5 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// GetSemanticOperations implements CommandParser for nc commands
func (n *NcParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*NcCommand)
	if !ok {
		return nil, fmt.Errorf("invalid nc command type")
	}

	builder := n.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	// nc is a network tool - always involves network operations
	target := cmd.TargetHost
	if cmd.TargetPort != "" {
		if target != "" {
			target += ":" + cmd.TargetPort
		} else {
			target = ":" + cmd.TargetPort
		}
	}

	switch cmd.Operation {
	case "listen":
		// Listening mode - creating a server
		if target != "" {
			builder.AddCreateOperation("network:+"+target, "nc_listen")
			builder = builder.WithParameter("command", "nc")
			builder = builder.WithParameter("operation", "listen")
			builder = builder.WithParameter("protocol", n.getProtocol(cmd))
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)
		} else {
			builder.AddCreateOperation("network:*", "nc_listen_any")
			builder = builder.WithParameter("command", "nc")
			builder = builder.WithParameter("operation", "listen")
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)
		}

		// If keep-open is set, we might have multiple connections
		if cmd.KeepOpen {
			builder.AddCreateOperation("network:*/*", "nc_multiple_connections")
			builder = builder.WithParameter("command", "nc")
			builder = builder.WithParameter("keep_open", true)
			builder = builder.WithParameter("over_approximated", true)
		}

	case "connect":
		// Connection mode - connect to remote
		if target != "" {
			builder.AddReadOperation("network:"+target, "nc_connect_read")
			builder = builder.WithParameter("command", "nc")
			builder = builder.WithParameter("operation", "connect")
			builder = builder.WithParameter("protocol", n.getProtocol(cmd))
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)

			builder.AddWriteOperation("network:"+target, "nc_connect_write")
			builder = builder.WithParameter("command", "nc")
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)
		}

	case "scan":
		// Scanning mode - check ports
		if target != "" {
			builder.AddReadOperation("network:"+target+"/scan", "nc_port_scan")
			builder = builder.WithParameter("command", "nc")
			builder = builder.WithParameter("operation", "scan")
			builder = builder.WithParameter("protocol", n.getProtocol(cmd))
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)
			builder = builder.WithParameter("over_approximated", true)
		}

	case "exec":
		// Execute mode - very dangerous
		if target != "" {
			builder.AddReadOperation("network:"+target, "nc_exec_connection")
			builder = builder.WithParameter("command", "nc")
			builder = builder.WithParameter("operation", "exec")
			builder = builder.WithParameter("protocol", n.getProtocol(cmd))
			builder = builder.WithParameter("dangerous", true)
			builder = builder.WithParameter("high_risk", true)
			builder = builder.WithParameter("command", cmd.Command)
		}

		// The execution itself
		builder.AddWriteOperation("exec:"+cmd.Command, "nc_command_exec")
		builder = builder.WithParameter("command", "nc")
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)
		builder = builder.WithParameter("over_approximated", true)
	}

	// Handle source port
	if cmd.SourcePort != "" {
		builder.AddWriteOperation("network:localhost:"+cmd.SourcePort, "nc_source_port")
		builder = builder.WithParameter("command", "nc")
		builder = builder.WithParameter("source_port", cmd.SourcePort)
		builder = builder.WithParameter("dangerous", true)
	}

	// Handle source address
	if cmd.SourceAddr != "" {
		builder.AddReadOperation("network:"+cmd.SourceAddr, "nc_source_address")
		builder = builder.WithParameter("command", "nc")
		builder = builder.WithParameter("source_address", cmd.SourceAddr)
		builder = builder.WithParameter("dangerous", true)
	}

	// Handle verbose output
	if cmd.Verbose || cmd.VeryVerbose {
		builder.AddWriteOperation("/dev/stdout", "nc_verbose_output")
		builder = builder.WithParameter("command", "nc")
		builder = builder.WithParameter("verbose", true)
	}

	operations = builder.Build()

	return operations, nil
}

// getProtocol returns the protocol being used
func (n *NcParser) getProtocol(cmd *NcCommand) string {
	if cmd.UDP {
		return "UDP"
	}
	return "TCP"
}

// GetOperationGraph implements the enhanced CommandParser interface for nc commands
func (p *NcParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*NcCommand)
	if !ok {
		return nil, fmt.Errorf("invalid nc command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("nc", operations, []SemanticOperation{})

	return graph, nil
}
