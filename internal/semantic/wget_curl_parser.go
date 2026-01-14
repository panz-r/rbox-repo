package semantic

import (
	"fmt"
	"strings"
)

// WgetCurlCommand represents a parsed wget or curl command
type WgetCurlCommand struct {
	CommandType string // "wget" or "curl"
	Options     map[string]interface{}
	Urls        []string
	OutputFile  string
	Quiet       bool
	Verbose     bool
	Follow      bool
	UserAgent   string
	Headers     []string
	PostData    string
	Insecure    bool
	Location    bool
	LimitRate   string
}

// WgetCurlParser parses wget and curl commands
type WgetCurlParser struct {
	utils *ParserUtils
}

// NewWgetCurlParser creates a new WgetCurlParser
func NewWgetCurlParser() *WgetCurlParser {
	return &WgetCurlParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for wget/curl commands
func (w *WgetCurlParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for wget/curl parser")
	}

	cmd := &WgetCurlCommand{
		CommandType: args[0], // "wget" or "curl"
		Options:     make(map[string]interface{}),
	}

	i := 1
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-O", "--output-document":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing output file after -O")
			}
			cmd.OutputFile = args[i+1]
			cmd.Options["output"] = args[i+1]
			i += 2
			continue
		case "-q", "--quiet":
			cmd.Quiet = true
			cmd.Options["quiet"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "-L", "--location":
			cmd.Follow = true
			cmd.Options["follow"] = true
		case "--user-agent":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing user agent after --user-agent")
			}
			cmd.UserAgent = args[i+1]
			cmd.Options["user_agent"] = args[i+1]
			i += 2
			continue
		case "-H", "--header":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing header after -H")
			}
			cmd.Headers = append(cmd.Headers, args[i+1])
			cmd.Options["header"] = args[i+1]
			i += 2
			continue
		case "-d", "--data":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing data after -d")
			}
			cmd.PostData = args[i+1]
			cmd.Options["post_data"] = args[i+1]
			i += 2
			continue
		case "-k", "--insecure":
			cmd.Insecure = true
			cmd.Options["insecure"] = true
		case "--limit-rate":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing rate after --limit-rate")
			}
			cmd.LimitRate = args[i+1]
			cmd.Options["limit_rate"] = args[i+1]
			i += 2
			continue
		case "--":
			i++
			break
		default:
			// Handle curl-specific options
			if cmd.CommandType == "curl" {
				switch opt {
				case "-X", "--request":
					if i+1 >= len(args) {
						return nil, fmt.Errorf("missing request method after -X")
					}
					cmd.Options["method"] = args[i+1]
					i += 2
					continue
				case "-I", "--head":
					cmd.Options["head"] = true
				case "-o", "--output":
					if i+1 >= len(args) {
						return nil, fmt.Errorf("missing output file after -o")
					}
					cmd.OutputFile = args[i+1]
					cmd.Options["output"] = args[i+1]
					i += 2
					continue
				}
			}

			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'q':
						cmd.Quiet = true
						cmd.Options["quiet"] = true
					case 'v':
						cmd.Verbose = true
						cmd.Options["verbose"] = true
					case 'L':
						cmd.Follow = true
						cmd.Options["follow"] = true
					case 'k':
						cmd.Insecure = true
						cmd.Options["insecure"] = true
					}
				}
			}
		}
		i++
	}

	// Parse URLs
	if i < len(args) {
		cmd.Urls = args[i:]
	} else {
		return nil, fmt.Errorf("missing URL for %s command", cmd.CommandType)
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for wget/curl commands
func (w *WgetCurlParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*WgetCurlCommand)
	if !ok {
		return nil, fmt.Errorf("invalid wget/curl command type")
	}

	builder := w.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	// Network operations - read from URLs
	for _, url := range cmd.Urls {
		builder.AddReadOperation("network:"+url, "url_read")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("url", url)
			
			builder = builder.WithParameter("dangerous", true) // Network reads are dangerous
			
			builder = builder.WithParameter("over_approximated", true)

		// If following redirects
		if cmd.Follow {
			builder.AddReadOperation("network:"+url+"/redirects/*", "redirect_read")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("over_approximated", true)
				
			builder = builder.WithParameter("dangerous", true)
		}

		// If POST data is provided
		if cmd.PostData != "" {
			builder.AddWriteOperation("network:"+url, "post_write")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("post_data", cmd.PostData)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("high_risk", true) // POST requests can modify data
		}

		// If insecure mode is enabled
		if cmd.Insecure {
			builder.AddReadOperation("network:"+url, "insecure_read")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("insecure", true)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("high_risk", true) // Insecure connections are high risk
		}

		// Write to output file if specified
		if cmd.OutputFile != "" {
			builder.AddWriteOperation(cmd.OutputFile, "output_write")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
		} else {
			// If no output file, might write to current directory
			builder.AddWriteOperation("./*", "default_output_write")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("over_approximated", true)
				
			builder = builder.WithParameter("dangerous", true)
		}

		// Might create temporary files
		builder.AddCreateOperation("/tmp/*", "temp_files")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("over_approximated", true)
	}

	// Handle verbose output
	if cmd.Verbose {
		builder.AddWriteOperation("/dev/stdout", "verbose_output")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("verbose", true)
	}

	// Handle quiet mode
	if cmd.Quiet {
		builder.AddReadOperation("/dev/null", "quiet_suppression")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("quiet", true)
	}

	// Handle rate limiting
	if cmd.LimitRate != "" {
		builder.AddReadOperation("/proc/net/*", "network_monitoring")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("limit_rate", cmd.LimitRate)
			
			builder = builder.WithParameter("over_approximated", true)
	}

	// Handle custom headers
	for _, header := range cmd.Headers {
		builder.AddWriteOperation("network:*", "custom_header")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("header", header)
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("dangerous", true)
	}

	// Handle user agent
	if cmd.UserAgent != "" {
		builder.AddWriteOperation("network:*", "custom_user_agent")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("user_agent", cmd.UserAgent)
			
			builder = builder.WithParameter("over_approximated", true)
	}

	operations = builder.Build()

	return operations, nil
}
// GetOperationGraph implements the enhanced CommandParser interface for wget commands
func (p *WgetCurlParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*WgetCurlCommand)
	if !ok {
		return nil, fmt.Errorf("invalid wget command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("wget", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for wget commands
