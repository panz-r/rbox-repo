package semantic

import (
	"fmt"
	"strings"
)

// EchoCommand represents a parsed echo command
type EchoCommand struct {
	Text      string
	Options   map[string]interface{}
	NoNewline bool
	EnableInterpretation bool
	DisableInterpretation bool
}

// DateCommand represents a parsed date command
type DateCommand struct {
	Format    string
	Options   map[string]interface{}
	UTC       bool
	Reference string
	ISO8601   bool
	RFC3339   bool
}

// WhoamiCommand represents a parsed whoami command
type WhoamiCommand struct {
	Options map[string]interface{}
}

// EchoDateWhoamiParser parses echo, date, and whoami commands
type EchoDateWhoamiParser struct {
	commandType string // "echo", "date", or "whoami"
}

// ParseArguments implements CommandParser for echo/date/whoami commands
func (e *EchoDateWhoamiParser) ParseArguments(args []string) (interface{}, error) {
	if e.commandType == "echo" {
		return e.parseEchoCommand(args)
	} else if e.commandType == "date" {
		return e.parseDateCommand(args)
	} else if e.commandType == "whoami" {
		return e.parseWhoamiCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", e.commandType)
}

func (e *EchoDateWhoamiParser) parseEchoCommand(args []string) (*EchoCommand, error) {
	cmd := &EchoCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]
		if opt == "--" {
			i++
			break
		}

		switch opt {
		case "-n":
			cmd.NoNewline = true
			cmd.Options["no_newline"] = true
			i++

		case "-e":
			cmd.EnableInterpretation = true
			cmd.Options["enable_interpretation"] = true
			i++

		case "-E":
			cmd.DisableInterpretation = true
			cmd.Options["disable_interpretation"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown echo option: %s", opt)
		}
	}

	// Parse text arguments
	if i < len(args) {
		cmd.Text = strings.Join(args[i:], " ")
	}

	return cmd, nil
}

func (e *EchoDateWhoamiParser) parseDateCommand(args []string) (*DateCommand, error) {
	cmd := &DateCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]
		if opt == "--" {
			i++
			break
		}

		switch opt {
		case "-u", "--utc", "--universal":
			cmd.UTC = true
			cmd.Options["utc"] = true
			i++

		case "-r", "--reference":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Reference = args[i+1]
			cmd.Options["reference"] = args[i+1]
			i += 2

		case "--iso-8601":
			cmd.ISO8601 = true
			cmd.Options["iso_8601"] = true
			i++

		case "--rfc-3339":
			cmd.RFC3339 = true
			cmd.Options["rfc_3339"] = true
			i++

		default:
			// Handle format options
			if opt == "+" || (len(opt) > 1 && opt[0] == '+' && opt[1] != '-') {
				cmd.Format = opt
				cmd.Options["format"] = opt
				i++
			} else if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				// Handle combined short options
				for _, ch := range opt[1:] {
					switch ch {
					case 'u':
						cmd.UTC = true
					case 'r':
						// -r requires argument, handle separately
						if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
							cmd.Reference = args[i+1]
							cmd.Options["reference"] = args[i+1]
							i++
						}
					}
				}
				i++
			} else {
				return nil, fmt.Errorf("unknown date option: %s", opt)
			}
		}
	}

	// Parse format argument if not already set
	if i < len(args) && cmd.Format == "" && !strings.HasPrefix(args[i], "-") {
		cmd.Format = args[i]
		i++
	}

	return cmd, nil
}

func (e *EchoDateWhoamiParser) parseWhoamiCommand(args []string) (*WhoamiCommand, error) {
	cmd := &WhoamiCommand{
		Options: make(map[string]interface{}),
	}

	// whoami typically doesn't take options or arguments
	if len(args) > 0 {
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") {
				// Handle potential options
				if arg == "--help" || arg == "--version" {
					cmd.Options[arg] = true
				} else {
					return nil, fmt.Errorf("unknown whoami option: %s", arg)
				}
			} else {
				// whoami doesn't typically take non-option arguments
				return nil, fmt.Errorf("unexpected argument: %s", arg)
			}
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for echo/date/whoami commands
func (e *EchoDateWhoamiParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if echoCmd, ok := parsed.(*EchoCommand); ok {
		// Echo doesn't read files, but may read environment variables if interpretation is enabled
		if echoCmd.EnableInterpretation {
			builder.AddReadOperation("/proc/environment", "environment_variables")
			builder.WithCommandInfo("echo")
			builder.WithParameter("enable_interpretation", true)
			builder.WithOverApproximated() // Environment reading is over-approximated
		}

		// Add parameters for echo behavior
		builder.AddReadOperation("/dev/stdout", "output")
		builder.WithCommandInfo("echo")
		builder.WithParameter("no_newline", echoCmd.NoNewline)
		builder.WithParameter("disable_interpretation", echoCmd.DisableInterpretation)
		builder.WithSafe() // Echo is generally safe

		// If text contains variables and interpretation is enabled, mark as less safe
		if echoCmd.EnableInterpretation && strings.Contains(echoCmd.Text, "$") {
			builder.WithParameter("contains_variables", true)
			builder.WithOverApproximated()
		}
	} else if dateCmd, ok := parsed.(*DateCommand); ok {
		// Date reads system time information
		builder.AddReadOperation("/proc/sys/kernel/rtc/time", "system_time")
		builder.WithCommandInfo("date")

		// Add parameters for date options
		if dateCmd.UTC {
			builder.WithParameter("utc", true)
		}
		if dateCmd.Format != "" {
			builder.WithParameter("format", dateCmd.Format)
		}
		if dateCmd.ISO8601 {
			builder.WithParameter("iso_8601", true)
		}
		if dateCmd.RFC3339 {
			builder.WithParameter("rfc_3339", true)
		}

		builder.WithOverApproximated() // System time reading is over-approximated
		builder.WithSafe() // Date is generally safe
	} else if _, ok := parsed.(*WhoamiCommand); ok {
		// Whoami reads user information
		builder.AddReadOperation("/proc/self/status", "user_info")
		builder.WithCommandInfo("whoami")
		builder.WithOverApproximated() // User info reading is over-approximated
		builder.WithSafe() // Whoami is generally safe
	}

	return builder.Build(), nil
}