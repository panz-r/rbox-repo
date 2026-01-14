package semantic

import (
	"fmt"
	"strings"
)

// WhoCommand represents a parsed who command
type WhoCommand struct {
	Options     map[string]interface{}
	Heading     bool
	Short       bool
	Count       bool
	Dead        bool
	Lookup      bool
	Message     bool
	RunLevel    bool
	Users       []string
}

// LastCommand represents a parsed last command
type LastCommand struct {
	Options     map[string]interface{}
	Username    string
	Hostname    string
	Terminal    string
	Number      int
	FullTimes   bool
	Present     bool
	SinceTime   string
	UntilTime   string
}

// IdCommand represents a parsed id command
type IdCommand struct {
	Options     map[string]interface{}
	User        string
	Group       string
	Real        bool
	Effective   bool
	Zero        bool
}

// PwdCommand represents a parsed pwd command
type PwdCommand struct {
	Options     map[string]interface{}
	Logical     bool
	Physical    bool
}

// WhoLastIdPwdParser parses who, last, id, and pwd commands
type WhoLastIdPwdParser struct {
	commandType string // "who", "last", "id", or "pwd"
}

// ParseArguments implements CommandParser for who/last/id/pwd commands
func (w *WhoLastIdPwdParser) ParseArguments(args []string) (interface{}, error) {
	if w.commandType == "who" {
		return w.parseWhoCommand(args)
	} else if w.commandType == "last" {
		return w.parseLastCommand(args)
	} else if w.commandType == "id" {
		return w.parseIdCommand(args)
	} else if w.commandType == "pwd" {
		return w.parsePwdCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", w.commandType)
}

func (w *WhoLastIdPwdParser) parseWhoCommand(args []string) (*WhoCommand, error) {
	cmd := &WhoCommand{
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
		case "-H", "--heading":
			cmd.Heading = true
			cmd.Options["heading"] = true
			i++

		case "-s", "--short":
			cmd.Short = true
			cmd.Options["short"] = true
			i++

		case "-q", "--count":
			cmd.Count = true
			cmd.Options["count"] = true
			i++

		case "-d", "--dead":
			cmd.Dead = true
			cmd.Options["dead"] = true
			i++

		case "-l", "--lookup":
			cmd.Lookup = true
			cmd.Options["lookup"] = true
			i++

		case "-m", "--message":
			cmd.Message = true
			cmd.Options["message"] = true
			i++

		case "-r", "--runlevel":
			cmd.RunLevel = true
			cmd.Options["runlevel"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown who option: %s", opt)
		}
	}

	// Parse user arguments
	if i < len(args) {
		cmd.Users = args[i:]
	}

	return cmd, nil
}

func (w *WhoLastIdPwdParser) parseLastCommand(args []string) (*LastCommand, error) {
	cmd := &LastCommand{
		Options: make(map[string]interface{}),
		Number: -1, // Default: show all
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
		case "-n", "--limit":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Number = parseInt(args[i+1])
			cmd.Options["limit"] = cmd.Number
			i += 2

		case "-f", "--fulltimes":
			cmd.FullTimes = true
			cmd.Options["fulltimes"] = true
			i++

		case "-p", "--present":
			cmd.Present = true
			cmd.Options["present"] = true
			i++

		case "-s", "--since":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.SinceTime = args[i+1]
			cmd.Options["since"] = args[i+1]
			i += 2

		case "-u", "--until":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.UntilTime = args[i+1]
			cmd.Options["until"] = args[i+1]
			i += 2

		default:
			// Handle non-option arguments as usernames/terminals
			if !strings.HasPrefix(opt, "-") {
				break
			}
			return nil, fmt.Errorf("unknown last option: %s", opt)
		}
	}

	// Parse non-option arguments (usernames, terminals, hostnames)
	if i < len(args) {
		// For simplicity, we'll treat all remaining args as potential filters
		cmd.Options["filters"] = args[i:]
	}

	return cmd, nil
}

func (w *WhoLastIdPwdParser) parseIdCommand(args []string) (*IdCommand, error) {
	cmd := &IdCommand{
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
		case "-u", "--user":
			cmd.User = "user"
			cmd.Options["user"] = true
			i++

		case "-g", "--group":
			cmd.Group = "group"
			cmd.Options["group"] = true
			i++

		case "-r", "--real":
			cmd.Real = true
			cmd.Options["real"] = true
			i++

		case "-e", "--effective":
			cmd.Effective = true
			cmd.Options["effective"] = true
			i++

		case "-z", "--zero":
			cmd.Zero = true
			cmd.Options["zero"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown id option: %s", opt)
		}
	}

	// Parse user argument (optional)
	if i < len(args) {
		cmd.Options["username"] = args[i]
	}

	return cmd, nil
}

func (w *WhoLastIdPwdParser) parsePwdCommand(args []string) (*PwdCommand, error) {
	cmd := &PwdCommand{
		Options: make(map[string]interface{}),
		Logical: true, // Default is logical path
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
		case "-L", "--logical":
			cmd.Logical = true
			cmd.Physical = false
			cmd.Options["logical"] = true
			i++

		case "-P", "--physical":
			cmd.Physical = true
			cmd.Logical = false
			cmd.Options["physical"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown pwd option: %s", opt)
		}
	}

	// pwd doesn't take file arguments
	return cmd, nil
}

// GetSemanticOperations implements CommandParser for who/last/id/pwd commands
func (w *WhoLastIdPwdParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if whoCmd, ok := parsed.(*WhoCommand); ok {
		// who reads system user information
		builder.AddReadOperation("/var/run/utmp", "user_info")
		builder.WithCommandInfo("who")

		// Add who-specific parameters
		if whoCmd.Heading {
			builder.WithParameter("heading", true)
		}
		if whoCmd.Short {
			builder.WithParameter("short", true)
		}
		if whoCmd.Count {
			builder.WithParameter("count", true)
		}
		if whoCmd.Dead {
			builder.WithParameter("dead", true)
		}
		if whoCmd.Lookup {
			builder.WithParameter("lookup", true)
		}
		if whoCmd.Message {
			builder.WithParameter("message", true)
		}
		if whoCmd.RunLevel {
			builder.WithParameter("runlevel", true)
		}
		if len(whoCmd.Users) > 0 {
			builder.WithParameter("users", whoCmd.Users)
		}

		builder.WithOverApproximated() // System info reading is over-approximated
		builder.WithSafe() // who is generally safe
	} else if lastCmd, ok := parsed.(*LastCommand); ok {
		// last reads system login information
		builder.AddReadOperation("/var/log/wtmp", "login_info")
		builder.WithCommandInfo("last")

		// Add last-specific parameters
		if lastCmd.Number > 0 {
			builder.WithParameter("limit", lastCmd.Number)
		}
		if lastCmd.FullTimes {
			builder.WithParameter("fulltimes", true)
		}
		if lastCmd.Present {
			builder.WithParameter("present", true)
		}
		if lastCmd.SinceTime != "" {
			builder.WithParameter("since", lastCmd.SinceTime)
		}
		if lastCmd.UntilTime != "" {
			builder.WithParameter("until", lastCmd.UntilTime)
		}

		builder.WithOverApproximated() // System info reading is over-approximated
		builder.WithSafe() // last is generally safe
	} else if idCmd, ok := parsed.(*IdCommand); ok {
		// id reads system user/group information
		builder.AddReadOperation("/etc/passwd", "user_info")
		builder.AddReadOperation("/etc/group", "group_info")
		builder.WithCommandInfo("id")

		// Add id-specific parameters
		if idCmd.User != "" {
			builder.WithParameter("user", true)
		}
		if idCmd.Group != "" {
			builder.WithParameter("group", true)
		}
		if idCmd.Real {
			builder.WithParameter("real", true)
		}
		if idCmd.Effective {
			builder.WithParameter("effective", true)
		}
		if idCmd.Zero {
			builder.WithParameter("zero", true)
		}

		builder.WithOverApproximated() // System info reading is over-approximated
		builder.WithSafe() // id is generally safe
	} else if pwdCmd, ok := parsed.(*PwdCommand); ok {
		// pwd reads current working directory
		builder.AddReadOperation("/proc/self/cwd", "current_directory")
		builder.WithCommandInfo("pwd")

		// Add pwd-specific parameters
		if pwdCmd.Logical {
			builder.WithParameter("logical", true)
		}
		if pwdCmd.Physical {
			builder.WithParameter("physical", true)
		}

		builder.WithOverApproximated() // Current directory reading is over-approximated
		builder.WithSafe() // pwd is generally safe
	}

	return builder.Build(), nil
}