package semantic

import (
	"fmt"
	"strings"
)

// CutCommand represents a parsed cut command
type CutCommand struct {
	Files       []string
	Options     map[string]interface{}
	Fields      string
	Delimiter   string
	OnlyDelimited bool
	Characters  string
	Bytes       string
	Complement  bool
}

// PasteCommand represents a parsed paste command
type PasteCommand struct {
	Files       []string
	Options     map[string]interface{}
	Delimiter   string
	Serial      bool
}

// JoinCommand represents a parsed join command
type JoinCommand struct {
	Files       []string
	Options     map[string]interface{}
	Field1      int
	Field2      int
	Separator   string
	IgnoreCase  bool
	NoCheckOrder bool
	Unpaired    string
}

// CutPasteJoinParser parses cut, paste, and join commands
type CutPasteJoinParser struct {
	commandType string // "cut", "paste", or "join"
}

// ParseArguments implements CommandParser for cut/paste/join commands
func (c *CutPasteJoinParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	if c.commandType == "cut" {
		return c.parseCutCommand(args)
	} else if c.commandType == "paste" {
		return c.parsePasteCommand(args)
	} else if c.commandType == "join" {
		return c.parseJoinCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", c.commandType)
}

func (c *CutPasteJoinParser) parseCutCommand(args []string) (*CutCommand, error) {
	cmd := &CutCommand{
		Options: make(map[string]interface{}),
		Delimiter: "\t", // Default delimiter is tab
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
		case "-f", "--fields":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Fields = args[i+1]
			cmd.Options["fields"] = args[i+1]
			i += 2

		case "-d", "--delimiter":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Delimiter = args[i+1]
			cmd.Options["delimiter"] = args[i+1]
			i += 2

		case "-s", "--only-delimited":
			cmd.OnlyDelimited = true
			cmd.Options["only_delimited"] = true
			i++

		case "-c", "--characters":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Characters = args[i+1]
			cmd.Options["characters"] = args[i+1]
			i += 2

		case "-b", "--bytes":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Bytes = args[i+1]
			cmd.Options["bytes"] = args[i+1]
			i += 2

		case "--complement":
			cmd.Complement = true
			cmd.Options["complement"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown cut option: %s", opt)
		}
	}

	// Parse file arguments
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}

func (c *CutPasteJoinParser) parsePasteCommand(args []string) (*PasteCommand, error) {
	cmd := &PasteCommand{
		Options: make(map[string]interface{}),
		Delimiter: "\t", // Default delimiter is tab
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
		case "-d", "--delimiters":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Delimiter = args[i+1]
			cmd.Options["delimiter"] = args[i+1]
			i += 2

		case "-s", "--serial":
			cmd.Serial = true
			cmd.Options["serial"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown paste option: %s", opt)
		}
	}

	// Parse file arguments
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}

func (c *CutPasteJoinParser) parseJoinCommand(args []string) (*JoinCommand, error) {
	cmd := &JoinCommand{
		Options: make(map[string]interface{}),
		Field1: 1, // Default join field
		Field2: 1,
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
		case "-1":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Field1 = parseInt(args[i+1])
			cmd.Options["field1"] = cmd.Field1
			i += 2

		case "-2":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Field2 = parseInt(args[i+1])
			cmd.Options["field2"] = cmd.Field2
			i += 2

		case "-t", "--separator":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Separator = args[i+1]
			cmd.Options["separator"] = args[i+1]
			i += 2

		case "-i", "--ignore-case":
			cmd.IgnoreCase = true
			cmd.Options["ignore_case"] = true
			i++

		case "--nocheck-order":
			cmd.NoCheckOrder = true
			cmd.Options["no_check_order"] = true
			i++

		case "-a":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Unpaired = args[i+1]
			cmd.Options["unpaired"] = args[i+1]
			i += 2

		default:
			return nil, fmt.Errorf("unknown join option: %s", opt)
		}
	}

	// Parse file arguments (join requires exactly 2 files)
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}


// GetSemanticOperations implements CommandParser for cut/paste/join commands
func (c *CutPasteJoinParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if cutCmd, ok := parsed.(*CutCommand); ok {
		// Add read operations for each file
		for _, file := range cutCmd.Files {
			builder.AddReadOperation(file, "file_content")
			builder.WithCommandInfo("cut")

			// Add cut-specific parameters
			if cutCmd.Fields != "" {
				builder.WithParameter("fields", cutCmd.Fields)
			}
			if cutCmd.Delimiter != "\t" {
				builder.WithParameter("delimiter", cutCmd.Delimiter)
			}
			if cutCmd.OnlyDelimited {
				builder.WithParameter("only_delimited", true)
			}
			if cutCmd.Characters != "" {
				builder.WithParameter("characters", cutCmd.Characters)
			}
			if cutCmd.Complement {
				builder.WithParameter("complement", true)
			}

			// Cut operations are precise since we know exactly what files are being processed
			builder.WithPrecise()
		}

		// If no files specified, cut reads from stdin
		if len(cutCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "file_content")
			builder.WithCommandInfo("cut")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	} else if pasteCmd, ok := parsed.(*PasteCommand); ok {
		// Add read operations for each file
		for _, file := range pasteCmd.Files {
			builder.AddReadOperation(file, "file_content")
			builder.WithCommandInfo("paste")

			// Add paste-specific parameters
			if pasteCmd.Delimiter != "\t" {
				builder.WithParameter("delimiter", pasteCmd.Delimiter)
			}
			if pasteCmd.Serial {
				builder.WithParameter("serial", true)
			}

			// Paste operations are precise since we know exactly what files are being processed
			builder.WithPrecise()
		}

		// If no files specified, paste reads from stdin
		if len(pasteCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "file_content")
			builder.WithCommandInfo("paste")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	} else if joinCmd, ok := parsed.(*JoinCommand); ok {
		// Add read operations for each file
		for _, file := range joinCmd.Files {
			builder.AddReadOperation(file, "file_content")
			builder.WithCommandInfo("join")

			// Add join-specific parameters
			if joinCmd.Field1 > 0 {
				builder.WithParameter("field1", joinCmd.Field1)
			}
			if joinCmd.Field2 > 0 {
				builder.WithParameter("field2", joinCmd.Field2)
			}
			if joinCmd.Separator != "" {
				builder.WithParameter("separator", joinCmd.Separator)
			}
			if joinCmd.IgnoreCase {
				builder.WithParameter("ignore_case", true)
			}
			if joinCmd.NoCheckOrder {
				builder.WithParameter("no_check_order", true)
			}

			// Join operations are precise since we know exactly what files are being processed
			builder.WithPrecise()
		}

		// If no files specified, join reads from stdin
		if len(joinCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "file_content")
			builder.WithCommandInfo("join")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	}

	return builder.Build(), nil
}