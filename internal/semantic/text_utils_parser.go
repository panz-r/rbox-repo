package semantic

import (
	"fmt"
	"strings"
)

// SeqCommand represents a parsed seq command
type SeqCommand struct {
	Options     map[string]interface{}
	First       string
	Last        string
	Increment   string
	Format      string
	Separator   string
	Terminator  string
	Width       int
}

// NlCommand represents a parsed nl command
type NlCommand struct {
	Options     map[string]interface{}
	InputFiles  []string
	NumberFormat string
	NumberWidth  int
	NumberSeparator string
	StartNumber  int
	Increment    int
	BodyNumbering string
	HeaderNumbering string
	FooterNumbering string
	JoinBlankLines int
	NoReset      bool
	SectionDelimiter string
	PageIncrement bool
	NumberSection bool
	Style        string
	LineIncrement int
	LineStart    int
	LineStep     int
}

// TacCommand represents a parsed tac command
type TacCommand struct {
	Options     map[string]interface{}
	InputFiles  []string
	Separator   string
	Before      bool
	Regex       bool
	Number      bool
	NumberNonblank bool
	NumberSeparator string
}

// RevCommand represents a parsed rev command
type RevCommand struct {
	Options     map[string]interface{}
	InputFiles  []string
}

// ExpandCommand represents a parsed expand command
type ExpandCommand struct {
	Options     map[string]interface{}
	InputFiles  []string
	Tabs        int
	InitialTabs bool
}

// UnexpandCommand represents a parsed unexpand command
type UnexpandCommand struct {
	Options     map[string]interface{}
	InputFiles  []string
	Tabs        int
	All         bool
}

// TextUtilsParser parses seq, nl, tac, rev, expand, and unexpand commands
type TextUtilsParser struct {
	commandType string // "seq", "nl", "tac", "rev", "expand", or "unexpand"
}

// ParseArguments implements CommandParser for text utility commands
func (t *TextUtilsParser) ParseArguments(args []string) (interface{}, error) {
	if t.commandType == "seq" {
		return t.parseSeqCommand(args)
	} else if t.commandType == "nl" {
		return t.parseNlCommand(args)
	} else if t.commandType == "tac" {
		return t.parseTacCommand(args)
	} else if t.commandType == "rev" {
		return t.parseRevCommand(args)
	} else if t.commandType == "expand" {
		return t.parseExpandCommand(args)
	} else if t.commandType == "unexpand" {
		return t.parseUnexpandCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", t.commandType)
}

func (t *TextUtilsParser) parseSeqCommand(args []string) (*SeqCommand, error) {
	cmd := &SeqCommand{
		Options: make(map[string]interface{}),
		Width: 1, // Default width
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
		case "-f", "--format":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Format = args[i+1]
			cmd.Options["format"] = args[i+1]
			i += 2

		case "-s", "--separator":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Separator = args[i+1]
			cmd.Options["separator"] = args[i+1]
			i += 2

		case "-t", "--terminator":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Terminator = args[i+1]
			cmd.Options["terminator"] = args[i+1]
			i += 2

		case "-w", "--equal-width":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Width = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["width"] = cmd.Width
			i += 2

		default:
			return nil, fmt.Errorf("unknown seq option: %s", opt)
		}
	}

	// Parse sequence arguments
	if i < len(args) {
		// seq can take 1-3 arguments: [FIRST] [INCREMENT] LAST
		if i+2 < len(args) {
			// Three arguments: FIRST INCREMENT LAST
			cmd.First = args[i]
			cmd.Increment = args[i+1]
			cmd.Last = args[i+2]
			i += 3
		} else if i+1 < len(args) {
			// Two arguments: FIRST LAST (increment defaults to 1)
			cmd.First = args[i]
			cmd.Last = args[i+1]
			cmd.Increment = "1"
			i += 2
		} else {
			// One argument: LAST (first defaults to 1, increment to 1)
			cmd.Last = args[i]
			cmd.First = "1"
			cmd.Increment = "1"
			i += 1
		}
	} else {
		// No arguments - use defaults
		cmd.First = "1"
		cmd.Increment = "1"
		cmd.Last = "1"
	}

	return cmd, nil
}

func (t *TextUtilsParser) parseNlCommand(args []string) (*NlCommand, error) {
	cmd := &NlCommand{
		Options: make(map[string]interface{}),
		NumberFormat: "right", // Default: right-aligned
		NumberWidth: 6, // Default: 6 characters
		NumberSeparator: "\t", // Default: tab
		StartNumber: 1, // Default: start at 1
		Increment: 1, // Default: increment by 1
		BodyNumbering: "t", // Default: text lines
		HeaderNumbering: "n", // Default: no numbering
		FooterNumbering: "n", // Default: no numbering
		JoinBlankLines: 1, // Default: 1
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
		case "-b", "--body-numbering":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.BodyNumbering = args[i+1]
			cmd.Options["body_numbering"] = args[i+1]
			i += 2

		case "-d", "--section-delimiter":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.SectionDelimiter = args[i+1]
			cmd.Options["section_delimiter"] = args[i+1]
			i += 2

		case "-f", "--footer-numbering":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.FooterNumbering = args[i+1]
			cmd.Options["footer_numbering"] = args[i+1]
			i += 2

		case "-h", "--header-numbering":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.HeaderNumbering = args[i+1]
			cmd.Options["header_numbering"] = args[i+1]
			i += 2

		case "-i", "--page-increment":
			cmd.PageIncrement = true
			cmd.Options["page_increment"] = true
			i++

		case "-l", "--join-blank-lines":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.JoinBlankLines = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["join_blank_lines"] = cmd.JoinBlankLines
			i += 2

		case "-n", "--number-format":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.NumberFormat = args[i+1]
			cmd.Options["number_format"] = args[i+1]
			i += 2

		case "-p", "--no-renumber":
			cmd.NoReset = true
			cmd.Options["no_renumber"] = true
			i++

		case "-s", "--number-separator":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.NumberSeparator = args[i+1]
			cmd.Options["number_separator"] = args[i+1]
			i += 2

		case "-v", "--starting-line-number":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.StartNumber = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["starting_line_number"] = cmd.StartNumber
			i += 2

		case "-w", "--number-width":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.NumberWidth = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["number_width"] = cmd.NumberWidth
			i += 2

		case "-I", "--line-increment":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.LineIncrement = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["line_increment"] = cmd.LineIncrement
			i += 2

		case "-S", "--line-start":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.LineStart = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["line_start"] = cmd.LineStart
			i += 2

		case "-T", "--line-step":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.LineStep = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["line_step"] = cmd.LineStep
			i += 2

		case "-N", "--number-style":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Style = args[i+1]
			cmd.Options["number_style"] = args[i+1]
			i += 2

		default:
			return nil, fmt.Errorf("unknown nl option: %s", opt)
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

func (t *TextUtilsParser) parseTacCommand(args []string) (*TacCommand, error) {
	cmd := &TacCommand{
		Options: make(map[string]interface{}),
		Separator: "\n", // Default: newline
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
		case "-b", "--before":
			cmd.Before = true
			cmd.Options["before"] = true
			i++

		case "-r", "--regex":
			cmd.Regex = true
			cmd.Options["regex"] = true
			i++

		case "-s", "--separator":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Separator = args[i+1]
			cmd.Options["separator"] = args[i+1]
			i += 2

		case "-n", "--number":
			cmd.Number = true
			cmd.Options["number"] = true
			i++

		case "-N", "--number-nonblank":
			cmd.NumberNonblank = true
			cmd.Options["number_nonblank"] = true
			i++

		case "-S", "--number-separator":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.NumberSeparator = args[i+1]
			cmd.Options["number_separator"] = args[i+1]
			i += 2

		default:
			return nil, fmt.Errorf("unknown tac option: %s", opt)
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

func (t *TextUtilsParser) parseRevCommand(args []string) (*RevCommand, error) {
	cmd := &RevCommand{
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
		case "--help":
			cmd.Options["help"] = true
			i++

		case "--version":
			cmd.Options["version"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown rev option: %s", opt)
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

func (t *TextUtilsParser) parseExpandCommand(args []string) (*ExpandCommand, error) {
	cmd := &ExpandCommand{
		Options: make(map[string]interface{}),
		Tabs: 8, // Default: 8 spaces
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
		case "-t", "--tabs":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Tabs = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["tabs"] = cmd.Tabs
			i += 2

		case "-i", "--initial":
			cmd.InitialTabs = true
			cmd.Options["initial"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown expand option: %s", opt)
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

func (t *TextUtilsParser) parseUnexpandCommand(args []string) (*UnexpandCommand, error) {
	cmd := &UnexpandCommand{
		Options: make(map[string]interface{}),
		Tabs: 8, // Default: 8 spaces
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
		case "-t", "--tabs":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Tabs = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["tabs"] = cmd.Tabs
			i += 2

		case "-a", "--all":
			cmd.All = true
			cmd.Options["all"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown unexpand option: %s", opt)
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for text utility commands
func (t *TextUtilsParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if seqCmd, ok := parsed.(*SeqCommand); ok {
		// seq generates numbers, doesn't read files
		builder.AddReadOperation("/dev/null", "number_generation")
		builder.WithCommandInfo("seq")

		// Add seq-specific parameters
		if seqCmd.First != "" {
			builder.WithParameter("first", seqCmd.First)
		}
		if seqCmd.Last != "" {
			builder.WithParameter("last", seqCmd.Last)
		}
		if seqCmd.Increment != "" {
			builder.WithParameter("increment", seqCmd.Increment)
		}
		if seqCmd.Format != "" {
			builder.WithParameter("format", seqCmd.Format)
		}
		if seqCmd.Separator != "" {
			builder.WithParameter("separator", seqCmd.Separator)
		}
		if seqCmd.Terminator != "" {
			builder.WithParameter("terminator", seqCmd.Terminator)
		}
		if seqCmd.Width > 0 {
			builder.WithParameter("width", seqCmd.Width)
		}

		builder.WithOverApproximated() // Number generation is over-approximated
		builder.WithSafe() // seq is generally safe
	} else if nlCmd, ok := parsed.(*NlCommand); ok {
		// nl reads input files
		for _, file := range nlCmd.InputFiles {
			builder.AddReadOperation(file, "text_data")
			builder.WithCommandInfo("nl")

			// Add nl-specific parameters
			if nlCmd.NumberFormat != "" {
				builder.WithParameter("number_format", nlCmd.NumberFormat)
			}
			if nlCmd.NumberWidth > 0 {
				builder.WithParameter("number_width", nlCmd.NumberWidth)
			}
			if nlCmd.NumberSeparator != "" {
				builder.WithParameter("number_separator", nlCmd.NumberSeparator)
			}
			if nlCmd.StartNumber > 0 {
				builder.WithParameter("start_number", nlCmd.StartNumber)
			}
			if nlCmd.Increment > 0 {
				builder.WithParameter("increment", nlCmd.Increment)
			}

			// nl operations are precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no files specified, nl reads from stdin
		if len(nlCmd.InputFiles) == 0 {
			builder.AddReadOperation("/dev/stdin", "text_data")
			builder.WithCommandInfo("nl")
			builder.WithOverApproximated() // Less precise without explicit files
		}

		builder.WithSafe() // nl is generally safe
	} else if tacCmd, ok := parsed.(*TacCommand); ok {
		// tac reads input files
		for _, file := range tacCmd.InputFiles {
			builder.AddReadOperation(file, "text_data")
			builder.WithCommandInfo("tac")

			// Add tac-specific parameters
			if tacCmd.Separator != "" {
				builder.WithParameter("separator", tacCmd.Separator)
			}
			if tacCmd.Before {
				builder.WithParameter("before", true)
			}
			if tacCmd.Regex {
				builder.WithParameter("regex", true)
			}
			if tacCmd.Number {
				builder.WithParameter("number", true)
			}
			if tacCmd.NumberNonblank {
				builder.WithParameter("number_nonblank", true)
			}
			if tacCmd.NumberSeparator != "" {
				builder.WithParameter("number_separator", tacCmd.NumberSeparator)
			}

			// tac operations are precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no files specified, tac reads from stdin
		if len(tacCmd.InputFiles) == 0 {
			builder.AddReadOperation("/dev/stdin", "text_data")
			builder.WithCommandInfo("tac")
			builder.WithOverApproximated() // Less precise without explicit files
		}

		builder.WithSafe() // tac is generally safe
	} else if revCmd, ok := parsed.(*RevCommand); ok {
		// rev reads input files
		for _, file := range revCmd.InputFiles {
			builder.AddReadOperation(file, "text_data")
			builder.WithCommandInfo("rev")

			// rev operations are precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no files specified, rev reads from stdin
		if len(revCmd.InputFiles) == 0 {
			builder.AddReadOperation("/dev/stdin", "text_data")
			builder.WithCommandInfo("rev")
			builder.WithOverApproximated() // Less precise without explicit files
		}

		builder.WithSafe() // rev is generally safe
	} else if expandCmd, ok := parsed.(*ExpandCommand); ok {
		// expand reads input files
		for _, file := range expandCmd.InputFiles {
			builder.AddReadOperation(file, "text_data")
			builder.WithCommandInfo("expand")

			// Add expand-specific parameters
			if expandCmd.Tabs > 0 {
				builder.WithParameter("tabs", expandCmd.Tabs)
			}
			if expandCmd.InitialTabs {
				builder.WithParameter("initial", true)
			}

			// expand operations are precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no files specified, expand reads from stdin
		if len(expandCmd.InputFiles) == 0 {
			builder.AddReadOperation("/dev/stdin", "text_data")
			builder.WithCommandInfo("expand")
			builder.WithOverApproximated() // Less precise without explicit files
		}

		builder.WithSafe() // expand is generally safe
	} else if unexpandCmd, ok := parsed.(*UnexpandCommand); ok {
		// unexpand reads input files
		for _, file := range unexpandCmd.InputFiles {
			builder.AddReadOperation(file, "text_data")
			builder.WithCommandInfo("unexpand")

			// Add unexpand-specific parameters
			if unexpandCmd.Tabs > 0 {
				builder.WithParameter("tabs", unexpandCmd.Tabs)
			}
			if unexpandCmd.All {
				builder.WithParameter("all", true)
			}

			// unexpand operations are precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no files specified, unexpand reads from stdin
		if len(unexpandCmd.InputFiles) == 0 {
			builder.AddReadOperation("/dev/stdin", "text_data")
			builder.WithCommandInfo("unexpand")
			builder.WithOverApproximated() // Less precise without explicit files
		}

		builder.WithSafe() // unexpand is generally safe
	}

	return builder.Build(), nil
}