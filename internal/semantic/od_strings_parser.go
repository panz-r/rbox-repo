package semantic

import (
	"fmt"
	"strings"
)

// OdCommand represents a parsed od command
type OdCommand struct {
	Options     map[string]interface{}
	InputFiles  []string
	OutputType  string
	AddressRadix string
	BytesPerBlock int
	SkipBytes    int
	ReadBytes    int
}

// StringsCommand represents a parsed strings command
type StringsCommand struct {
	Options     map[string]interface{}
	InputFiles  []string
	MinLength   int
	Encoding    string
	Radix       string
	Target      string
}

// FactorCommand represents a parsed factor command
type FactorCommand struct {
	Options     map[string]interface{}
	Numbers     []string
	Bignum      bool
	Quiet       bool
}

// YesCommand represents a parsed yes command
type YesCommand struct {
	Options     map[string]interface{}
	Message     string
}

// SleepCommand represents a parsed sleep command
type SleepCommand struct {
	Options     map[string]interface{}
	Duration    string
}

// CalCommand represents a parsed cal command
type CalCommand struct {
	Options     map[string]interface{}
	Month       int
	Year        int
	ShowYear    bool
	MondayWeek  bool
	Julian      bool
}

// PrintenvCommand represents a parsed printenv command
type PrintenvCommand struct {
	Options     map[string]interface{}
	Variables   []string
	All         bool
	Null        bool
}

// OdStringsParser parses od, strings, factor, yes, sleep, cal, and printenv commands
type OdStringsParser struct {
	commandType string // "od", "strings", "factor", "yes", "sleep", "cal", or "printenv"
}

// ParseArguments implements CommandParser for od/strings/factor/yes/sleep/cal/printenv commands
func (o *OdStringsParser) ParseArguments(args []string) (interface{}, error) {
	if o.commandType == "od" {
		return o.parseOdCommand(args)
	} else if o.commandType == "strings" {
		return o.parseStringsCommand(args)
	} else if o.commandType == "factor" {
		return o.parseFactorCommand(args)
	} else if o.commandType == "yes" {
		return o.parseYesCommand(args)
	} else if o.commandType == "sleep" {
		return o.parseSleepCommand(args)
	} else if o.commandType == "cal" {
		return o.parseCalCommand(args)
	} else if o.commandType == "printenv" {
		return o.parsePrintenvCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", o.commandType)
}

func (o *OdStringsParser) parseOdCommand(args []string) (*OdCommand, error) {
	cmd := &OdCommand{
		Options:     make(map[string]interface{}),
		OutputType:  "o", // Default: octal
		AddressRadix: "o", // Default: octal
		BytesPerBlock: 16, // Default: 16 bytes
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
		case "-A", "--address-radix":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.AddressRadix = args[i+1]
			cmd.Options["address_radix"] = args[i+1]
			i += 2

		case "-t", "--format":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.OutputType = args[i+1]
			cmd.Options["format"] = args[i+1]
			i += 2

		case "-j", "--skip-bytes":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.SkipBytes = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["skip_bytes"] = cmd.SkipBytes
			i += 2

		case "-N", "--read-bytes":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.ReadBytes = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["read_bytes"] = cmd.ReadBytes
			i += 2

		case "-v", "--output-duplicates":
			cmd.Options["output_duplicates"] = true
			i++

		case "-w", "--width":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.BytesPerBlock = parseInt(args[i+1])
			cmd.Options["width"] = cmd.BytesPerBlock
			i += 2

		default:
			return nil, fmt.Errorf("unknown od option: %s", opt)
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

func (o *OdStringsParser) parseStringsCommand(args []string) (*StringsCommand, error) {
	cmd := &StringsCommand{
		Options:   make(map[string]interface{}),
		MinLength: 4, // Default: 4 characters
		Encoding:  "s", // Default: 7-bit
		Radix:     "d", // Default: decimal
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
		case "-a", "--all":
			cmd.Options["all"] = true
			i++

		case "-f", "--print-file-name":
			cmd.Options["print_file_name"] = true
			i++

		case "-n", "--bytes":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.MinLength = ParserUtilsInstance.ParseInt(args[i+1])
			cmd.Options["bytes"] = cmd.MinLength
			i += 2

		case "-t", "--radix":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Radix = args[i+1]
			cmd.Options["radix"] = args[i+1]
			i += 2

		case "-e", "--encoding":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Encoding = args[i+1]
			cmd.Options["encoding"] = args[i+1]
			i += 2

		case "-T", "--target":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Target = args[i+1]
			cmd.Options["target"] = args[i+1]
			i += 2

		default:
			return nil, fmt.Errorf("unknown strings option: %s", opt)
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

func (o *OdStringsParser) parseFactorCommand(args []string) (*FactorCommand, error) {
	cmd := &FactorCommand{
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
		case "-b", "--bignum":
			cmd.Bignum = true
			cmd.Options["bignum"] = true
			i++

		case "-q", "--quiet":
			cmd.Quiet = true
			cmd.Options["quiet"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown factor option: %s", opt)
		}
	}

	// Parse number arguments
	if i < len(args) {
		cmd.Numbers = args[i:]
	}

	return cmd, nil
}

func (o *OdStringsParser) parseYesCommand(args []string) (*YesCommand, error) {
	cmd := &YesCommand{
		Options: make(map[string]interface{}),
		Message:  "y", // Default message
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
			return nil, fmt.Errorf("unknown yes option: %s", opt)
		}
	}

	// Parse message argument
	if i < len(args) {
		cmd.Message = strings.Join(args[i:], " ")
	}

	return cmd, nil
}

func (o *OdStringsParser) parseSleepCommand(args []string) (*SleepCommand, error) {
	cmd := &SleepCommand{
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
			return nil, fmt.Errorf("unknown sleep option: %s", opt)
		}
	}

	// Parse duration argument
	if i < len(args) {
		cmd.Duration = args[i]
	}

	return cmd, nil
}

func (o *OdStringsParser) parseCalCommand(args []string) (*CalCommand, error) {
	cmd := &CalCommand{
		Options: make(map[string]interface{}),
		Month: -1, // -1 means current month
		Year:  -1, // -1 means current year
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
		case "-y", "--year":
			cmd.ShowYear = true
			cmd.Options["year"] = true
			i++

		case "-m", "--monday":
			cmd.MondayWeek = true
			cmd.Options["monday"] = true
			i++

		case "-j", "--julian":
			cmd.Julian = true
			cmd.Options["julian"] = true
			i++

		case "-1", "--one":
			cmd.Options["one"] = true
			i++

		case "-3", "--three":
			cmd.Options["three"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown cal option: %s", opt)
		}
	}

	// Parse month and year arguments
	if i < len(args) {
		// Try to parse month
		month := ParserUtilsInstance.ParseInt(args[i])
		if month >= 1 && month <= 12 {
			cmd.Month = month
			i++
			// Try to parse year
			if i < len(args) {
				year := ParserUtilsInstance.ParseInt(args[i])
				if year > 0 {
					cmd.Year = year
					i++
				}
			}
		} else {
			// Try to parse year directly
			year := ParserUtilsInstance.ParseInt(args[i])
			if year > 0 {
				cmd.Year = year
				i++
			}
		}
	}

	return cmd, nil
}

func (o *OdStringsParser) parsePrintenvCommand(args []string) (*PrintenvCommand, error) {
	cmd := &PrintenvCommand{
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
		case "-0", "--null":
			cmd.Null = true
			cmd.Options["null"] = true
			i++

		case "--help":
			cmd.Options["help"] = true
			i++

		case "--version":
			cmd.Options["version"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown printenv option: %s", opt)
		}
	}

	// Parse variable names
	if i < len(args) {
		cmd.Variables = args[i:]
	} else {
		// No arguments means print all variables
		cmd.All = true
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for od/strings/factor/yes/sleep/cal/printenv commands
func (o *OdStringsParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if odCmd, ok := parsed.(*OdCommand); ok {
		// od reads input files
		for _, file := range odCmd.InputFiles {
			builder.AddReadOperation(file, "binary_data")
			builder.WithCommandInfo("od")

			// Add od-specific parameters
			if odCmd.OutputType != "" {
				builder.WithParameter("format", odCmd.OutputType)
			}
			if odCmd.AddressRadix != "" {
				builder.WithParameter("address_radix", odCmd.AddressRadix)
			}
			if odCmd.SkipBytes > 0 {
				builder.WithParameter("skip_bytes", odCmd.SkipBytes)
			}
			if odCmd.ReadBytes > 0 {
				builder.WithParameter("read_bytes", odCmd.ReadBytes)
			}

			// od operations are precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no files specified, od reads from stdin
		if len(odCmd.InputFiles) == 0 {
			builder.AddReadOperation("/dev/stdin", "binary_data")
			builder.WithCommandInfo("od")
			builder.WithOverApproximated() // Less precise without explicit files
		}

		builder.WithSafe() // od is generally safe
	} else if stringsCmd, ok := parsed.(*StringsCommand); ok {
		// strings reads input files
		for _, file := range stringsCmd.InputFiles {
			builder.AddReadOperation(file, "text_data")
			builder.WithCommandInfo("strings")

			// Add strings-specific parameters
			if stringsCmd.MinLength > 0 {
				builder.WithParameter("min_length", stringsCmd.MinLength)
			}
			if stringsCmd.Encoding != "" {
				builder.WithParameter("encoding", stringsCmd.Encoding)
			}
			if stringsCmd.Radix != "" {
				builder.WithParameter("radix", stringsCmd.Radix)
			}

			// strings operations are precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no files specified, strings reads from stdin
		if len(stringsCmd.InputFiles) == 0 {
			builder.AddReadOperation("/dev/stdin", "text_data")
			builder.WithCommandInfo("strings")
			builder.WithOverApproximated() // Less precise without explicit files
		}

		builder.WithSafe() // strings is generally safe
	} else if factorCmd, ok := parsed.(*FactorCommand); ok {
		// factor doesn't read files, just processes numbers
		builder.AddReadOperation("/dev/null", "computation")
		builder.WithCommandInfo("factor")

		// Add factor-specific parameters
		if factorCmd.Bignum {
			builder.WithParameter("bignum", true)
		}
		if factorCmd.Quiet {
			builder.WithParameter("quiet", true)
		}
		if len(factorCmd.Numbers) > 0 {
			builder.WithParameter("numbers", factorCmd.Numbers)
		}

		builder.WithOverApproximated() // Computation is over-approximated
		builder.WithSafe() // factor is generally safe
	} else if yesCmd, ok := parsed.(*YesCommand); ok {
		// yes doesn't read files, just outputs repeatedly
		builder.AddReadOperation("/dev/null", "output_generation")
		builder.WithCommandInfo("yes")

		// Add yes-specific parameters
		if yesCmd.Message != "" {
			builder.WithParameter("message", yesCmd.Message)
		}

		builder.WithOverApproximated() // Output generation is over-approximated
		builder.WithSafe() // yes is generally safe
	} else if sleepCmd, ok := parsed.(*SleepCommand); ok {
		// sleep doesn't read files, just waits
		builder.AddReadOperation("/dev/null", "time_operation")
		builder.WithCommandInfo("sleep")

		// Add sleep-specific parameters
		if sleepCmd.Duration != "" {
			builder.WithParameter("duration", sleepCmd.Duration)
		}

		builder.WithOverApproximated() // Time operation is over-approximated
		builder.WithSafe() // sleep is generally safe
	} else if calCmd, ok := parsed.(*CalCommand); ok {
		// cal doesn't read files, just generates calendar
		builder.AddReadOperation("/dev/null", "calendar_generation")
		builder.WithCommandInfo("cal")

		// Add cal-specific parameters
		if calCmd.Month > 0 {
			builder.WithParameter("month", calCmd.Month)
		}
		if calCmd.Year > 0 {
			builder.WithParameter("year", calCmd.Year)
		}
		if calCmd.ShowYear {
			builder.WithParameter("show_year", true)
		}
		if calCmd.MondayWeek {
			builder.WithParameter("monday_week", true)
		}
		if calCmd.Julian {
			builder.WithParameter("julian", true)
		}

		builder.WithOverApproximated() // Calendar generation is over-approximated
		builder.WithSafe() // cal is generally safe
	} else if printenvCmd, ok := parsed.(*PrintenvCommand); ok {
		// printenv reads environment variables
		builder.AddReadOperation("/proc/self/environ", "environment_variables")
		builder.WithCommandInfo("printenv")

		// Add printenv-specific parameters
		if printenvCmd.All {
			builder.WithParameter("all", true)
		}
		if printenvCmd.Null {
			builder.WithParameter("null", true)
		}
		if len(printenvCmd.Variables) > 0 {
			builder.WithParameter("variables", printenvCmd.Variables)
		}

		builder.WithOverApproximated() // Environment reading is over-approximated
		builder.WithSafe() // printenv is generally safe
	}

	return builder.Build(), nil
}

// GetOperationGraph implements the enhanced CommandParser interface
func (p *OdStringsParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	// This parser handles multiple command types
	var commandName string

	switch parsed.(type) {
	case *OdCommand:
		commandName = "od"
	case *StringsCommand:
		commandName = "strings"
	case *FactorCommand:
		commandName = "factor"
	case *YesCommand:
		commandName = "yes"
	case *SleepCommand:
		commandName = "sleep"
	case *CalCommand:
		commandName = "cal"
	case *PrintenvCommand:
		commandName = "printenv"
	default:
		return nil, fmt.Errorf("invalid command type for od/strings/factor/yes/sleep/cal/printenv parser")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph(commandName, operations, []SemanticOperation{})

	return graph, nil
}