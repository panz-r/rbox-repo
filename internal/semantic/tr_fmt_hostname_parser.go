package semantic

import (
	"fmt"
	"strings"
)

// TrCommand represents a parsed tr command
type TrCommand struct {
	Options     map[string]interface{}
	Set1        string
	Set2        string
	Delete      bool
	SqueezeRepeats bool
	Complement   bool
	Translate    bool
}

// FmtCommand represents a parsed fmt command
type FmtCommand struct {
	Options     map[string]interface{}
	Width       int
	Prefix      string
	CrownMargin bool
	TaggedParagraph bool
}

// HostnameCommand represents a parsed hostname command
type HostnameCommand struct {
	Options     map[string]interface{}
	Short       bool
	Long        bool
	IPAddress   bool
	FQDN        bool
}

// TrFmtHostnameParser parses tr, fmt, and hostname commands
type TrFmtHostnameParser struct {
	commandType string // "tr", "fmt", or "hostname"
}

// ParseArguments implements CommandParser for tr/fmt/hostname commands
func (t *TrFmtHostnameParser) ParseArguments(args []string) (interface{}, error) {
	if t.commandType == "tr" {
		if len(args) == 0 {
			return nil, fmt.Errorf("no arguments provided")
		}
		return t.parseTrCommand(args)
	} else if t.commandType == "fmt" {
		// fmt can be called with no arguments
		return t.parseFmtCommand(args)
	} else if t.commandType == "hostname" {
		// hostname can be called with no arguments
		return t.parseHostnameCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", t.commandType)
}

func (t *TrFmtHostnameParser) parseTrCommand(args []string) (*TrCommand, error) {
	cmd := &TrCommand{
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
		case "-d", "--delete":
			cmd.Delete = true
			cmd.Options["delete"] = true
			i++

		case "-s", "--squeeze-repeats":
			cmd.SqueezeRepeats = true
			cmd.Options["squeeze_repeats"] = true
			i++

		case "-c", "--complement":
			cmd.Complement = true
			cmd.Options["complement"] = true
			i++

		case "-t", "--truncate-set1":
			cmd.Translate = true
			cmd.Options["translate"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown tr option: %s", opt)
		}
	}

	// Parse character sets
	if i < len(args) {
		cmd.Set1 = args[i]
		i++
	}
	if i < len(args) {
		cmd.Set2 = args[i]
		i++
	}

	return cmd, nil
}

func (t *TrFmtHostnameParser) parseFmtCommand(args []string) (*FmtCommand, error) {
	cmd := &FmtCommand{
		Options: make(map[string]interface{}),
		Width: 75, // Default width
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
		case "-w", "--width":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Width = parseInt(args[i+1])
			cmd.Options["width"] = cmd.Width
			i += 2

		case "-p", "--prefix":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Prefix = args[i+1]
			cmd.Options["prefix"] = args[i+1]
			i += 2

		case "-c", "--crown-margin":
			cmd.CrownMargin = true
			cmd.Options["crown_margin"] = true
			i++

		case "-t", "--tagged-paragraph":
			cmd.TaggedParagraph = true
			cmd.Options["tagged_paragraph"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown fmt option: %s", opt)
		}
	}

	// Parse file arguments
	if i < len(args) {
		// fmt can take file arguments
		// For now, we'll just note that files are present
		cmd.Options["has_files"] = true
	}

	return cmd, nil
}

func (t *TrFmtHostnameParser) parseHostnameCommand(args []string) (*HostnameCommand, error) {
	cmd := &HostnameCommand{
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
		case "-s", "--short":
			cmd.Short = true
			cmd.Options["short"] = true
			i++

		case "-l", "--long":
			cmd.Long = true
			cmd.Options["long"] = true
			i++

		case "-i", "--ip-address":
			cmd.IPAddress = true
			cmd.Options["ip_address"] = true
			i++

		case "-f", "--fqdn":
			cmd.FQDN = true
			cmd.Options["fqdn"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown hostname option: %s", opt)
		}
	}

	// Parse hostname argument (optional)
	if i < len(args) {
		cmd.Options["new_hostname"] = args[i]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for tr/fmt/hostname commands
func (t *TrFmtHostnameParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if trCmd, ok := parsed.(*TrCommand); ok {
		// tr reads from stdin and writes to stdout
		builder.AddReadOperation("/dev/stdin", "character_data")
		builder.WithCommandInfo("tr")

		// Add tr-specific parameters
		if trCmd.Delete {
			builder.WithParameter("delete", true)
		}
		if trCmd.SqueezeRepeats {
			builder.WithParameter("squeeze_repeats", true)
		}
		if trCmd.Complement {
			builder.WithParameter("complement", true)
		}
		if trCmd.Translate {
			builder.WithParameter("translate", true)
		}
		if trCmd.Set1 != "" {
			builder.WithParameter("set1", trCmd.Set1)
		}
		if trCmd.Set2 != "" {
			builder.WithParameter("set2", trCmd.Set2)
		}

		builder.WithOverApproximated() // stdin/stdout operations are over-approximated
		builder.WithSafe() // tr is generally safe
	} else if fmtCmd, ok := parsed.(*FmtCommand); ok {
		// fmt reads from stdin or files and writes to stdout
		builder.AddReadOperation("/dev/stdin", "text_data")
		builder.WithCommandInfo("fmt")

		// Add fmt-specific parameters
		if fmtCmd.Width != 75 {
			builder.WithParameter("width", fmtCmd.Width)
		}
		if fmtCmd.Prefix != "" {
			builder.WithParameter("prefix", fmtCmd.Prefix)
		}
		if fmtCmd.CrownMargin {
			builder.WithParameter("crown_margin", true)
		}
		if fmtCmd.TaggedParagraph {
			builder.WithParameter("tagged_paragraph", true)
		}

		builder.WithOverApproximated() // stdin/stdout operations are over-approximated
		builder.WithSafe() // fmt is generally safe
	} else if hostnameCmd, ok := parsed.(*HostnameCommand); ok {
		// hostname reads system information
		builder.AddReadOperation("/proc/sys/kernel/hostname", "system_info")
		builder.WithCommandInfo("hostname")

		// Add hostname-specific parameters
		if hostnameCmd.Short {
			builder.WithParameter("short", true)
		}
		if hostnameCmd.Long {
			builder.WithParameter("long", true)
		}
		if hostnameCmd.IPAddress {
			builder.WithParameter("ip_address", true)
		}
		if hostnameCmd.FQDN {
			builder.WithParameter("fqdn", true)
		}

		builder.WithOverApproximated() // System info reading is over-approximated
		builder.WithSafe() // hostname is generally safe
	}

	return builder.Build(), nil
}