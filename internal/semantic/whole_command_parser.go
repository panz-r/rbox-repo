package semantic

import (
	"fmt"
)

// WholeCommandParser coordinates the parsing process
type WholeCommandParser struct {
	registry     *ParserRegistry
	tokenizer    *Tokenizer
	shellParser  *ShellParser
	graphBuilder *OperationGraphBuilder
}

// NewWholeCommandParser creates a new whole command parser
func NewWholeCommandParser() *WholeCommandParser {
	registry := NewParserRegistry()

	// Register built-in parsers
	registry.RegisterParser("cat", &CatParser{})
	registry.RegisterParser("grep", &GrepParser{})
	registry.RegisterParser("sort", &SortParser{})
	registry.RegisterParser("find", &FindParser{})
	registry.RegisterParser("git", &GitParser{})
	registry.RegisterParser("ls", &LsParser{})
	registry.RegisterParser("ps", &PsParser{})
	registry.RegisterParser("df", &DfDuParser{})
	registry.RegisterParser("du", &DfDuParser{})
	registry.RegisterParser("sed", &SedAWKParser{})
	registry.RegisterParser("awk", &SedAWKParser{})
	registry.RegisterParser("make", &MakeCMakeParser{})
	registry.RegisterParser("cmake", &MakeCMakeParser{})
	registry.RegisterParser("head", &HeadTailParser{commandType: "head"})
	registry.RegisterParser("tail", &HeadTailParser{commandType: "tail"})
	registry.RegisterParser("wc", &WcUnameParser{commandType: "wc"})
	registry.RegisterParser("uname", &WcUnameParser{commandType: "uname"})
	registry.RegisterParser("stat", &StatFileParser{commandType: "stat"})
	registry.RegisterParser("file", &StatFileParser{commandType: "file"})
	registry.RegisterParser("echo", &EchoDateWhoamiParser{commandType: "echo"})
	registry.RegisterParser("date", &EchoDateWhoamiParser{commandType: "date"})
	registry.RegisterParser("whoami", &EchoDateWhoamiParser{commandType: "whoami"})
	registry.RegisterParser("diff", &DiffCommUniqParser{commandType: "diff"})
	registry.RegisterParser("comm", &DiffCommUniqParser{commandType: "comm"})
	registry.RegisterParser("uniq", &DiffCommUniqParser{commandType: "uniq"})
	registry.RegisterParser("cut", &CutPasteJoinParser{commandType: "cut"})
	registry.RegisterParser("paste", &CutPasteJoinParser{commandType: "paste"})
	registry.RegisterParser("join", &CutPasteJoinParser{commandType: "join"})
	registry.RegisterParser("tr", &TrFmtHostnameParser{commandType: "tr"})
	registry.RegisterParser("fmt", &TrFmtHostnameParser{commandType: "fmt"})
	registry.RegisterParser("hostname", &TrFmtHostnameParser{commandType: "hostname"})
	registry.RegisterParser("readlink", &ReadlinkBasenameUptimeParser{commandType: "readlink"})
	registry.RegisterParser("basename", &ReadlinkBasenameUptimeParser{commandType: "basename"})
	registry.RegisterParser("dirname", &ReadlinkBasenameUptimeParser{commandType: "dirname"})
	registry.RegisterParser("uptime", &ReadlinkBasenameUptimeParser{commandType: "uptime"})
	registry.RegisterParser("free", &ReadlinkBasenameUptimeParser{commandType: "free"})
	registry.RegisterParser("who", &WhoLastIdPwdParser{commandType: "who"})
	registry.RegisterParser("last", &WhoLastIdPwdParser{commandType: "last"})
	registry.RegisterParser("id", &WhoLastIdPwdParser{commandType: "id"})
	registry.RegisterParser("pwd", &WhoLastIdPwdParser{commandType: "pwd"})

	// Additional utility commands
	registry.RegisterParser("od", &OdStringsParser{commandType: "od"})
	registry.RegisterParser("strings", &OdStringsParser{commandType: "strings"})
	registry.RegisterParser("factor", &OdStringsParser{commandType: "factor"})
	registry.RegisterParser("yes", &OdStringsParser{commandType: "yes"})
	registry.RegisterParser("sleep", &OdStringsParser{commandType: "sleep"})
	registry.RegisterParser("cal", &OdStringsParser{commandType: "cal"})
	registry.RegisterParser("printenv", &OdStringsParser{commandType: "printenv"})

	// Text processing utilities
	registry.RegisterParser("seq", &TextUtilsParser{commandType: "seq"})
	registry.RegisterParser("nl", &TextUtilsParser{commandType: "nl"})
	registry.RegisterParser("tac", &TextUtilsParser{commandType: "tac"})
	registry.RegisterParser("rev", &TextUtilsParser{commandType: "rev"})
	registry.RegisterParser("expand", &TextUtilsParser{commandType: "expand"})
	registry.RegisterParser("unexpand", &TextUtilsParser{commandType: "unexpand"})

	// Work Stream B: Infrastructure & Operations
	// System Operations
	registry.RegisterParser("ln", &LnParser{})

	// Network Tools
	registry.RegisterParser("rsync", &RsyncParser{})
	registry.RegisterParser("nc", &NcParser{})
	registry.RegisterParser("netcat", &NcParser{})

	// Containerization
	registry.RegisterParser("docker", &DockerParser{})

	// Cloud Tools
	registry.RegisterParser("kubectl", &KubectlParser{})

	// Add more parsers here as they're implemented

	return &WholeCommandParser{
		registry:     registry,
		tokenizer:    &Tokenizer{},
		shellParser:  &ShellParser{},
		graphBuilder: &OperationGraphBuilder{},
	}
}

// ParseFullCommand parses a complete command line into an operation graph
func (wcp *WholeCommandParser) ParseFullCommand(commandLine string) (*OperationGraph, error) {
	// Step 1: Tokenize the command line
	tokens, err := wcp.tokenizer.Tokenize(commandLine)
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %v", err)
	}

	// Step 2: Parse shell structures
	shellStruct, err := wcp.shellParser.ParseShellStructures(tokens)
	if err != nil {
		return nil, fmt.Errorf("shell parsing failed: %v", err)
	}

	// Step 3: Get command-specific parser
	parser := wcp.registry.GetParser(shellStruct.BaseCommand)

	// Step 4: Parse command-specific arguments
	cmdModel, err := parser.ParseArguments(shellStruct.Arguments)
	if err != nil {
		return nil, fmt.Errorf("command parsing failed: %v", err)
	}

	// Step 5: Get semantic operations from command parser
	cmdOperations, err := parser.GetSemanticOperations(cmdModel)
	if err != nil {
		return nil, fmt.Errorf("semantic analysis failed: %v", err)
	}

	// Step 6: Get shell semantic operations
	shellOperations := wcp.getShellSemanticOperations(shellStruct)

	// Step 7: Build complete operation graph
	graph := wcp.graphBuilder.BuildOperationGraph(
		shellStruct.BaseCommand,
		cmdOperations,
		shellOperations,
	)

	return graph, nil
}

// getShellSemanticOperations converts shell structures to semantic operations
func (wcp *WholeCommandParser) getShellSemanticOperations(structure *ShellStructure) []SemanticOperation {
	operations := make([]SemanticOperation, 0)

	// Handle redirections
	for _, redir := range structure.Redirections {
		opType := getOperationTypeForRedirection(redir.Operator)
		operations = append(operations, SemanticOperation{
			OperationType: opType,
			TargetPath:    redir.Target,
			Context:       "redirection",
			Parameters: map[string]interface{}{
				"redirection_type": redir.Operator,
			},
		})
	}

	return operations
}

func getOperationTypeForRedirection(operator string) OperationType {
	switch operator {
	case ">":
		return OpOverwrite
	case ">>":
		return OpWrite
	case "2>":
		return OpOverwrite
	case "2>>":
		return OpWrite
	case "<":
		return OpRead
	case "<<":
		return OpRead
	default:
		return OpWrite
	}
}
