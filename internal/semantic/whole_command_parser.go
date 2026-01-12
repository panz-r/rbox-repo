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