package semantic

// ShellStructure represents the parsed shell structure of a command
type ShellStructure struct {
	BaseCommand   string
	Arguments     []string
	Pipes         []PipeInfo
	Redirections  []RedirectionInfo
}

// PipeInfo represents a pipe in the command
type PipeInfo struct {
	FromCommand string
	ToCommand   string
	Position    int
}

// RedirectionInfo represents a redirection in the command
type RedirectionInfo struct {
	Operator string
	Target   string
	Position int
}

// ShellParser parses shell structures from tokens
type ShellParser struct {
	// Can add configuration here
}

// ParseShellStructures parses shell structures from tokens
func (sp *ShellParser) ParseShellStructures(tokens []Token) (*ShellStructure, error) {
	shellStruct := &ShellStructure{
		Arguments:    make([]string, 0),
		Pipes:        make([]PipeInfo, 0),
		Redirections: make([]RedirectionInfo, 0),
	}

	if len(tokens) == 0 {
		return shellStruct, nil
	}

	shellStruct.BaseCommand = tokens[0].Value

	i := 1
	for i < len(tokens) {
		token := tokens[i]

		switch token.Type {
		case TokenPipe:
			if i+1 < len(tokens) {
				nextCmd := tokens[i+1].Value
				shellStruct.Pipes = append(shellStruct.Pipes, PipeInfo{
					FromCommand: shellStruct.BaseCommand,
					ToCommand:   nextCmd,
					Position:    token.Pos,
				})
				// Update base command for next iteration
				shellStruct.BaseCommand = nextCmd
				// Clear arguments for the new command
				shellStruct.Arguments = make([]string, 0)
				i += 2
				continue
			}

		case TokenRedirection:
			if i+1 < len(tokens) {
				target := tokens[i+1].Value
				shellStruct.Redirections = append(shellStruct.Redirections, RedirectionInfo{
					Operator: token.Value,
					Target:   target,
					Position: token.Pos,
				})
				i += 2
				continue
			}

		default:
			// Regular argument
			shellStruct.Arguments = append(shellStruct.Arguments, token.Value)
			i++
		}
	}

	return shellStruct, nil
}
