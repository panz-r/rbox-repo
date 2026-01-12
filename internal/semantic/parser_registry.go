package semantic

import (
	"sync"
)

// ParserRegistry manages command parsers
type ParserRegistry struct {
	parsers map[string]CommandParser
	mu      sync.RWMutex
}

// NewParserRegistry creates a new parser registry
func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: make(map[string]CommandParser),
	}
}

// RegisterParser registers a command parser
func (pr *ParserRegistry) RegisterParser(command string, parser CommandParser) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.parsers[command] = parser
}

// GetParser gets a command parser
func (pr *ParserRegistry) GetParser(command string) CommandParser {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	if parser, exists := pr.parsers[command]; exists {
		return parser
	}

	// Return generic parser for unknown commands
	return &GenericParser{}
}

// ListParsers lists all registered parsers
func (pr *ParserRegistry) ListParsers() []string {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	commands := make([]string, 0, len(pr.parsers))
	for cmd := range pr.parsers {
		commands = append(commands, cmd)
	}
	return commands
}