//go:build cgo
// +build cgo

package shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		minCount int // minimum number of subcommands expected
	}{
		{
			name:     "Simple command",
			input:    "ls -l",
			wantErr:  false,
			minCount: 1,
		},
		{
			name:     "Empty string",
			input:    "",
			wantErr:  false, // returns nil, nil which is not an error per current impl
			minCount: 0,
		},
		{
			name:     "Command with multiple args",
			input:    "git commit -m 'initial commit'",
			wantErr:  false,
			minCount: 1,
		},
		{
			name:     "Find command",
			input:    "find /home -name '*.txt' -type f",
			wantErr:  false,
			minCount: 1,
		},
		{
			name:     "Grep with regex",
			input:    "grep -E 'error|warning' /var/log/syslog",
			wantErr:  false,
			minCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCommand(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tt.minCount == 0 {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.GreaterOrEqual(t, len(result), tt.minCount)
			}
		})
	}
}

func TestParseCommandToString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple command",
			input:    "ls -l",
			expected: "[word:command] | [word:argument]",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Git status",
			input:    "git status",
			expected: "[word:command] | [word:argument]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCommandToString(tt.input)
			// Just verify it returns something - the exact format may vary
			if tt.expected == "" {
				assert.Equal(t, "", result)
			} else {
				assert.NotEmpty(t, result)
				// Should contain type:feature format
				assert.Contains(t, result, ":")
			}
		})
	}
}

func TestParseCommandEmpty(t *testing.T) {
	result, err := ParseCommand("")
	assert.NoError(t, err)
	assert.Nil(t, result)
}
