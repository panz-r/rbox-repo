//go:build cgo
// +build cgo

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractBaseName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Simple command", "ls", "ls"},
		{"Path with command", "/usr/bin/git", "git"},
		{"Command with args", "git commit", "git"},
		{"Caller prefix", "[git:commit] git commit", "git"},
		{"Empty string", "", ""},
		{"Path only", "/usr/local/bin", "bin"},
		{"Git with multiple args", "[git:push] git push origin main", "git"},
		{"Just brackets and command", "[app] command", "command"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractBaseName(tt.input))
		})
	}
}

func TestClampScrollY(t *testing.T) {
	tests := []struct {
		name       string
		scrollY    int
		maxHeight  int
		totalItems int
		expected   int
	}{
		{"Normal case", 5, 10, 20, 5},
		{"Scroll past max", 15, 10, 20, 10},
		{"Negative scroll", -5, 10, 20, 0},
		{"Total less than height", 0, 10, 5, 0},
		{"Scroll at boundary", 10, 10, 20, 10},
		{"Empty list", 0, 10, 0, 0},
		{"Single item", 0, 10, 1, 0},
		{"Scroll negative at boundary", -10, 10, 20, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := clampScrollY(tt.scrollY, tt.maxHeight, tt.totalItems)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxWidth int
		expected string
	}{
		{"Short string", "hello", 10, "hello"},
		{"Exact width", "hello", 5, "hello"},
		{"Long string truncated", "hello world", 8, "hello..."},
		{"Very long", "this is a very long string", 10, "this is..."},
		{"Empty string", "", 10, ""},
		{"Width 3 or less", "hello", 3, "..."},
		{"Width 4", "hello", 4, "h..."},
		{"Width 5", "hello", 5, "hello"},
		{"Width 6", "hello world", 6, "hel..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxWidth)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDurationToReason(t *testing.T) {
	testsAllow := []struct {
		choice   int
		decision string
		reason   string
		duration uint32
	}{
		{0, "ALLOW", "once", 0},
		{1, "ALLOW", "15m", 900},
		{2, "ALLOW", "1h", 3600},
		{3, "ALLOW", "4h", 14400},
		{5, "ALLOW", "session", 0},
		{6, "ALLOW", "always", 0},
		{7, "ALLOW", "pattern", 0},
	}

	for _, tt := range testsAllow {
		t.Run("allow_"+tt.reason, func(t *testing.T) {
			decision, reason, duration := durationToReason(true, tt.choice)
			assert.Equal(t, tt.decision, decision)
			assert.Equal(t, tt.reason, reason)
			assert.Equal(t, tt.duration, duration)
		})
	}

	testsDeny := []struct {
		choice   int
		decision string
		reason   string
		duration uint32
	}{
		{0, "DENY", "once", 0},
		{1, "DENY", "15m", 900},
		{2, "DENY", "1h", 3600},
		{3, "DENY", "4h", 14400},
		{5, "DENY", "session", 0},
		{6, "DENY", "always", 0},
		{7, "DENY", "pattern", 0},
	}

	for _, tt := range testsDeny {
		t.Run("deny_"+tt.reason, func(t *testing.T) {
			decision, reason, duration := durationToReason(false, tt.choice)
			assert.Equal(t, tt.decision, decision)
			assert.Equal(t, tt.reason, reason)
			assert.Equal(t, tt.duration, duration)
		})
	}

	// Test default case
	t.Run("unknown_choice", func(t *testing.T) {
		decision, reason, duration := durationToReason(true, 99)
		assert.Equal(t, "ALLOW", decision)
		assert.Equal(t, "unknown", reason)
		assert.Equal(t, uint32(0), duration)
	})
}

func TestNewModel(t *testing.T) {
	model := NewModel()
	assert.NotNil(t, model)
	assert.Empty(t, model.commands)
	assert.Empty(t, model.logs)
	assert.Equal(t, 1, model.step)
	assert.Equal(t, 0, model.cursor)
	assert.Equal(t, 0, model.selectedIdx)
	assert.Equal(t, "history", model.focus)
	assert.NotNil(t, model.eventChan)
	assert.Empty(t, model.pendingRetry)
}

func TestAddCommand(t *testing.T) {
	model := NewModel()

	// Add first command
	model.AddCommand("ALLOW", "ls", "-l", "", "", "read-only command", "", "", 1, nil)
	assert.Len(t, model.commands, 1)
	assert.Equal(t, "ALLOW", model.commands[0].Decision)
	assert.Equal(t, "ls", model.commands[0].Command)
	assert.Equal(t, "-l", model.commands[0].Args)
	assert.Equal(t, 0, model.selectedIdx)

	// Add second command - should be selected
	model.AddCommand("DENY", "rm", "-rf /", "", "", "dangerous command", "", "", 2, nil)
	assert.Len(t, model.commands, 2)
	assert.Equal(t, 1, model.selectedIdx)

	// Stats should count pending
	model.AddCommand("PENDING", "git", "status", "", "", "waiting for decision", "", "", 3, nil)
	assert.Equal(t, 1, model.stats.totalUnknown)
}

func TestAddLog(t *testing.T) {
	model := NewModel()
	model.AddLog("Test log entry")
	assert.Len(t, model.logs, 1)
	assert.Equal(t, "Test log entry", model.logs[0])

	// Test MaxLogs limit
	for i := 0; i < 60; i++ {
		model.AddLog("entry")
	}
	assert.Len(t, model.logs, 50) // Should be capped at MaxLogs
}

func TestParsePipeline(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedFileOps string
		expectedSyscall string
	}{
		{
			name:            "Simple ls",
			input:           "ls -l",
			expectedFileOps: "Lists: -l",
			expectedSyscall: "",
		},
		{
			name:            "Git status",
			input:           "git status",
			expectedFileOps: "Reads: .git (status)",
			expectedSyscall: "",
		},
		{
			name:            "Git commit (not read-only)",
			input:           "git commit -m 'fix bug'",
			expectedFileOps: "Reads/Writes: .git (commit)",
			expectedSyscall: "",
		},
		{
			name:            "Git push (affects remote)",
			input:           "git push origin main",
			expectedFileOps: "Reads: .git, Writes: remote (push)",
			expectedSyscall: "",
		},
		{
			name:            "Find command",
			input:           "find /home -name *.txt",
			expectedFileOps: "Searches: /home",
			expectedSyscall: "",
		},
		{
			name:            "Ls with path",
			input:           "ls /tmp",
			expectedFileOps: "Lists: /tmp",
			expectedSyscall: "",
		},
		{
			name:            "Cat file",
			input:           "cat /etc/passwd",
			expectedFileOps: "Reads: /etc/passwd",
			expectedSyscall: "",
		},
		{
			name:            "Grep recursive",
			input:           "grep -r error /var/log",
			expectedFileOps: "Searches: ./*",
			expectedSyscall: "",
		},
		{
			name:            "Ps command",
			input:           "ps aux",
			expectedFileOps: "Reads: /proc/*",
			expectedSyscall: "",
		},
		{
			name:            "With caller prefix",
			input:           "[git:commit] git commit -m 'test'",
			expectedFileOps: "Reads/Writes: .git (commit)",
			expectedSyscall: "commit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePipeline(tt.input)
			assert.Equal(t, tt.expectedFileOps, result.FileOps)
			assert.Equal(t, tt.expectedSyscall, result.Syscall)
			assert.NotEmpty(t, result.Stages)
		})
	}
}

func TestGeneratePipelineOutput(t *testing.T) {
	analysis := PipelineAnalysis{
		Original: "ls -l",
		Stages: []PipelineStage{
			{Command: "ls", Args: []string{"-l"}},
		},
		FileOps: "",
	}

	lines := generatePipelineOutput(analysis)
	assert.NotEmpty(t, lines)
	assert.Contains(t, lines[0], "$ ls -l")
	assert.Contains(t, lines[len(lines)-1], "Intent:")
}

func TestMinInt(t *testing.T) {
	assert.Equal(t, 5, minInt(5, 10))
	assert.Equal(t, 5, minInt(10, 5))
	assert.Equal(t, 5, minInt(5, 5))
	assert.Equal(t, -5, minInt(-5, 5))
	assert.Equal(t, 0, minInt(0, 5))
}

func TestMaxInt(t *testing.T) {
	assert.Equal(t, 10, maxInt(5, 10))
	assert.Equal(t, 10, maxInt(10, 5))
	assert.Equal(t, 5, maxInt(5, 5))
	assert.Equal(t, 5, maxInt(-5, 5))
	assert.Equal(t, 5, maxInt(0, 5))
}
