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
