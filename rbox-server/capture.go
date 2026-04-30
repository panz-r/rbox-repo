//go:build capture

package main

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// captureEntry is one JSON Lines record per request/response pair.
type captureEntry struct {
	ID            uint64              `json:"id"`
	Ts            string              `json:"ts"`
	Cmd           string              `json:"cmd"`
	Args          []string            `json:"args"`
	Caller        string              `json:"caller"`
	Syscall       string              `json:"syscall"`
	EnvCount      int                 `json:"env_count"`
	EnvVars       []captureEnvVar     `json:"env_vars"`
	Decision      string              `json:"decision"`
	Reason        string              `json:"reason"`
	DurationMs    uint32              `json:"duration_ms"`
	EnvDecisions  []int               `json:"env_decisions"`
}

type captureEnvVar struct {
	Name  string  `json:"name"`
	Score float32 `json:"score"`
}

// Capture writes every request/response pair to a JSON Lines file.
type Capture struct {
	mu      sync.Mutex
	file    *os.File
	enc     *json.Encoder
	seq     atomic.Uint64
	enabled bool
}

var captureInstance *Capture

// InitCapture opens the capture file. Returns nil if path is empty.
func InitCapture(path string) error {
	if path == "" {
		return nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	captureInstance = &Capture{
		file:    f,
		enc:     json.NewEncoder(f),
		enabled: true,
	}
	return nil
}

// CloseCapture flushes and closes the capture file.
func CloseCapture() {
	if captureInstance != nil {
		captureInstance.Close()
		captureInstance = nil
	}
}

// CaptureEnabled returns true if capture is active.
func CaptureEnabled() bool {
	return captureInstance != nil && captureInstance.enabled
}

// CaptureRequest logs a request/response pair to the capture file.
// Called after the decision is made but before req.Decide() (which frees the C handle).
func CaptureRequest(
	cmd string,
	args []string,
	caller string,
	syscallName string,
	envCount int,
	envNames []string,
	envScores []float32,
	decision uint8,
	reason string,
	duration uint32,
	envDecisions []EnvVarDecision,
) {
	if captureInstance == nil || !captureInstance.enabled {
		return
	}
	captureInstance.write(cmd, args, caller, syscallName, envCount, envNames, envScores, decision, reason, duration, envDecisions)
}

func (c *Capture) write(
	cmd string,
	args []string,
	caller string,
	syscallName string,
	envCount int,
	envNames []string,
	envScores []float32,
	decision uint8,
	reason string,
	duration uint32,
	envDecisions []EnvVarDecision,
) {
	id := c.seq.Add(1)

	entry := captureEntry{
		ID:       id,
		Ts:       time.Now().UTC().Format(time.RFC3339Nano),
		Cmd:      cmd,
		Args:     args,
		Caller:   caller,
		Syscall:  syscallName,
		EnvCount: envCount,
		Decision: decisionString(decision),
		Reason:   reason,
		DurationMs: duration,
	}

	if envCount > 0 && len(envNames) == envCount {
		entry.EnvVars = make([]captureEnvVar, envCount)
		for i := 0; i < envCount; i++ {
			entry.EnvVars[i] = captureEnvVar{Name: envNames[i], Score: envScores[i]}
		}
	}

	for i, d := range envDecisions {
		if d.Decision == 1 {
			entry.EnvDecisions = append(entry.EnvDecisions, i)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.enc.Encode(entry)
}

func (c *Capture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = false
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}

func decisionString(d uint8) string {
	switch d {
	case DecisionAllow:
		return "ALLOW"
	case DecisionDeny:
		return "DENY"
	case DecisionError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}
