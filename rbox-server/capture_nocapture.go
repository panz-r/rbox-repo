//go:build !capture

package main

// Stubs when capture is not compiled in — zero overhead.

func InitCapture(path string) error { return nil }
func CloseCapture()                 {}
func CaptureEnabled() bool          { return false }

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
}
