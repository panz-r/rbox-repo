package command

import (
	"io"
	"os/exec"
)

// Executor interface for executing commands
// This allows us to mock command execution in tests
type Executor interface {
	Command(name string, arg ...string) *exec.Cmd
	Run(cmd *exec.Cmd) error
	SetStdout(cmd *exec.Cmd, stdout io.Writer)
	SetStderr(cmd *exec.Cmd, stderr io.Writer)
	SetStdin(cmd *exec.Cmd, stdin io.Reader)
}

// RealExecutor implements Executor using real system commands
type RealExecutor struct{}

func (e *RealExecutor) Command(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}

func (e *RealExecutor) Run(cmd *exec.Cmd) error {
	return cmd.Run()
}

func (e *RealExecutor) SetStdout(cmd *exec.Cmd, stdout io.Writer) {
	cmd.Stdout = stdout
}

func (e *RealExecutor) SetStderr(cmd *exec.Cmd, stderr io.Writer) {
	cmd.Stderr = stderr
}

func (e *RealExecutor) SetStdin(cmd *exec.Cmd, stdin io.Reader) {
	cmd.Stdin = stdin
}

// MockExecutor implements Executor for testing without real system commands
type MockExecutor struct {
	CommandsRun [][]string
	ShouldFail  bool
	ExitCode    int
}

func (e *MockExecutor) Command(name string, arg ...string) *exec.Cmd {
	// Record the command that would be run
	fullCommand := append([]string{name}, arg...)
	e.CommandsRun = append(e.CommandsRun, fullCommand)

	// Return a mock command
	return &exec.Cmd{}
}

func (e *MockExecutor) Run(cmd *exec.Cmd) error {
	if e.ShouldFail {
		return &exec.ExitError{}
	}
	return nil
}

func (e *MockExecutor) SetStdout(cmd *exec.Cmd, stdout io.Writer) {
	// No-op for mock
}

func (e *MockExecutor) SetStderr(cmd *exec.Cmd, stderr io.Writer) {
	// No-op for mock
}

func (e *MockExecutor) SetStdin(cmd *exec.Cmd, stdin io.Reader) {
	// No-op for mock
}

// GetRealExecutor returns a real command executor
func GetRealExecutor() Executor {
	return &RealExecutor{}
}

// GetMockExecutor returns a mock command executor for testing
func GetMockExecutor() *MockExecutor {
	return &MockExecutor{
		CommandsRun: make([][]string, 0),
		ShouldFail:  false,
	}
}