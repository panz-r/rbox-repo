//go:build cgo
// +build cgo

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type Logger struct {
	file     *os.File
	logLevel int
}

func NewLogger(filename string, level int) *Logger {
	if filename == "" || level == 0 {
		return nil
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil
	}
	return &Logger{file: f, logLevel: level}
}

func (l *Logger) Log(level int, format string, args ...interface{}) {
	if l == nil || l.file == nil || level > l.logLevel {
		return
	}
	fmt.Fprintf(l.file, format+"\n", args...)
}

func (l *Logger) Close() {
	if l != nil && l.file != nil && l.file != os.Stderr && l.file != os.Stdout {
		l.file.Close()
	}
}

var gLogger *Logger

var (
	socketPath   = flag.String("socket", "", "Unix socket path (overrides env and defaults)")
	verbose      = flag.Bool("v", false, "Verbose: show all commands")
	veryVerbose  = flag.Bool("vv", false, "Very verbose: show all commands and logs")
	quiet        = flag.Bool("q", false, "Quiet: only show blocked commands (default)")
	logFile      = flag.String("log", "", "Log file path (empty=disabled)")
	logLevel     = flag.Int("log-level", 0, "Log level: 0=off, 1=errors, 2=info, 3=debug")
	tui          = flag.Bool("tui", false, "Run in TUI mode")
	autoDeny     = flag.Bool("auto-deny", false, "Auto-deny unknown commands (for testing)")
	testEnvDeny  = flag.String("test-env-deny", "", "Bitmap of env var indices to deny (for testing, e.g., '1,3' denies indices 1 and 3)")
	systemSocket = flag.Bool("system-socket", false, "Use system socket /run/readonlybox/readonlybox.sock")
	userSocket   = flag.Bool("user-socket", false, "Use user socket $XDG_RUNTIME_DIR/readonlybox.sock")
	logReader    = flag.Bool("log-reader", false, "Output machine-readable ALLOW/DENY lines to stdout")
	capturePath  = flag.String("capture", "", "Capture all requests/decisions to JSON Lines file (requires capture build tag)")
)

const (
	ServerVersion    = "1.0.0"
	SystemSocketPath = "/run/readonlybox/readonlybox.sock"
	EnvSocket        = "READONLYBOX_SOCKET"
)

// getSocketPath returns the socket path following priority:
// 1. cmd_socket (explicit --socket path) - highest priority
// 2. --system-socket -> SYSTEM_SOCKET
// 3. --user-socket -> XDG_RUNTIME_DIR/readonlybox.sock (if set), else SYSTEM_SOCKET
// 4. READONLYBOX_SOCKET env var
// 5. XDG_RUNTIME_DIR/readonlybox.sock (if XDG_RUNTIME_DIR is set)
// 6. System default
func getSocketPath(cmdSocket string, forceSystem, forceUser bool) string {
	// 1. Explicit --socket path
	if cmdSocket != "" {
		return cmdSocket
	}

	// 2. --system-socket
	if forceSystem {
		return SystemSocketPath
	}

	// 3. --user-socket
	if forceUser {
		if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
			return xdgRuntime + "/readonlybox.sock"
		}
		// Fall back to system path if XDG_RUNTIME_DIR not set
		return SystemSocketPath
	}

	// 4. READONLYBOX_SOCKET env var
	if sock := os.Getenv(EnvSocket); sock != "" {
		return sock
	}

	// 5. XDG_RUNTIME_DIR
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		return xdgRuntime + "/readonlybox.sock"
	}

	// 6. System default
	return SystemSocketPath
}

func main() {
	flag.Parse()

	// Determine socket path
	resolvedSocketPath := getSocketPath(*socketPath, *systemSocket, *userSocket)
	fmt.Printf("Using socket: %s\n", resolvedSocketPath)

	gLogger = NewLogger(*logFile, *logLevel)
	if gLogger != nil {
		defer gLogger.Close()
		gLogger.Log(2, "Server starting v%s", ServerVersion)
	}

	// Initialize capture (no-op if --capture is empty or build tag is absent)
	if err := InitCapture(*capturePath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to open capture file: %v\n", err)
		os.Exit(1)
	}
	defer CloseCapture()
	if CaptureEnabled() {
		fmt.Printf("Capture: %s\n", *capturePath)
	}

	if *tui {
		RunTUIMode()
		return
	}

	server, err := NewRBoxServer(resolvedSocketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("readonlybox-server v1.0 - listening on %s\n", resolvedSocketPath)
	if err := os.Chmod(resolvedSocketPath, 0666); err != nil {
		gLogger.Log(1, "Warning: chmod failed: %v", err)
	}

	policyStr := "auto-allow"
	if *autoDeny {
		policyStr = "auto-deny"
	}
	mode := "quiet"
	if *veryVerbose {
		mode = "very verbose"
	} else if *verbose {
		mode = "verbose"
	}
	fmt.Printf("Mode: %s, %s (unknown commands %s)\n\n", mode, policyStr,
		map[bool]string{true: "denied", false: "allowed"}[*autoDeny])

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		server.Stop()
		server.Free()
	}()

	// Process requests in a loop
	for {
		req := server.GetRequest()
		if req == nil {
			// Server stopped
			break
		}

		// Check for stop request
		if req.IsStop() {
			break
		}

		cmd := req.GetCommand()
		caller := req.GetCaller()
		syscallName := req.GetSyscall()

		// Log caller info if present
		callerInfo := ""
		if caller != "" {
			callerInfo = " [caller: " + caller
			if syscallName != "" {
				callerInfo += ", syscall: " + syscallName
			}
			callerInfo += "]"
		}

		argc := req.GetArgc()

		args := make([]string, argc)
		for i := 0; i < argc; i++ {
			args[i] = req.GetArg(i)
		}

		// Log request if verbose
		if *verbose || *veryVerbose {
			fmt.Printf("Request: %s%s", cmd, callerInfo)
			if len(args) > 1 {
				for _, arg := range args[1:] {
					fmt.Printf(" %s", arg)
				}
			}
			fmt.Println()
		}

		// Make decision
		decision, reason := makeNoninteractiveDecision(cmd, args, *autoDeny)

		// Make env decisions: auto-deny high-score env vars (score >= 0.8)
		envDecisions := makeEnvDecisions(req)

		// Capture request+decision before req.Decide frees the C handle
		if CaptureEnabled() {
			envCount := req.GetEnvVarCount()
			envNames := make([]string, envCount)
			envScores := make([]float32, envCount)
			for i := 0; i < envCount; i++ {
				envNames[i] = req.GetEnvVarName(i)
				envScores[i] = req.GetEnvVarScore(i)
			}
			var argsSlice []string
			if len(args) > 1 {
				argsSlice = args[1:]
			}
			CaptureRequest(cmd, argsSlice, caller, syscallName, envCount, envNames, envScores, decision, reason, 0, envDecisions)
		}

		// Send decision with env decisions
		if err := req.Decide(decision, reason, 0, envDecisions); err != nil {
			if gLogger != nil {
				gLogger.Log(1, "Error sending decision: %v", err)
			}
		}

		// Log decision
		if *verbose || *veryVerbose {
			// When log-reader mode is enabled, skip verbose output to avoid duplication
			// The machine-readable format below provides clean counting
			if !*logReader {
				if decision == DecisionDeny {
					fmt.Printf("DENY: %s (%s)\n", cmd, reason)
				} else {
					fmt.Printf("ALLOW: %s\n", cmd)
				}
			}
		}

		// Log-reader output: machine-readable format
		if *logReader {
			if decision == DecisionDeny {
				fmt.Fprintf(os.Stdout, "DENY:%s\n", cmd)
			} else {
				fmt.Fprintf(os.Stdout, "ALLOW:%s\n", cmd)
			}
		}
	}

	fmt.Println("\nShutting down...")
	if gLogger != nil {
		gLogger.Log(2, "Server stopped")
	}
}

// ========================================================================
// NON-INTERACTIVE MODE FUNCTIONS
// ========================================================================

// makeNoninteractiveDecision determines if a command should be allowed or denied
// This is ONLY used in non-interactive (non-TUI) mode for automatic decisions
func makeNoninteractiveDecision(cmd string, args []string, autoDeny bool) (uint8, string) {
	if cmd == "" {
		return DecisionDeny, "empty command"
	}

	// Auto-deny unknown commands if flag is set, otherwise allow
	if autoDeny {
		return DecisionDeny, "unknown command"
	}

	return DecisionAllow, "unknown command"
}

// makeEnvDecisions creates env decisions based on flagged env vars from request
// If testEnvDeny flag is set, use that bitmap to deny specific indices
// Otherwise auto-deny env vars with score >= 0.8
func makeEnvDecisions(req *RBoxRequest) []EnvVarDecision {
	envCount := req.GetEnvVarCount()
	if envCount == 0 {
		return nil
	}

	// Parse test-env-deny bitmap if set
	testDenyMap := make(map[int]bool)
	if *testEnvDeny != "" {
		parts := strings.Split(*testEnvDeny, ",")
		for _, p := range parts {
			var idx int
			if _, err := fmt.Sscanf(p, "%d", &idx); err == nil {
				testDenyMap[idx] = true
			}
		}
	}

	decisions := make([]EnvVarDecision, 0, envCount)
	for i := 0; i < envCount; i++ {
		name := req.GetEnvVarName(i)
		score := req.GetEnvVarScore(i)

		decision := uint8(0) // allow

		// Use test bitmap if set
		if len(testDenyMap) > 0 {
			if testDenyMap[i] {
				decision = 1 // deny
			}
		} else {
			// Auto-deny high-score env vars (score >= 0.8)
			if score >= 0.8 {
				decision = 1 // deny
			}
		}

		decisions = append(decisions, EnvVarDecision{
			Name:     name,
			Decision: decision,
		})
	}
	return decisions
}

// ========================================================================
// TUI MODE FUNCTIONS
// ========================================================================

// pendingRequests stores requests for TUI decision
// These are accessed by MakeDecision() when user responds in TUI
// Access is synchronized through the TUI event loop
var pendingRequests = make(map[int]*RBoxRequest)

// StoreRequest stores a request for later decision
// Must be called from the TUI event loop
func StoreRequest(id int, req *RBoxRequest) {
	pendingRequests[id] = req
}

// MakeDecision sends a decision for a pending request
// duration: time in seconds for time-limited decision (0 = no time limit)
func MakeDecision(id int, allowed bool, reason string, duration uint32, envDecisions []EnvVarDecision) error {
	req, ok := pendingRequests[id]
	if !ok {
		return fmt.Errorf("request not found")
	}

	decision := DecisionAllow
	if !allowed {
		decision = DecisionDeny
	}

	err := req.Decide(decision, reason, duration, envDecisions)
	if err == nil {
		delete(pendingRequests, id)
	}
	return err
}
