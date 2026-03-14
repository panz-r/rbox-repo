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

// Logger for server output
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
	socketPath  = flag.String("socket", SocketPath, "Unix socket path")
	verbose     = flag.Bool("v", false, "Verbose: show all commands")
	veryVerbose = flag.Bool("vv", false, "Very verbose: show all commands and logs")
	quiet       = flag.Bool("q", false, "Quiet: only show blocked commands (default)")
	logFile     = flag.String("log", "", "Log file path (empty=disabled)")
	logLevel    = flag.Int("log-level", 0, "Log level: 0=off, 1=errors, 2=info, 3=debug")
	tui         = flag.Bool("tui", false, "Run in TUI mode")
	autoDeny    = flag.Bool("auto-deny", false, "Auto-deny unknown commands (for testing)")
)

const SocketPath = "/tmp/readonlybox.sock"
const ServerVersion = "1.0.0"

func main() {
	flag.Parse()

	gLogger = NewLogger(*logFile, *logLevel)
	if gLogger != nil {
		defer gLogger.Close()
		gLogger.Log(2, "Server starting v%s", ServerVersion)
	}

	if *tui {
		RunTUIMode()
		return
	}

	server, err := NewRBoxServer(*socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("readonlybox-server v1.0 - listening on %s\n", *socketPath)
	os.Chmod(*socketPath, 0666)

	mode := "blocking"
	if *quiet || (!*verbose && !*veryVerbose) {
		mode = "quiet (blocked only)"
	} else if *veryVerbose {
		mode = "very verbose (all commands and logs)"
	} else if *verbose {
		mode = "verbose (all commands)"
	}
	fmt.Printf("Mode: %s\n\n", mode)

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		server.Stop()
		server.Free()
	}()

	// Process requests in a loop
	fmt.Println("Server: Entering request loop...")
	for {
		fmt.Println("Server: Calling GetRequest...")
		req := server.GetRequest()
		fmt.Printf("Server: GetRequest returned %v\n", req)
		if req == nil {
			// Server stopped
			fmt.Println("Server: GetRequest returned nil, exiting loop")
			break
		}
		
		// Check for stop request
		if req.IsStop() {
			fmt.Println("\nShutting down...")
			break
		}

		fmt.Println("Server: Got request!")

		cmd := req.GetCommand()
		caller := req.GetCaller()
		syscall := req.GetSyscall()
		
		// Log caller info if present
		callerInfo := ""
		if caller != "" {
			callerInfo = " [caller: " + caller
			if syscall != "" {
				callerInfo += ", syscall: " + syscall
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
			// Skip args[0] since it's the command itself (shellsplit includes command as first arg)
			for _, arg := range args[1:] {
				fmt.Printf(" %s", arg)
			}
			fmt.Println()
		}

		// Make decision
		decision, reason := makeDecision(cmd, args)
		
		// Make env decisions: auto-deny high-score env vars (score >= 0.8)
		envDecisions := makeEnvDecisions(req)
		
		// Send decision with env decisions
		if err := req.DecideWithEnv(decision, reason, 0, envDecisions); err != nil {
			if gLogger != nil {
				gLogger.Log(1, "Error sending decision: %v", err)
			}
		}

		// Log decision
		if *verbose || *veryVerbose {
			if decision == DecisionDeny {
				fmt.Printf("DENY: %s (%s)\n", cmd, reason)
			} else {
				fmt.Printf("ALLOW: %s\n", cmd)
			}
		}
	}

	fmt.Println("\nShutting down...")
	if gLogger != nil {
		gLogger.Log(2, "Server stopped")
	}
}

// makeDecision determines if a command should be allowed or denied
func makeDecision(cmd string, args []string) (uint8, string) {
	// Empty command
	if cmd == "" {
		return DecisionDeny, "empty command"
	}

	// Check for dangerous patterns in arguments
	for _, arg := range args {
		if arg == "/etc/passwd" || arg == "/etc/shadow" || arg == "/etc/group" {
			return DecisionDeny, "tries to modify system file"
		}
	}

	// Convert to lowercase for matching
	cmdLower := strings.ToLower(cmd)

	// Read-only commands that are always allowed
	readOnlyCmds := map[string]bool{
		"ls": true, "pwd": true, "cd": true, "echo": true, "cat": true,
		"head": true, "tail": true, "less": true, "more": true, "grep": true,
		"find": true, "xargs": true, "tr": true, "cut": true, "join": true,
		"paste": true, "comm": true, "diff": true, "nl": true, "od": true,
		"base64": true, "strings": true,
	}

	if readOnlyCmds[cmdLower] {
		return DecisionAllow, "read-only command"
	}

	// Block dangerous commands
	dangerousCmds := map[string]bool{
		"rm": true, "mv": true, "cp": true, "mkdir": true, "rmdir": true,
		"ln": true, "chmod": true, "chown": true, "touch": true, "dd": true,
	}

	if dangerousCmds[cmdLower] {
		return DecisionDeny, "dangerous command"
	}

	// Auto-deny unknown commands if flag is set
	if *autoDeny {
		return DecisionDeny, "unknown command"
	}

	// Default: allow unknown commands (they'll fail at execution if unsafe)
	return DecisionAllow, "unknown command"
}

// SetDecisionWithAllowance is used by the TUI
var pendingRequests = make(map[int]*RBoxRequest)

// makeEnvDecisions creates env decisions based on flagged env vars from request
// Auto-deny env vars with score >= 0.8
func makeEnvDecisions(req *RBoxRequest) []EnvVarDecision {
	envCount := req.GetEnvVarCount()
	fmt.Printf("DEBUG: makeEnvDecisions called with %d env vars\n", envCount)
	if envCount == 0 {
		return nil
	}
	
	decisions := make([]EnvVarDecision, 0, envCount)
	for i := 0; i < envCount; i++ {
		name := req.GetEnvVarName(i)
		score := req.GetEnvVarScore(i)
		
		// Auto-deny high-score env vars (score >= 0.8)
		decision := uint8(0) // allow
		if score >= 0.8 {
			decision = 1 // deny
		}
		decisions = append(decisions, EnvVarDecision{
			Name:     name,
			Decision: decision,
		})
	}
	return decisions
}

// StoreRequest stores a request for later decision
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
	
	err := req.DecideWithEnv(decision, reason, duration, envDecisions)
	delete(pendingRequests, id)
	return err
}
