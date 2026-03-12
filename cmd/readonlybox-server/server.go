//go:build cgo
// +build cgo

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RecentDecision stores a decision with expiration time
type RecentDecision struct {
	decision   uint8
	reason    string
	expiresAt time.Time
}

// RecentDecisionsCache stores recent decisions for auto-allow/deny
type RecentDecisionsCache struct {
	mu    sync.RWMutex
	cache map[string]RecentDecision
}

var recentDecisions = RecentDecisionsCache{
	cache: make(map[string]RecentDecision),
}

// checkRecentDecision checks if a command has a recent decision
func (c *RecentDecisionsCache) checkRecentDecision(cmd string) (uint8, string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if dec, ok := c.cache[cmd]; ok {
		if time.Now().Before(dec.expiresAt) {
			return dec.decision, dec.reason, true
		}
		// Expired - will be cleaned up lazily
	}
	return 0, "", false
}

// addRecentDecision adds a decision to the cache
func (c *RecentDecisionsCache) addRecentDecision(cmd string, decision uint8, reason string, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[cmd] = RecentDecision{
		decision:   decision,
		reason:    reason,
		expiresAt: time.Now().Add(duration),
	}
}

// cleanupExpired removes expired decisions from cache
func (c *RecentDecisionsCache) cleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	for cmd, dec := range c.cache {
		if now.After(dec.expiresAt) {
			delete(c.cache, cmd)
		}
	}
}

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
	for {
		req := server.GetRequest()
		if req == nil {
			// Server stopped
			break
		}
		
		// Check for stop request
		if req.IsStop() {
			fmt.Println("\nShutting down...")
			break
		}

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

		// Send decision
		if err := req.Decide(decision, reason, 0); err != nil {
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

// StoreRequest stores a request for later decision
func StoreRequest(id int, req *RBoxRequest) {
	pendingRequests[id] = req
}

// MakeDecision sends a decision for a pending request
// duration: time in seconds for time-limited decision (0 = no time limit)
func MakeDecision(id int, allowed bool, reason string, duration uint32) error {
	req, ok := pendingRequests[id]
	if !ok {
		return fmt.Errorf("request not found")
	}
	
	decision := DecisionAllow
	if !allowed {
		decision = DecisionDeny
	}
	
	err := req.Decide(decision, reason, duration)
	delete(pendingRequests, id)
	return err
}
