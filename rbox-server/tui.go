package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/panz-r/rbox-repo/rbox-server/shell"
)

type CommandLog struct {
	Timestamp        time.Time
	Decision         string
	Command          string
	Args             string
	Caller           string
	Syscall          string
	Reason           string
	Duration         uint32 // Duration choice for retry
	ClientID         string
	RequestID        int
	Cwd              string
	EnvVars          []EnvVarInfo      // Flagged env vars from request
	EnvDecisions     []EnvVarDecision  // User's decisions on env vars
	IntendedDecision string            // "ALLOW" or "DENY" for retries
	OriginalReason   string            // original reason (e.g., "once") for retries
	RetryCount       int               // number of retry attempts made
	EvalResult       *shell.EvalResult // shellgate analysis
}

type EnvVarInfo struct {
	Name  string
	Score float32
}

// EnvVarDecision holds the user's decision on an env var
type EnvVarDecision struct {
	Name     string
	Decision uint8 // 0 = allow, 1 = deny
}

type Stats struct {
	totalAllowed int
	totalDenied  int
	totalUnknown int
}

// OpMode represents the operational mode of the TUI
type OpMode int

const (
	OpModeInteractive OpMode = iota // Current behavior: waits for user input
	OpModePassthrough               // Allows everything without involvement
	OpModeAuto                      // Policy-based, auto-denies what needs user input
)

const (
	opModeInteractiveText = "Interactive"
	opModePassthroughText = "Passthrough"
	opModeAutoText        = "Auto"
)

func (m OpMode) String() string {
	switch m {
	case OpModePassthrough:
		return opModePassthroughText
	case OpModeAuto:
		return opModeAutoText
	default:
		return opModeInteractiveText
	}
}

func (m OpMode) Description() string {
	switch m {
	case OpModePassthrough:
		return "Allow all requests without user involvement"
	case OpModeAuto:
		return "Allow/deny by policy, auto-deny requests needing user input"
	default:
		return "Wait for user input on each request"
	}
}

type EventType int

const (
	EventNewRequest EventType = iota
	EventAddPendingRetry
)

const (
	MaxHistory          = 500
	FlashTimerSeconds   = 3
	EventChanBufferSize = 100
	TruncateWidth       = 30
	MinTruncateWidth    = 20
	DefaultPadding      = 30
	Duration15Minutes   = 900
	Duration1Hour       = 3600
	Duration4Hours      = 14400
)

type Event struct {
	Type               EventType
	Command            string
	Args               string
	Caller             string
	Syscall            string
	RequestID          int
	ClientID           string
	Cwd                string
	EnvVars            []EnvVarInfo
	Req                *RBoxRequest
	RetryDecision      string
	RetryReason        string
	RetryDuration      uint32
	RetryEnvDecisions  []EnvVarDecision
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF79C6")).
			Padding(0, 1)

	allowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#50FA7B")).
			MarginLeft(2)

	denyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5555")).
			MarginLeft(2)

	allowSelectedStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#50FA7B")).
				Foreground(lipgloss.Color("#000000")).
				Padding(0, 1).
				MarginLeft(2)

	denySelectedStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#FF5555")).
				Foreground(lipgloss.Color("#000000")).
				Padding(0, 1).
				MarginLeft(2)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8BE9FD"))

	cardStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#44475A")).
			Padding(0, 1)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4")).
			Padding(0, 1)

	editStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#50FA7B")) // green to match allowStyle

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#44475A")).
			Foreground(lipgloss.Color("#F8F8F2"))
)

// --- Helper functions ---

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampScrollY(scrollY, maxHeight, totalItems int) int {
	maxScrollY := maxInt(0, totalItems-maxHeight)
	if scrollY > maxScrollY {
		return maxScrollY
	}
	if scrollY < 0 {
		return 0
	}
	return scrollY
}

// extractBaseName returns the basename of a path or command name
func extractBaseName(path string) string {
	if path == "" {
		return ""
	}
	// Handle [appname:syscall] prefix
	if strings.HasPrefix(path, "[") {
		endBracket := strings.Index(path, "]")
		if endBracket > 0 {
			path = path[endBracket+1:]
			path = strings.TrimPrefix(path, " ")
		}
	}
	// First, extract the first whitespace-delimited token (the command name)
	// e.g., "git rev-parse --abbrev-ref HEAD" -> "git"
	// e.g., "/usr/bin/git remote get-url origin" -> "/usr/bin/git"
	firstToken := path
	if idx := strings.Index(path, " "); idx > 0 {
		firstToken = path[:idx]
	}

	// Now extract basename from the first token only
	// e.g., "/usr/bin/git" -> "git"
	// e.g., "git" -> "git"
	// This avoids incorrectly matching / in git refs like "origin/HEAD"
	if idx := strings.LastIndex(firstToken, "/"); idx >= 0 {
		return firstToken[idx+1:]
	}
	return firstToken
}

func truncateString(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return strings.Repeat(".", maxWidth)
	}
	return string(runes[:maxWidth-3]) + "..."
}

// durationToReason returns the decision, reason, and duration (in seconds) for a given choice
// choice: 0=once, 1=15m, 2=1h, 3=4h, 5=session, 6=always, 7=pattern
func durationToReason(allow bool, choice int) (decision, reason string, duration uint32) {
	if allow {
		decision = "ALLOW"
	} else {
		decision = "DENY"
	}

	switch choice {
	case 0:
		reason = "once"
		duration = 0
	case 1:
		reason = "15m"
		duration = Duration15Minutes
	case 2:
		reason = "1h"
		duration = Duration1Hour
	case 3:
		reason = "4h"
		duration = Duration4Hours
	default:
		reason = "unknown"
	}
	return
}

// gateAddDefaults adds default allow rules to the gate.
func gateAddDefaults(gate *shell.Gate) {
	if gate == nil {
		return
	}
	defaultRules := []string{
		"ls #path",
		"pwd",
		"whoami",
		"man #any",
		"which #any",
		"type #any",
		"echo #any",
		"cat --help",
		"head --help",
		"tail --help",
		"grep --help",
		"find --help",
	}
	for _, r := range defaultRules {
		if err := gate.AddRule(r); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to add default rule %q: %v\n", r, err)
			return
		}
	}
}

func RunTUIMode() {
	// Determine socket path using same logic as main()
	sock := getSocketPath(*socketPath, *systemSocket, *userSocket)

	// Start the C library server
	server, err := NewRBoxServer(sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("readonlybox-server v%s - TUI mode\n", ServerVersion)
	fmt.Println("Listening on:", sock)

	// Create shellgate for command analysis
	gate, gateErr := shell.NewGate()
	if gateErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: shellgate init failed (analysis disabled): %v\n", gateErr)
	}
	if gate != nil {
		gateAddDefaults(gate)
	}

	// Create router
	router := NewRouter(gate)

	// Start TUI
	p := tea.NewProgram(
		router,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Goroutine: forward events to TUI
	go func() {
		for event := range router.eventChan {
			p.Send(event)
		}
	}()

	// Goroutine: handle requests and send events to TUI
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		requestID := 0
		for {
			req := server.GetRequest()
			if req == nil {
				// Server stopped - exit loop
				break
			}

			requestID++

			cmd := req.GetCommand()
			argc := req.GetArgc()
			args := make([]string, argc)
			for i := 0; i < argc; i++ {
				args[i] = req.GetArg(i)
			}
			argsStr := ""
			if len(args) > 1 {
				argsStr = strings.Join(args[1:], " ")
			}

			// Get caller and syscall from request (v7 protocol)
			caller := req.GetCaller()
			syscall := req.GetSyscall()

			// Get flagged env vars from request (v8 protocol)
			envVarCount := req.GetEnvVarCount()
			envVars := make([]EnvVarInfo, envVarCount)
			for i := 0; i < envVarCount; i++ {
				envVars[i] = EnvVarInfo{
					Name:  req.GetEnvVarName(i),
					Score: req.GetEnvVarScore(i),
				}
			}

			// Shellgate evaluation happens in the event handler (safe single-threaded gate access)
			router.eventChan <- Event{
				Type:      EventNewRequest,
				RequestID: requestID,
				Req:       req,
				Command:   cmd,
				Args:      argsStr,
				Caller:    caller,
				Syscall:   syscall,
				EnvVars:   envVars,
			}
		}
	}()

	// Run TUI (blocks until exit)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	// Restore cursor visibility before shutdown
	fmt.Print("\033[?25h")

	// Stop server first to unblock the request goroutine
	server.Stop()
	// Wait for goroutine to exit before closing the channel
	<-requestDone
	close(router.eventChan)

	fmt.Println("\nShutting down...")
	if router.gate != nil {
		router.gate.Close()
	}
	server.Free()
}