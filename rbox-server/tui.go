package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type PipelineStage struct {
	Operator string
	Command  string
	Args     []string
	Stdin    string
	Stdout   string
}

type PipelineAnalysis struct {
	Original string
	Stages   []PipelineStage
	FileOps  string
	Flow     string
	Syscall  string
}

type GrepCommand struct {
	Pattern      string
	InputFiles   []string
	Options      map[string]interface{}
	UseRecursive bool
}

type GrepParser struct{}

type GitCommand struct {
	Subcommand    string
	Options       map[string]interface{}
	Arguments     []string
	IsReadOnly    bool
	AffectsRemote bool
	AffectsRepo   bool
}

type GitParser struct{}

type ClaudeCommand struct {
	Version    string
	Subcommand string
	Args       []string
	Target     string
	IsReadOnly bool
}

type ClaudeParser struct{}

func (c *ClaudeParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for claude")
	}

	cmd := &ClaudeCommand{
		Args:       args,
		IsReadOnly: true,
	}

	/* Check if first arg looks like a version number (X.Y.Z) */
	if len(args[0]) > 0 && strings.Contains(args[0], ".") {
		parts := strings.Split(args[0], ".")
		if len(parts) >= 2 {
			/* Looks like a version number - this is claude syntax */
			cmd.Version = args[0]

			/* Next arg is subcommand */
			if len(args) > 1 {
				cmd.Subcommand = args[1]

				/* Parse subcommand-specific args */
				i := 2
				for i < len(args) && strings.HasPrefix(args[i], "-") {
					i++
				}

				/* Remaining args are targets */
				if i < len(args) {
					cmd.Target = args[i]
				}
			}

			return cmd, nil
		}
	}

	return nil, fmt.Errorf("not a claude command")
}

func (g *GitParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for git")
	}

	cmd := &GitCommand{
		Options: make(map[string]interface{}),
	}

	cmd.Subcommand = args[0]
	cmd.determineCommandCharacteristics()

	i := 1
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]
		switch opt {
		case "--help", "-h":
			cmd.Options["help"] = true
		case "--version", "-v":
			cmd.Options["version"] = true
		case "--verbose":
			cmd.Options["verbose"] = true
		case "--dry-run":
			cmd.Options["dry_run"] = true
		case "--force", "-f":
			cmd.Options["force"] = true
			if cmd.IsReadOnly {
				cmd.IsReadOnly = false
			}
		default:
			if len(opt) > 1 {
				cmd.Options[opt] = true
			}
		}
		i++
	}

	if i < len(args) {
		cmd.Arguments = args[i:]
	}

	return cmd, nil
}

func (g *GitCommand) determineCommandCharacteristics() {
	readOnlyCommands := []string{
		"log", "show", "diff", "status", "grep", "blame", "annotate",
		"branch", "tag", "ls-files", "ls-tree", "cat-file",
		"config", "remote", "ls-remote", "archive",
	}

	for _, safeCmd := range readOnlyCommands {
		if g.Subcommand == safeCmd {
			g.IsReadOnly = true
			return
		}
	}

	remoteCommands := []string{"push", "fetch", "pull", "clone", "ls-remote"}
	for _, remoteCmd := range remoteCommands {
		if g.Subcommand == remoteCmd {
			g.AffectsRemote = true
			g.AffectsRepo = true
			return
		}
	}

	repoCommands := []string{
		"add", "commit", "reset", "rebase", "merge", "cherry-pick", "revert",
		"am", "apply", "checkout", "clean", "stash", "submodule", "worktree",
	}
	for _, repoCmd := range repoCommands {
		if g.Subcommand == repoCmd {
			g.AffectsRepo = true
			return
		}
	}

	g.AffectsRepo = true
}

func (g *GrepParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for grep")
	}

	cmd := &GrepCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-r", "-R":
			cmd.UseRecursive = true
			cmd.Options["recursive"] = true
		case "-E", "--extended-regexp":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing pattern after -E option")
			}
			cmd.Pattern = args[i+1]
			cmd.Options["pattern"] = args[i+1]
			i += 2
			continue
		case "-e":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing pattern after -e option")
			}
			cmd.Pattern = args[i+1]
			cmd.Options["pattern"] = args[i+1]
			i += 2
			continue
		case "-f":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing file after -f option")
			}
			cmd.Options["pattern_file"] = args[i+1]
			i += 2
			continue
		default:
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'r', 'R':
						cmd.UseRecursive = true
					case 'E':
						if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
							cmd.Pattern = args[i+1]
							cmd.Options["pattern"] = args[i+1]
						}
					}
				}
			}
		}
		i++
	}

	if cmd.Pattern == "" && i < len(args) {
		cmd.Pattern = args[i]
		i++
	}

	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

type CommandLog struct {
	Timestamp    time.Time
	Decision     string
	Command      string
	Args         string
	Caller       string
	Syscall      string
	Reason       string
	Duration     uint32 // Duration choice for retry
	ClientID     string
	RequestID    int
	Cwd          string
	EnvVars      []EnvVarInfo     // Flagged env vars from request
	EnvDecisions []EnvVarDecision // User's decisions on env vars
}

// EnvVarInfo holds info about a flagged env var
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

type EventType int

const (
	EventConnect EventType = iota
	EventDisconnect
	EventCommand
	EventLog
	EventRequest
)

const (
	MaxHistory          = 500
	MaxLogs             = 50
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
	Type      EventType
	Decision  string
	Command   string
	Args      string
	Caller    string
	Syscall   string
	Reason    string
	Log       string
	RequestID int
	ClientID  string
	Cwd       string
	EnvVars   []EnvVarInfo // Flagged env vars from request
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

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2")).
			Background(lipgloss.Color("#44475A")).
			Padding(0, 1).
			Width(40)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4")).
			Padding(0, 1)

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#44475A")).
			Foreground(lipgloss.Color("#F8F8F2"))
)

type Model struct {
	commands      []*CommandLog // store by reference for stable pointers
	logs          []string
	width         int
	height        int
	scrollY       int
	stats         Stats
	connections   int
	lastCmd       string
	lastDecision  string
	lastTime      time.Time
	flashTimer    int
	eventChan     chan Event
	step          int                 // 1 = history list, 2 = duration selection
	cursor        int                 // position in history list or duration selection
	allowChosen   bool                // true = Allow chosen in step 2, false = Deny chosen
	selectedIdx   int                 // currently selected command in history (for expansion)
	focus         string              // "history" or "actions"
	detailsScroll int                 // scroll position in details view
	expandedCmd   *CommandLog         // currently expanded command
	decisionReqID int                 // request ID being decided - prevents switching to different request
	logDecision   bool                // true = mark decision for logging to user_log.txt
	envVarCursor  int                 // -1 = command selected, 0+ = index of selected env var
	pendingRetry  map[int]*CommandLog // requests that failed and need retry
}

func NewModel() *Model {
	return &Model{
		commands:     make([]*CommandLog, 0),
		logs:         make([]string, 0),
		stats:        Stats{},
		eventChan:    make(chan Event, EventChanBufferSize),
		step:         1,
		cursor:       0,
		focus:        "history",
		pendingRetry: make(map[int]*CommandLog),
	}
}

func (m *Model) AddConnection() {
	m.connections++
}

func (m *Model) AddCommand(decision, cmd, args, caller, syscall, reason, clientID, cwd string, requestID int, envVars []EnvVarInfo) {
	m.lastCmd = cmd + " " + args
	m.lastDecision = decision
	m.lastTime = time.Now()
	m.flashTimer = FlashTimerSeconds

	log := CommandLog{
		Timestamp:    time.Now(),
		Decision:     decision,
		Command:      cmd,
		Args:         args,
		Caller:       caller,
		Syscall:      syscall,
		Reason:       reason,
		ClientID:     clientID,
		RequestID:    requestID,
		Cwd:          cwd,
		EnvVars:      envVars,
		EnvDecisions: make([]EnvVarDecision, len(envVars)),
	}
	m.commands = append(m.commands, &log)

	// Enforce MaxHistory limit
	if len(m.commands) > MaxHistory {
		m.commands = m.commands[len(m.commands)-MaxHistory:]
	}

	// Only select the new command if we're NOT in decision mode (step 2)
	// This prevents the decision view from switching to a different request
	// while the user is making a decision
	if m.step != 2 {
		m.selectedIdx = len(m.commands) - 1
		m.expandedCmd = m.commands[m.selectedIdx]
		m.decisionReqID = 0 // Clear decision mode tracking
	}

	// Count pending commands in unknown
	if decision == "PENDING" {
		m.stats.totalUnknown++
	}
}

func (m *Model) AddLog(log string) {
	m.logs = append(m.logs, log)
	if len(m.logs) > MaxLogs {
		m.logs = m.logs[len(m.logs)-MaxLogs:]
	}
}

type refreshMsg struct{}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return t
		}),
	)
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up":
			if m.step == 1 && m.selectedIdx > 0 {
				m.selectedIdx--
			} else if m.step == 2 {
				// If focused on details, navigate between command and env vars
				if m.focus == "details" && m.expandedCmd != nil && len(m.expandedCmd.EnvVars) > 0 {
					m.envVarCursor--
					if m.envVarCursor < -1 {
						m.envVarCursor = -1 // Go back to command
					}
				} else {
					// Scroll details up
					if m.detailsScroll > 0 {
						m.detailsScroll--
					}
				}
			}
		case "down":
			if m.step == 1 && m.selectedIdx < len(m.commands)-1 {
				m.selectedIdx++
			} else if m.step == 2 {
				// If focused on details, navigate between command and env vars
				if m.focus == "details" && m.expandedCmd != nil && len(m.expandedCmd.EnvVars) > 0 {
					maxEnv := len(m.expandedCmd.EnvVars) - 1
					if m.envVarCursor < maxEnv {
						m.envVarCursor++
					}
				} else {
					// Scroll details down
					m.detailsScroll++
				}
			}
		case "home":
			if m.step == 1 && len(m.commands) > 0 {
				m.selectedIdx = 0
				m.scrollY = 0
				m.expandedCmd = m.commands[0]
				m.detailsScroll = 0
			}
		case "end":
			if m.step == 1 && len(m.commands) > 0 {
				m.selectedIdx = len(m.commands) - 1
				m.expandedCmd = m.commands[m.selectedIdx]
				m.detailsScroll = 0
			}
		case "left":
			if m.step == 2 && m.focus == "actions" {
				if m.cursor <= 3 {
					m.cursor--
					if m.cursor < 0 {
						m.cursor = 3
					}
				} else if m.cursor == 4 {
					m.cursor = 3
				} else if m.cursor == 5 {
					m.cursor = 4
				}
			}
		case "right":
			if m.step == 2 && m.focus == "actions" {
				if m.cursor <= 3 {
					m.cursor++
					if m.cursor > 3 {
						m.cursor = 4
					}
				} else if m.cursor == 4 {
					m.cursor = 5
				} else if m.cursor == 5 {
					m.cursor = 0
				}
			}
		case "tab":
			// Toggle focus between history and actions
			if m.step == 2 {
				if m.focus == "actions" {
					m.focus = "details"
				} else {
					m.focus = "actions"
				}
			}
		case "enter":
			if m.step == 1 && len(m.commands) > 0 {
				// Expand selected command
				if m.expandedCmd != nil && m.selectedIdx >= 0 {
					m.step = 2
					m.cursor = 0
					m.allowChosen = true
					m.focus = "actions"
					// Track which request we're deciding (prevents switching on new requests)
					if m.selectedIdx >= 0 && m.selectedIdx < len(m.commands) {
						m.expandedCmd = m.commands[m.selectedIdx]
						m.decisionReqID = m.commands[m.selectedIdx].RequestID
					}
				}
			} else if m.step == 2 {
				m.executeDecision()
			}
		case "a", "A":
			if m.step == 1 && len(m.commands) > 0 {
				// Enter decision mode with Allow preselected
				m.step = 2
				m.cursor = 0
				m.allowChosen = true
				m.focus = "actions"
				// Track which request we're deciding (prevents switching on new requests)
				if m.selectedIdx >= 0 && m.selectedIdx < len(m.commands) {
					m.expandedCmd = m.commands[m.selectedIdx]
					m.decisionReqID = m.commands[m.selectedIdx].RequestID
					m.envVarCursor = -1 // Reset to command selection
				}
			} else if m.step == 2 && m.focus == "details" && m.envVarCursor >= 0 && m.expandedCmd != nil {
				// Set env var to allow
				if m.envVarCursor < len(m.expandedCmd.EnvDecisions) {
					m.expandedCmd.EnvDecisions[m.envVarCursor].Decision = 0 // allow
				}
			} else if m.step == 2 {
				// Switch to Allow mode
				m.allowChosen = true
				m.cursor = 0
				m.focus = "actions"
			}
		case "d", "D":
			if m.step == 1 && len(m.commands) > 0 {
				// Enter decision mode with Deny preselected
				m.step = 2
				m.cursor = 0
				m.allowChosen = false
				m.focus = "actions"
				// Track which request we're deciding (prevents switching on new requests)
				if m.selectedIdx >= 0 && m.selectedIdx < len(m.commands) {
					m.expandedCmd = m.commands[m.selectedIdx]
					m.decisionReqID = m.commands[m.selectedIdx].RequestID
					m.envVarCursor = -1 // Reset to command selection
				}
			} else if m.step == 2 && m.focus == "details" && m.envVarCursor >= 0 && m.expandedCmd != nil {
				// Set env var to deny
				if m.envVarCursor < len(m.expandedCmd.EnvDecisions) {
					m.expandedCmd.EnvDecisions[m.envVarCursor].Decision = 1 // deny
				}
			} else if m.step == 2 {
				// Switch to Deny mode
				m.allowChosen = false
				m.cursor = 0
				m.focus = "actions"
			}
		case "l", "L":
			if m.step == 2 {
				// Toggle logging for this decision
				m.logDecision = !m.logDecision
			}
		case "1":
			if m.step == 2 && m.focus == "actions" && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 0
				m.executeDecision()
			} else if m.step == 2 {
				// Also work if focused on details
				m.cursor = 0
				m.focus = "actions"
				m.executeDecision()
			}
		case "2":
			if m.step == 2 && m.focus == "actions" && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 1
				m.executeDecision()
			} else if m.step == 2 {
				m.cursor = 1
				m.focus = "actions"
				m.executeDecision()
			}
		case "3":
			if m.step == 2 && m.focus == "actions" && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 2
				m.executeDecision()
			} else if m.step == 2 {
				m.cursor = 2
				m.focus = "actions"
				m.executeDecision()
			}
		case "4":
			if m.step == 2 && m.focus == "actions" && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 3
				m.executeDecision()
			} else if m.step == 2 {
				m.cursor = 3
				m.focus = "actions"
				m.executeDecision()
			}
		case "=":
			if m.step == 2 && m.focus == "actions" {
				m.cursor = 4
				m.executeDecision()
			} else if m.step == 2 {
				m.cursor = 4
				m.focus = "actions"
				m.executeDecision()
			}
		case "+":
			if m.step == 2 && m.focus == "actions" {
				m.cursor = 5
				m.executeDecision()
			} else if m.step == 2 {
				m.cursor = 5
				m.focus = "actions"
				m.executeDecision()
			}
		case "esc":
			if m.step == 2 {
				m.step = 1
				m.cursor = 0
				m.focus = "history"
				m.decisionReqID = 0 // Clear decision mode tracking
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case Event:
		switch msg.Type {
		case EventConnect:
			m.connections++
		case EventRequest:
			m.AddCommand("PENDING", msg.Command, msg.Args, msg.Caller, msg.Syscall, "waiting for decision", msg.ClientID, msg.Cwd, msg.RequestID, msg.EnvVars)
		case EventCommand:
			m.lastDecision = msg.Decision
			m.lastTime = time.Now()
			m.flashTimer = 3
		case EventLog:
			m.AddLog(msg.Log)
		}

	case time.Time:
		if m.flashTimer > 0 {
			m.flashTimer--
		}
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return t
		})
	}

	return m, nil
}

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

// clampScrollY ensures scrollY is within valid bounds for the given content height
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
	if len(s) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return strings.Repeat(".", maxWidth)
	}
	return s[:maxWidth-3] + "..."
}

func wrapText(text string, maxWidth int) []string {
	if maxWidth < 10 {
		maxWidth = 40
	}
	var lines []string
	for len(text) > 0 {
		wrapLen := minInt(len(text), maxWidth)
		lines = append(lines, text[:wrapLen])
		text = text[wrapLen:]
	}
	return lines
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
	case 5:
		reason = "session"
		duration = 0
	case 6:
		reason = "always"
		duration = 0
	case 7:
		reason = "pattern"
		duration = 0
	default:
		reason = "unknown"
	}
	return
}

func (m *Model) retryPendingDecisions() {
	pendingMu.Lock()
	defer pendingMu.Unlock()

	if len(pendingRequests) >= 100 {
		fmt.Fprintf(os.Stderr, "ERROR: Too many pending decisions (%d), please restart server\n", len(pendingRequests))
		os.Exit(1)
	}

	for id, cmd := range m.pendingRetry {
		req, ok := pendingRequests[id]
		if !ok {
			delete(m.pendingRetry, id)
			continue
		}

		decision := DecisionAllow
		if cmd.Decision == "DENY" {
			decision = DecisionDeny
		}

		err := req.Decide(decision, cmd.Reason, cmd.Duration, cmd.EnvDecisions)
		if err != nil {
			continue
		}

		delete(pendingRequests, id)
		delete(m.pendingRetry, id)
	}
}

func (m *Model) executeDecision() {
	// Try to resend any pending failed decisions first (transparent to user)
	m.retryPendingDecisions()

	if m.expandedCmd == nil || m.step != 2 {
		return
	}

	allow := m.allowChosen
	decision, reason, duration := durationToReason(allow, m.cursor)
	baseCmd := extractBaseName(m.expandedCmd.Command)
	fmt.Printf("Executing: %s %s for %s %s (duration=%d)\n", decision, reason, baseCmd, m.expandedCmd.Args, duration)

	// Get env decisions from the command
	var envDecisions []EnvVarDecision
	if len(m.expandedCmd.EnvDecisions) > 0 {
		envDecisions = m.expandedCmd.EnvDecisions
	}

	err := MakeDecision(m.expandedCmd.RequestID, allow, reason, duration, envDecisions)
	if err != nil {
		// Decision failed - store for retry with full details
		fmt.Fprintf(os.Stderr, "Decision failed: %v (will retry)\n", err)
		m.expandedCmd.Decision = "RETRY"
		m.expandedCmd.Reason = err.Error()
		m.expandedCmd.Duration = duration
		m.expandedCmd.EnvDecisions = envDecisions
		m.pendingRetry[m.expandedCmd.RequestID] = m.expandedCmd
		m.lastDecision = "RETRY"
		m.lastTime = time.Now()
		m.flashTimer = FlashTimerSeconds
		// Don't clear expandedCmd - user moves on to next request
		return
	}

	// Log decision to user_log.xml if marked
	if m.logDecision {
		m.logDecisionToFile(decision, reason)
	}

	// Direct pointer update - O(1), no ID lookup needed
	oldDecision := m.expandedCmd.Decision
	m.expandedCmd.Decision = decision
	m.expandedCmd.Reason = reason
	m.lastDecision = decision
	m.lastTime = time.Now()
	m.flashTimer = FlashTimerSeconds

	// Update stats only if command was previously pending
	if oldDecision == "PENDING" {
		m.stats.totalUnknown--
		switch decision {
		case "ALLOW":
			m.stats.totalAllowed++
		case "DENY":
			m.stats.totalDenied++
		}
	}

	// Go back to history view
	m.step = 1
	m.cursor = 0
	m.focus = "history"
	m.expandedCmd = nil
	m.decisionReqID = 0
	m.logDecision = false
}

func (m *Model) logDecisionToFile(decision, reason string) {
	logFile := "user_log.xml"
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Escape XML special characters in command/args
	escapeXML := func(s string) string {
		s = strings.ReplaceAll(s, "&", "&amp;")
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		s = strings.ReplaceAll(s, "\"", "&quot;")
		s = strings.ReplaceAll(s, "'", "&apos;")
		return s
	}

	logEntry := fmt.Sprintf(`<response timestamp="%s">
  <request id="%d" client="%s" cwd="%s">
    <command>%s</command>
    <args>%s</args>
  </request>
  <decision action="%s" duration="%s"/>
</response>
`,
		timestamp,
		m.expandedCmd.RequestID,
		escapeXML(m.expandedCmd.ClientID),
		escapeXML(m.expandedCmd.Cwd),
		escapeXML(m.expandedCmd.Command),
		escapeXML(m.expandedCmd.Args),
		decision,
		reason,
	)

	// Append to file
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open user_log.xml: %v\n", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write to user_log.xml: %v\n", err)
	}
}

func (m *Model) View() string {
	var sb strings.Builder

	// Header with stats
	total := m.stats.totalAllowed + m.stats.totalDenied + m.stats.totalUnknown
	statsStr := fmt.Sprintf(" %s %d  %s %d  %s %d = %d ",
		allowStyle.Render("●"),
		m.stats.totalAllowed,
		denyStyle.Render("●"),
		m.stats.totalDenied,
		infoStyle.Render("●"),
		m.stats.totalUnknown,
		total)

	// Add pending retry count if any
	pendingCount := len(m.pendingRetry)
	if pendingCount > 0 {
		pendingStr := fmt.Sprintf("  %s %d pending", infoStyle.Render("●"), pendingCount)
		statsStr += pendingStr
	}

	padding := m.width - len(statsStr)
	if m.width == 0 {
		padding = DefaultPadding
	}
	if padding < 0 {
		padding = 0
	}
	leftPadding := padding / 2
	rightPadding := padding - leftPadding

	headerLine := strings.Repeat(" ", leftPadding) + statsStr + strings.Repeat(" ", rightPadding)
	sb.WriteString(titleStyle.Render(headerLine))
	sb.WriteString("\n")

	if m.step == 1 {
		// HISTORY LIST VIEW
		// Each item takes 3 lines (top border + content + bottom border), total lines = 3*N + 5 = height, so N = (height - 5) / 3
		historyAvailable := (m.height - 5) / 3
		if historyAvailable < 1 {
			historyAvailable = 1
		}
		m.renderHistoryList(&sb, historyAvailable)
	} else {
		// DETAILS & ACTIONS VIEW
		// Reserve space for actions palette at bottom
		detailsAvailable := m.height - 10 // header + details + actions + footer
		if detailsAvailable < 5 {
			detailsAvailable = 5
		}
		m.renderDetailsAndActions(&sb, detailsAvailable)
	}

	// Footer
	var controls string
	if m.step == 1 {
		controls = "↑↓ navigate  Enter/A/D expand  q/ctrl+c quit"
	} else {
		controls = "A/D decision  1-4 duration  Esc back"
	}
	footer := fmt.Sprintf(" %s  Connections: %d  |  %s  q/ctrl+c to quit",
		infoStyle.Render(controls),
		m.connections,
		infoStyle.Render("Exit:"))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render(strings.Repeat("─", m.width)))
	sb.WriteString("\n")
	sb.WriteString(footerStyle.Render(footer))

	return sb.String()
}

func (m *Model) renderHistoryList(sb *strings.Builder, maxHeight int) {
	// maxHeight is the available height for history items

	// Ensure selectedIdx is visible
	if m.selectedIdx < m.scrollY {
		m.scrollY = m.selectedIdx
	}
	if m.selectedIdx >= m.scrollY+maxHeight {
		m.scrollY = maxInt(0, m.selectedIdx-maxHeight+1)
	}

	// Clamp scrollY to valid range
	m.scrollY = clampScrollY(m.scrollY, maxHeight, len(m.commands))

	visibleStart := m.scrollY
	visibleEnd := m.scrollY + maxHeight
	if visibleEnd > len(m.commands) {
		visibleEnd = len(m.commands)
	}

	// Render visible history items
	for i := visibleStart; i < visibleEnd; i++ {
		cmd := m.commands[i]
		ts := cmd.Timestamp.Format("15:04:05")

		var decisionStr string
		switch cmd.Decision {
		case "ALLOW":
			decisionStr = allowStyle.Render("✓")
		case "DENY":
			decisionStr = denyStyle.Render("✗")
		default:
			decisionStr = dimStyle.Render("?")
		}

		// Build summary: show caller:syscall$ command args or caller$ command args
		baseCmd := extractBaseName(cmd.Command)
		var summary string
		if cmd.Caller != "" {
			// Format: caller:syscall$ command args or caller$ command args
			callerPrefix := cmd.Caller
			if cmd.Syscall != "" {
				callerPrefix = cmd.Caller + ":" + cmd.Syscall
			}
			callerPrefix += "$"
			if cmd.Args != "" {
				summary = fmt.Sprintf("%s %s %s", callerPrefix, baseCmd, truncateString(cmd.Args, TruncateWidth))
			} else {
				summary = fmt.Sprintf("%s %s", callerPrefix, baseCmd)
			}
		} else {
			// No caller - use baseCmd + args
			summary = baseCmd
			if cmd.Args != "" {
				summary = fmt.Sprintf("%s %s", baseCmd, truncateString(cmd.Args, TruncateWidth))
			}
		}

		maxWidth := m.width - 50
		if maxWidth < MinTruncateWidth {
			maxWidth = MinTruncateWidth
		}
		truncatedSummary := truncateString(summary, maxWidth)

		// Highlight selected item
		if i == m.selectedIdx {
			row := fmt.Sprintf(" ▶ %s  %s  %s [%s]",
				dimStyle.Render(ts),
				decisionStr,
				selectedStyle.Render(truncatedSummary),
				infoStyle.Render(cmd.Reason))
			sb.WriteString(cardStyle.Render(row))
		} else {
			row := fmt.Sprintf("   %s  %s  %s [%s]",
				dimStyle.Render(ts),
				decisionStr,
				titleStyle.Render(truncatedSummary),
				infoStyle.Render(cmd.Reason))
			sb.WriteString(cardStyle.Render(row))
		}
		sb.WriteString("\n")
	}
}

func parsePipeline(cmd string) PipelineAnalysis {
	/* Extract caller and syscall from [appname:syscall] prefix */
	var caller, syscall string
	cleanCmd := cmd

	/* Parse [appname:syscall] prefix */
	if strings.HasPrefix(cmd, "[") {
		endBracket := strings.Index(cmd, "]")
		if endBracket > 0 {
			/* Extract content between [ and ] */
			content := cmd[1:endBracket]
			parts := strings.SplitN(content, ":", 2)
			if len(parts) >= 1 {
				caller = parts[0]
			}
			if len(parts) >= 2 {
				syscall = parts[1]
			}
			/* Get the rest of the command after "] " */
			rest := cmd[endBracket+1:]
			if strings.HasPrefix(rest, " ") {
				cleanCmd = rest[1:]
			} else {
				cleanCmd = rest
			}
		}
	}

	stages := []PipelineStage{}
	segments := strings.Fields(cleanCmd)

	for i := 0; i < len(segments); i++ {
		segment := segments[i]
		if segment == "|" {
			if len(stages) > 0 {
				stages[len(stages)-1].Stdout = "|"
			}
		} else if len(segment) > 0 {
			cmdName := segment
			var args []string

			j := i + 1
			for j < len(segments) && segments[j] != "|" {
				args = append(args, segments[j])
				j++
			}

			stage := PipelineStage{
				Operator: getOperator(len(stages), segments),
				Command:  cmdName,
				Args:     args,
				Stdin:    getInputSource(len(stages), segments),
				Stdout:   getOutputDesc(cmdName),
			}
			stages = append(stages, stage)
			i = j - 1
		}
	}

	return PipelineAnalysis{
		Original: cmd,
		Stages:   stages,
		FileOps:  inferFileOps(stages, caller),
		Flow:     "Data pipeline",
		Syscall:  syscall,
	}
}

func getOperator(stageIndex int, segments []string) string {
	if stageIndex == 0 {
		return ""
	}
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i] == "|" {
			return "|"
		}
	}
	return ""
}

func getInputSource(stageIndex int, segments []string) string {
	if stageIndex == 0 {
		return ""
	}
	return "|"
}

func getOutputDesc(command string) string {
	switch {
	case command == "find":
		return "File paths to stdout"
	case command == "grep":
		return "Matching lines to stdout"
	case command == "wc":
		return "Line count to stdout"
	case command == "sort":
		return "Sorted lines to stdout"
	case command == "cat":
		return "File contents to stdout"
	case command == "ls":
		return "Directory listing to stdout"
	case command == "head":
		return "First lines to stdout"
	case command == "tail":
		return "Last lines to stdout"
	case command == "xargs":
		return "Arguments to command"
	case command == "awk":
		return "Processed output to stdout"
	default:
		return "Output to stdout"
	}
}

func inferFileOps(stages []PipelineStage, appName string) string {
	/* Check for claude/cursor app with version command (X.Y.Z) */
	if appName == "claude" || appName == "cursor" {
		for _, stage := range stages {
			if strings.Contains(stage.Command, ".") {
				parts := strings.Split(stage.Command, ".")
				if len(parts) >= 2 {
					parser := &ClaudeParser{}
					parsed, err := parser.ParseArguments(stage.Args)
					if err == nil {
						cmd := parsed.(*ClaudeCommand)
						switch cmd.Subcommand {
						case "--ripgrep", "ripgrep":
							if cmd.Target != "" {
								return fmt.Sprintf("Searches: %s (claude ripgrep)", cmd.Target)
							}
							return "Searches: files (claude ripgrep)"
						case "--grep", "grep":
							if cmd.Target != "" {
								return fmt.Sprintf("Searches: %s (claude grep)", cmd.Target)
							}
							return "Searches: files (claude grep)"
						case "--files", "files":
							if cmd.Target != "" {
								return fmt.Sprintf("Lists: %s (claude files)", cmd.Target)
							}
							return "Lists: files (claude files)"
						}
					}
				}
			}
		}
	}

	for _, stage := range stages {
		switch stage.Command {
		case "git":
			parser := &GitParser{}
			parsed, err := parser.ParseArguments(stage.Args)
			if err != nil {
				return ""
			}

			cmd := parsed.(*GitCommand)
			if cmd.IsReadOnly {
				return fmt.Sprintf("Reads: .git (%s)", cmd.Subcommand)
			} else if cmd.AffectsRemote {
				return fmt.Sprintf("Reads: .git, Writes: remote (%s)", cmd.Subcommand)
			} else {
				return fmt.Sprintf("Reads/Writes: .git (%s)", cmd.Subcommand)
			}
		case "find":
			if len(stage.Args) > 0 {
				return fmt.Sprintf("Searches: %s", stage.Args[0])
			}
			return "Searches: ./*"
		case "ls":
			if len(stage.Args) > 0 {
				return fmt.Sprintf("Lists: %s", stage.Args[0])
			}
			return "Lists: current directory"
		case "cat":
			if len(stage.Args) > 0 {
				return fmt.Sprintf("Reads: %s", strings.Join(stage.Args, ", "))
			}
			return ""
		case "grep":
			parser := &GrepParser{}
			parsed, err := parser.ParseArguments(stage.Args)
			if err != nil {
				return ""
			}

			cmd := parsed.(*GrepCommand)
			if cmd.UseRecursive {
				return "Searches: ./*"
			} else if len(cmd.InputFiles) > 0 {
				return fmt.Sprintf("Searches: %s", strings.Join(cmd.InputFiles, ", "))
			} else {
				return ""
			}
		case "ps":
			return "Reads: /proc/*"
		case "ldd":
			if len(stage.Args) > 0 {
				return fmt.Sprintf("Checks libraries: %s", stage.Args[0])
			}
			return "Checks libraries for binary"
		case "sh", "bash":
			if len(stage.Args) > 1 {
				return fmt.Sprintf("Executes: %s", stage.Args[1])
			}
			return ""
		}
	}
	return ""
}

func detectCommandIntent(analysis PipelineAnalysis) string {
	for _, stage := range analysis.Stages {
		/* Check for claude version command */
		if strings.Contains(stage.Command, ".") {
			parts := strings.Split(stage.Command, ".")
			if len(parts) >= 2 {
				parser := &ClaudeParser{}
				parsed, err := parser.ParseArguments(stage.Args)
				if err == nil {
					cmd := parsed.(*ClaudeCommand)
					switch cmd.Subcommand {
					case "--ripgrep", "ripgrep":
						return fmt.Sprintf("Claude: ripgrep search in %s", cmd.Target)
					case "--grep", "grep":
						return fmt.Sprintf("Claude: grep search in %s", cmd.Target)
					case "--files", "files":
						return fmt.Sprintf("Claude: list files in %s", cmd.Target)
					}
					return "Claude command"
				}
			}
		}

		switch {
		case strings.Contains(stage.Command, "find"):
			return "Search for files"
		case strings.Contains(stage.Command, "grep"):
			return "Text search and pattern matching"
		case strings.Contains(stage.Command, "ps"):
			return "Process enumeration"
		case strings.Contains(stage.Command, "wc"):
			return "Counting and statistics"
		case strings.Contains(stage.Command, "sort"):
			return "Data sorting"
		}
	}
	return "Command execution"
}

func generatePipelineOutput(analysis PipelineAnalysis) []string {
	var lines []string

	// Build the display command
	lines = append(lines, fmt.Sprintf("$ %s", analysis.Original))

	for i, stage := range analysis.Stages {
		if i == len(analysis.Stages)-1 {
			lines = append(lines, fmt.Sprintf("o ← %s %s", stage.Command, strings.Join(stage.Args, " ")))
		} else {
			lines = append(lines, fmt.Sprintf("| ← %s %s", stage.Command, strings.Join(stage.Args, " ")))
		}
	}

	if analysis.FileOps != "" {
		lines = append(lines, analysis.FileOps)
	}

	for _, stage := range analysis.Stages {
		if stage.Stdout != "" && stage.Stdout != "|" && stage.Stdout != "Output to stdout" {
			lines = append(lines, fmt.Sprintf("Out: %s", stage.Stdout))
			break
		}
	}

	lines = append(lines, "")

	intent := detectCommandIntent(analysis)
	lines = append(lines, fmt.Sprintf("💡 Intent: %s", intent))

	return lines
}

func (m *Model) renderDetailsAndActions(sb *strings.Builder, maxHeight int) {
	if m.expandedCmd == nil {
		return
	}

	cmd := m.expandedCmd
	ts := cmd.Timestamp.Format("15:04:05")

	var decisionStr string
	switch cmd.Decision {
	case "ALLOW":
		decisionStr = allowStyle.Render("✓ ALLOW")
	case "DENY":
		decisionStr = denyStyle.Render("✗ DENY")
	default:
		decisionStr = dimStyle.Render("◌ PENDING")
	}

	// Render expanded command header (show full command with caller prefix)
	row := fmt.Sprintf("  %s  %s  %s [%s]",
		dimStyle.Render(ts),
		decisionStr,
		titleStyle.Render(cmd.Command),
		infoStyle.Render(cmd.Reason))
	sb.WriteString(cardStyle.Render(row))
	sb.WriteString("\n")

	// Calculate how much space is available for details
	// Reserve: 3 lines for header, 8 lines for actions palette
	detailsMaxLines := maxHeight - 12
	if detailsMaxLines < 3 {
		detailsMaxLines = 3
	}

	// Render details section with scrolling
	detailsFocus := dimStyle
	if m.focus == "details" {
		detailsFocus = infoStyle
	}
	sb.WriteString(detailsFocus.Render("  Details:"))
	sb.WriteString("\n")

	// Show Command line
	sb.WriteString(detailsFocus.Render(fmt.Sprintf("  Command: %s", cmd.Command)))
	sb.WriteString("\n")

	// Show Cwd (from client request)
	if cmd.Cwd != "" {
		sb.WriteString(detailsFocus.Render(fmt.Sprintf("  Cwd: %s", cmd.Cwd)))
	} else {
		sb.WriteString(detailsFocus.Render("  Cwd: <unknown>"))
	}
	sb.WriteString("\n")

	// Show Flagged Env Vars (from v8 protocol)
	if len(cmd.EnvVars) > 0 {
		// If envVarCursor is -1, command is selected, else env var is selected
		if m.envVarCursor == -1 {
			sb.WriteString(detailsFocus.Render("> Flagged Env Vars:"))
		} else {
			sb.WriteString(detailsFocus.Render("  Flagged Env Vars:"))
		}
		sb.WriteString("\n")
		for i, env := range cmd.EnvVars {
			decision := "allow"
			if i < len(cmd.EnvDecisions) {
				if cmd.EnvDecisions[i].Decision == 1 {
					decision = "deny"
				}
			}
			// Highlight selected env var
			if i == m.envVarCursor {
				sb.WriteString(allowSelectedStyle.Render(fmt.Sprintf("  ● %s (%.2f) [%s]", env.Name, env.Score, decision)))
			} else {
				sb.WriteString(detailsFocus.Render(fmt.Sprintf("    %s (%.2f) [%s]", env.Name, env.Score, decision)))
			}
			sb.WriteString("\n")
		}
	} else {
		// No env vars - reset cursor
		m.envVarCursor = -1
	}

	// Show Path (executable path, if determinable from command)
	// Path shows the actual executable path when different from basename
	// e.g., "/usr/bin/git" shows Path: /usr/bin, Command: git ...
	fullCmd := cmd.Command
	var pathStr string
	if strings.HasPrefix(fullCmd, "[") {
		endBracket := strings.Index(fullCmd, "]")
		if endBracket > 0 {
			rest := fullCmd[endBracket+1:]
			rest = strings.TrimPrefix(rest, " ")
			// Find the actual path - it's the first token after the prefix
			// e.g., "/home/panz/.local/share/claude/versions/2.1.19 --ripgrep..." -> "/home/panz/.local/share/claude/versions/2.1.19"
			if idx := strings.Index(rest, " "); idx > 0 {
				pathStr = rest[:idx]
			} else if rest != "" && strings.Contains(rest, "/") {
				pathStr = rest
			}
		}
	}
	// Only show Path if it's different from the basename and contains a path separator
	baseName := extractBaseName(pathStr)
	if pathStr != "" && pathStr != baseName && strings.Contains(pathStr, "/") {
		sb.WriteString(detailsFocus.Render(fmt.Sprintf("  Path: %s", pathStr)))
		sb.WriteString("\n")
	}

	// Build full command text for pipeline parsing (strip caller prefix for analysis)
	fullText := cmd.Command
	if strings.HasPrefix(fullText, "[") {
		endBracket := strings.Index(fullText, "]")
		if endBracket > 0 {
			rest := fullText[endBracket+1:]
			fullText = strings.TrimPrefix(rest, " ")
		}
	}
	fullText = strings.TrimSpace(fullText)

	// Parse and analyze pipeline
	analysis := parsePipeline(fullText)

	// Generate formatted pipeline output
	wrappedLines := generatePipelineOutput(analysis)
	visibleLines := wrappedLines
	if len(wrappedLines) > detailsMaxLines {
		start := m.detailsScroll
		end := start + detailsMaxLines
		if end > len(wrappedLines) {
			end = len(wrappedLines)
		}
		if start >= len(wrappedLines) {
			start = len(wrappedLines) - 1
		}
		if start < end {
			visibleLines = wrappedLines[start:end]
		}
	}

	for i, line := range visibleLines {
		lineNum := m.detailsScroll + i + 1
		totalLines := len(wrappedLines)
		scrollIndicator := "  "
		if len(wrappedLines) > detailsMaxLines {
			if lineNum == 1 {
				scrollIndicator = "▲"
			} else if lineNum == totalLines {
				scrollIndicator = "▼"
			} else {
				scrollIndicator = "│"
			}
		}
		cmdLine := fmt.Sprintf(" %s  %s", scrollIndicator, titleStyle.Render(line))
		sb.WriteString(detailsFocus.Render(cmdLine))
		sb.WriteString("\n")
	}

	// Show scroll indicator if needed
	if len(wrappedLines) > detailsMaxLines {
		scrollInfo := fmt.Sprintf("   (%d/%d lines, ↑↓ to scroll, Tab to actions)", m.detailsScroll+1, len(wrappedLines))
		sb.WriteString(dimStyle.Render(scrollInfo))
		sb.WriteString("\n")
	}

	// ACTIONS PALETTE (always fully visible)
	sb.WriteString("\n")

	// Step 1: Allow/Deny selection
	var allowStr, denyStr string
	if m.focus == "actions" {
		if m.allowChosen {
			allowStr = allowSelectedStyle.Render(" [A] Allow")
			denyStr = denyStyle.Render(" [D] Deny")
		} else {
			allowStr = allowStyle.Render(" [A] Allow")
			denyStr = denySelectedStyle.Render(" [D] Deny")
		}
	} else {
		allowStr = allowStyle.Render(" [A] Allow")
		denyStr = denyStyle.Render(" [D] Deny")
	}

	backStr := dimStyle.Render("[Esc] Back")
	paddingLen := m.width - 50
	if m.width == 0 || paddingLen < 0 {
		paddingLen = 20
	}
	padding := strings.Repeat(" ", paddingLen)
	sb.WriteString(fmt.Sprintf("  %s  %s%s%s\n", allowStr, denyStr, padding, backStr))
	sb.WriteString("\n")

	// Step 2: Duration selection
	durations := []struct {
		num  int
		text string
	}{
		{0, "[1] Once"},
		{1, "[2] 15m"},
		{2, "[3] 1h"},
		{3, "[4] 4h"},
	}

	var durationStyle lipgloss.Style
	if m.focus == "actions" {
		if m.allowChosen {
			durationStyle = allowStyle
		} else {
			durationStyle = denyStyle
		}
	} else {
		durationStyle = dimStyle
	}

	sb.WriteString("           ")
	for _, d := range durations {
		prefix := "  "
		if m.focus == "actions" && m.cursor == d.num {
			prefix = "> "
		}
		sb.WriteString(prefix + durationStyle.Render(d.text) + "  ")
	}
	sb.WriteString("\n")

	// Policy rows (= and +)
	equalsPrefix := "  "
	plusPrefix := "  "
	if m.focus == "actions" {
		if m.cursor == 4 {
			equalsPrefix = "> "
		} else if m.cursor == 5 {
			plusPrefix = "> "
		}
	}
	cmdSuggestion := cmd.Command
	equalsContent := "[=] " + truncateString(cmdSuggestion, TruncateWidth)
	plusContent := "[+] session"

	if m.focus == "actions" {
		sb.WriteString("           " + equalsPrefix + durationStyle.Render(equalsContent) + "\n")
		sb.WriteString("           " + plusPrefix + durationStyle.Render(plusContent) + "\n")
	} else {
		sb.WriteString("           " + equalsPrefix + dimStyle.Render(equalsContent) + "\n")
		sb.WriteString("           " + plusPrefix + dimStyle.Render(plusContent) + "\n")
	}

	// Log toggle indicator
	if m.step == 2 {
		if m.logDecision {
			logStr := infoStyle.Render("[L] Log to user_log.xml")
			sb.WriteString(fmt.Sprintf("           %s\n", logStr))
		} else {
			logStr := dimStyle.Render("[L] Log to user_log.xml")
			sb.WriteString(fmt.Sprintf("           %s\n", logStr))
		}
	}

	// Focus indicator
	if m.focus == "details" {
		sb.WriteString(dimStyle.Render("  (Tab to Actions)"))
	} else {
		sb.WriteString(dimStyle.Render("  (Tab to Details)"))
	}
	sb.WriteString("\n")
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

	// Create model
	model := NewModel()

	// Start TUI
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Goroutine: forward events to TUI
	go func() {
		for event := range model.eventChan {
			p.Send(event)
		}
	}()

	// Goroutine: handle requests and send events to TUI
	go func() {
		requestID := 0
		for {
			req := server.GetRequest()
			if req == nil {
				// Server stopped
				close(model.eventChan)
				break
			}

			requestID++

			cmd := req.GetCommand()
			argc := req.GetArgc()
			args := make([]string, argc)
			for i := 0; i < argc; i++ {
				args[i] = req.GetArg(i)
			}
			// Skip args[0] since it's the command itself (shellsplit includes command as first arg)
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

			// Store request for later decision
			StoreRequest(requestID, req)

			// Send request event to TUI
			select {
			case model.eventChan <- Event{Type: EventRequest, RequestID: requestID, Command: cmd, Args: argsStr, Caller: caller, Syscall: syscall, EnvVars: envVars}:
			default:
			}
		}
	}()

	// Run TUI (blocks until exit)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	fmt.Println("\nShutting down...")
	server.Stop()
	server.Free()
}
