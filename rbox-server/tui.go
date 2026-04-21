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
	EnvVars          []EnvVarInfo     // Flagged env vars from request
	EnvDecisions     []EnvVarDecision // User's decisions on env vars
	IntendedDecision string           // "ALLOW" or "DENY" for retries
	OriginalReason   string           // original reason (e.g., "once") for retries
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

type EventType int

const (
	EventConnect EventType = iota
	EventDisconnect
	EventNewRequest
	EventAddPendingRetry
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
	EnvVars   []EnvVarInfo
	Req       *RBoxRequest
	RetryDecision     string
	RetryReason       string
	RetryDuration     uint32
	RetryEnvDecisions []EnvVarDecision
	EvalResult *shell.EvalResult
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
	flashMessage  string
	eventChan     chan Event
	step          int                 // 1 = history list, 2 = duration selection
	cursor        int                 // position in history list or duration selection
	allowChosen   bool                // true = Allow chosen in step 2, false = Deny chosen
	selectedIdx   int                 // currently selected command in history (for expansion)
	focus         string              // "history" or "actions"
	expandedCmd   *CommandLog         // currently expanded command
	decisionReqID int                 // request ID being decided - prevents switching to different request
	logDecision   bool                // true = mark decision for logging to user_log.txt
	envVarCursor  int                 // -1 = command selected, 0+ = index of selected env var
	pendingRetry  map[int]*CommandLog // requests that failed and need retry
	viewOnly      bool                // true when viewing details of a decided command (no decision allowed)
	gate          *shell.Gate         // shellgate policy engine (may be nil)
	suggAccepted  []bool              // per-suggestion accept state (true = accepted/green)
	suggDuration  int                 // last selected duration (0-3) for suggestion accept
	violOverrides map[uint32]bool     // violation types user has explicitly allowed this session
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
		viewOnly:     false,
		violOverrides: make(map[uint32]bool),
	}
}

func (m *Model) initSuggestions() {
	if m.expandedCmd != nil && m.expandedCmd.EvalResult != nil {
		ev := m.expandedCmd.EvalResult
		suggs := ev.Suggestions
		if !m.allowChosen && len(ev.DenySuggestions) > 0 {
			suggs = ev.DenySuggestions
		}
		if len(suggs) > 0 {
			m.suggAccepted = make([]bool, len(suggs))
			return
		}
	}
	m.suggAccepted = nil
}

func (m *Model) activeSuggestions() []string {
	if m.expandedCmd == nil || m.expandedCmd.EvalResult == nil {
		return nil
	}
	ev := m.expandedCmd.EvalResult
	if !m.allowChosen && len(ev.DenySuggestions) > 0 {
		return ev.DenySuggestions
	}
	return ev.Suggestions
}

func (m *Model) suggCount() int {
	return len(m.suggAccepted)
}

func (m *Model) maxCursor() int {
	return 3 + m.suggCount()
}

func (m *Model) AddConnection() {
	m.connections++
}

func (m *Model) AddCommand(decision, cmd, args, caller, syscall, reason, clientID, cwd string, requestID int, envVars []EnvVarInfo, evalResult *shell.EvalResult) {
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
		EvalResult:   evalResult,
	}
	m.commands = append(m.commands, &log)

	// Enforce MaxHistory limit
	if len(m.commands) > MaxHistory {
		start := len(m.commands) - MaxHistory
		m.commands = m.commands[start:]
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
	switch decision {
	case "PENDING":
		m.stats.totalUnknown++
	case "POLICY ALLOW":
		m.stats.totalAllowed++
	case "POLICY DENY":
		m.stats.totalDenied++
	}
}

func (m *Model) AddLog(log string) {
	m.logs = append(m.logs, log)
	if len(m.logs) > MaxLogs {
		start := len(m.logs) - MaxLogs
		m.logs = m.logs[start:]
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
				if m.focus == "actions" && !m.viewOnly {
					m.cursor--
					if m.cursor < 0 {
						m.cursor = m.maxCursor()
					}
					if m.cursor <= 3 {
						m.suggDuration = m.cursor
					}
				} else if m.focus == "details" && !m.viewOnly && m.expandedCmd != nil && len(m.expandedCmd.EnvVars) > 0 {
					m.envVarCursor--
					if m.envVarCursor < -1 {
						m.envVarCursor = -1
					}
				} else if m.viewOnly || m.focus == "details" {
				}
			}
		case "down":
			if m.step == 1 && m.selectedIdx < len(m.commands)-1 {
				m.selectedIdx++
			} else if m.step == 2 {
				if m.focus == "actions" && !m.viewOnly {
					m.cursor++
					if m.cursor > m.maxCursor() {
						m.cursor = 0
					}
					if m.cursor <= 3 {
						m.suggDuration = m.cursor
					}
				} else if m.focus == "details" && !m.viewOnly && m.expandedCmd != nil && len(m.expandedCmd.EnvVars) > 0 {
					maxEnv := len(m.expandedCmd.EnvVars) - 1
					if m.envVarCursor < maxEnv {
						m.envVarCursor++
					}
				} else if m.viewOnly || m.focus == "details" {
				}
			}
		case "home":
			if m.step == 1 && len(m.commands) > 0 {
				m.selectedIdx = 0
				m.scrollY = 0
				m.expandedCmd = m.commands[0]
			}
		case "end":
			if m.step == 1 && len(m.commands) > 0 {
				m.selectedIdx = len(m.commands) - 1
				m.expandedCmd = m.commands[m.selectedIdx]
			}
		case "left":
			if m.step == 2 && !m.viewOnly && m.focus == "details" && m.envVarCursor >= 0 && m.expandedCmd != nil {
				if m.envVarCursor < len(m.expandedCmd.EnvDecisions) {
					m.expandedCmd.EnvDecisions[m.envVarCursor].Decision = 1
				}
			} else if m.step == 2 && !m.viewOnly && m.focus == "actions" {
				if m.cursor <= 3 {
					m.cursor--
					if m.cursor < 0 {
						m.cursor = m.maxCursor()
					}
					m.suggDuration = m.cursor
				} else {
					si := m.cursor - 4
					if si >= 0 && si < m.suggCount() {
						m.suggAccepted[si] = false
					}
				}
			}
		case "right":
			if m.step == 2 && !m.viewOnly && m.focus == "details" && m.envVarCursor >= 0 && m.expandedCmd != nil {
				if m.envVarCursor < len(m.expandedCmd.EnvDecisions) {
					m.expandedCmd.EnvDecisions[m.envVarCursor].Decision = 0
				}
			} else if m.step == 2 && !m.viewOnly && m.focus == "actions" {
				if m.cursor <= 3 {
					m.cursor++
					if m.cursor > 3 && m.suggCount() > 0 {
						m.cursor = 4
					} else if m.cursor > 3 {
						m.cursor = 0
					}
					m.suggDuration = m.cursor
				} else {
					si := m.cursor - 4
					if si >= 0 && si < m.suggCount() {
						m.suggAccepted[si] = true
					}
				}
			}
		case "tab":
			if m.step == 2 && !m.viewOnly {
				if m.focus == "actions" {
					m.focus = "details"
				} else {
					m.focus = "actions"
				}
			}
		case "enter":
			if m.step == 1 && len(m.commands) > 0 {
				if m.selectedIdx >= 0 && m.selectedIdx < len(m.commands) {
					selectedCmd := m.commands[m.selectedIdx]
					if selectedCmd.Decision == "PENDING" {
						m.step = 2
						m.cursor = 0
						m.allowChosen = true
						m.focus = "actions"
						m.viewOnly = false
						m.expandedCmd = selectedCmd
						m.decisionReqID = selectedCmd.RequestID
						m.envVarCursor = -1
						m.initSuggestions()
					} else {
						m.step = 2
						m.viewOnly = true
						m.focus = "details"
						m.expandedCmd = selectedCmd
						m.decisionReqID = 0
						m.envVarCursor = -1
					}
				}
			} else if m.step == 2 {
				m.executeDecision()
			}
		case "a", "A":
			if m.step == 1 && len(m.commands) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(m.commands) {
				selectedCmd := m.commands[m.selectedIdx]
				if selectedCmd.Decision == "PENDING" {
					m.step = 2
					m.cursor = 0
					m.allowChosen = true
					m.focus = "actions"
					m.viewOnly = false
					m.expandedCmd = selectedCmd
					m.decisionReqID = selectedCmd.RequestID
					m.envVarCursor = -1
					m.initSuggestions()
				} else {
					m.step = 2
					m.viewOnly = true
					m.focus = "details"
					m.expandedCmd = selectedCmd
					m.decisionReqID = 0
					m.envVarCursor = -1
				}
			} else if m.step == 2 && !m.viewOnly && m.focus == "details" && m.envVarCursor >= 0 && m.expandedCmd != nil {
				if m.envVarCursor < len(m.expandedCmd.EnvDecisions) {
					m.expandedCmd.EnvDecisions[m.envVarCursor].Decision = 0
				}
			} else if m.step == 2 && !m.viewOnly {
				m.allowChosen = true
				m.cursor = 0
				m.focus = "actions"
				m.initSuggestions()
			}
		case "d", "D":
			if m.step == 1 && len(m.commands) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(m.commands) {
				selectedCmd := m.commands[m.selectedIdx]
				if selectedCmd.Decision == "PENDING" {
					m.step = 2
					m.cursor = 0
					m.allowChosen = false
					m.focus = "actions"
					m.viewOnly = false
					m.expandedCmd = selectedCmd
					m.decisionReqID = selectedCmd.RequestID
					m.envVarCursor = -1
					m.initSuggestions()
				} else {
					m.step = 2
					m.viewOnly = true
					m.focus = "details"
					m.expandedCmd = selectedCmd
					m.decisionReqID = 0
					m.envVarCursor = -1
				}
			} else if m.step == 2 && !m.viewOnly && m.focus == "details" && m.envVarCursor >= 0 && m.expandedCmd != nil {
				if m.envVarCursor < len(m.expandedCmd.EnvDecisions) {
					m.expandedCmd.EnvDecisions[m.envVarCursor].Decision = 1
				}
			} else if m.step == 2 && !m.viewOnly {
				m.allowChosen = false
				m.cursor = 0
				m.focus = "actions"
				m.initSuggestions()
			}
		case "l", "L":
			if m.step == 2 && !m.viewOnly {
				m.logDecision = !m.logDecision
			}
		case "c", "C":
			if m.step == 1 && m.gate != nil {
				m.gate.Close()
				var err error
				m.gate, err = shell.NewGate()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Fatal: failed to recreate gate: %v\n", err)
					m.gate = nil
					return m, tea.Quit
				}
				gateAddDefaults(m.gate)
				m.violOverrides = make(map[uint32]bool)
				m.flashMessage = "Policy cleared"
				m.flashTimer = 3
			}
		case "1":
			if m.step == 2 && !m.viewOnly && m.focus == "actions" && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 0
				m.executeDecision()
			} else if m.step == 2 && !m.viewOnly {
				m.cursor = 0
				m.focus = "actions"
				m.executeDecision()
			}
		case "2":
			if m.step == 2 && !m.viewOnly && m.focus == "actions" && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 1
				m.executeDecision()
			} else if m.step == 2 && !m.viewOnly {
				m.cursor = 1
				m.focus = "actions"
				m.executeDecision()
			}
		case "3":
			if m.step == 2 && !m.viewOnly && m.focus == "actions" && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 2
				m.executeDecision()
			} else if m.step == 2 && !m.viewOnly {
				m.cursor = 2
				m.focus = "actions"
				m.executeDecision()
			}
		case "4":
			if m.step == 2 && !m.viewOnly && m.focus == "actions" && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 3
				m.executeDecision()
			} else if m.step == 2 && !m.viewOnly {
				m.cursor = 3
				m.focus = "actions"
				m.executeDecision()
			}
		case "=":
			if m.step == 2 && !m.viewOnly && m.focus == "actions" {
				m.cursor = 4
				m.executeDecision()
			} else if m.step == 2 && !m.viewOnly {
				m.cursor = 4
				m.focus = "actions"
				m.executeDecision()
			}
		case "+":
			if m.step == 2 && !m.viewOnly && m.focus == "actions" {
				m.cursor = 5
				m.executeDecision()
			} else if m.step == 2 && !m.viewOnly {
				m.cursor = 5
				m.focus = "actions"
				m.executeDecision()
			}
		case "esc":
			if m.step == 2 {
				if m.viewOnly {
					m.step = 1
					m.viewOnly = false
					m.cursor = 0
					m.focus = "history"
					m.decisionReqID = 0
					return m, nil
				}
				m.step = 1
				m.cursor = 0
				m.focus = "history"
				m.decisionReqID = 0
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case Event:
		switch msg.Type {
		case EventConnect:
			m.connections++
		case EventNewRequest:
			// Evaluate command through shellgate (single-threaded gate access)
			var evalResult *shell.EvalResult
			if m.gate != nil {
				var err error
				evalResult, err = m.gate.Eval(msg.Command)
				if err != nil {
					evalResult = &shell.EvalResult{
						Verdict:    shell.VerdictUndetermined,
						DenyReason: "eval error: " + err.Error(),
					}
				} else if evalResult != nil && evalResult.Truncated {
					fmt.Fprintf(os.Stderr, "Warning: shellgate buffer truncated for command: %s\n", msg.Command)
				}
			}

			// Auto-allow / auto-deny logic
			autoAllowed := false
			autoDenied := false
			if evalResult != nil && len(msg.EnvVars) == 0 {
				ev := evalResult
				if ev.Verdict == shell.VerdictAllow && len(ev.Suggestions) == 0 {
					// Literal allow match — check violations
					if !ev.HasViolation || len(ev.Violations) == 0 {
						autoAllowed = true
					} else {
						allOverridden := true
						for _, v := range ev.Violations {
							if !m.violOverrides[v.Type] {
								allOverridden = false
								break
							}
						}
						if allOverridden {
							autoAllowed = true
						}
					}
					if autoAllowed {
						msg.Req.Decide(DecisionAllow, "once", 0, nil)
						m.AddCommand("POLICY ALLOW", msg.Command, msg.Args, msg.Caller, msg.Syscall, "policy-allow", msg.ClientID, msg.Cwd, msg.RequestID, msg.EnvVars, evalResult)
					}
				} else if ev.Verdict == shell.VerdictDeny && len(ev.DenySuggestions) == 0 {
					// Literal deny match — auto-deny
					autoDenied = true
					msg.Req.Decide(DecisionDeny, "once", 0, nil)
					m.AddCommand("POLICY DENY", msg.Command, msg.Args, msg.Caller, msg.Syscall, "policy-deny", msg.ClientID, msg.Cwd, msg.RequestID, msg.EnvVars, evalResult)
				}
			}
			if !autoAllowed && !autoDenied {
				StoreRequest(msg.RequestID, msg.Req)
				m.AddCommand("PENDING", msg.Command, msg.Args, msg.Caller, msg.Syscall, "waiting for decision", msg.ClientID, msg.Cwd, msg.RequestID, msg.EnvVars, evalResult)
			}
		case EventAddPendingRetry:
			// Find the command log for this request
			var cmdLog *CommandLog
			for _, c := range m.commands {
				if c.RequestID == msg.RequestID {
					cmdLog = c
					break
				}
			}
			if cmdLog != nil {
				cmdLog.Decision = "RETRY"
				cmdLog.IntendedDecision = msg.RetryDecision
				cmdLog.OriginalReason = msg.RetryReason
				cmdLog.Duration = msg.RetryDuration
				cmdLog.EnvDecisions = msg.RetryEnvDecisions
				m.pendingRetry[msg.RequestID] = cmdLog
				m.lastDecision = "RETRY"
				m.lastTime = time.Now()
				m.flashTimer = FlashTimerSeconds
			}
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
	default:
		reason = "unknown"
	}
	return
}

func (m *Model) retryPendingDecisions() {
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
		if cmd.IntendedDecision == "DENY" {
			decision = DecisionDeny
		}

		err := req.Decide(decision, cmd.OriginalReason, cmd.Duration, cmd.EnvDecisions)
		if err != nil {
			continue
		}

		// Successful retry - update command log
		delete(pendingRequests, id)
		delete(m.pendingRetry, id)

		cmd.Decision = cmd.IntendedDecision
		cmd.Reason = cmd.OriginalReason
		m.lastDecision = cmd.Decision
		m.lastTime = time.Now()
		m.flashTimer = FlashTimerSeconds

		// Update stats - this was previously a PENDING/RETRY command
		m.stats.totalUnknown--
		switch cmd.IntendedDecision {
		case "ALLOW":
			m.stats.totalAllowed++
		case "DENY":
			m.stats.totalDenied++
		}
	}
}

func (m *Model) executeDecision() {
	if m.viewOnly || m.expandedCmd == nil || m.step != 2 || m.expandedCmd.Decision != "PENDING" {
		return
	}

	// Try to resend any pending failed decisions first (transparent to user)
	m.retryPendingDecisions()

	allow := m.allowChosen
	durationCursor := m.cursor
	if durationCursor > 3 {
		durationCursor = m.suggDuration
		if durationCursor < 0 || durationCursor > 3 {
			durationCursor = 0
		}
	}
	decision, reason, duration := durationToReason(allow, durationCursor)

	// Add accepted suggestion rules to the gate
	if m.gate != nil {
		active := m.activeSuggestions()
		for si, accepted := range m.suggAccepted {
			if accepted && si < len(active) {
				pattern := active[si]
				if pattern != "" {
					var err error
					if allow {
						err = m.gate.AddRule(pattern)
					} else {
						err = m.gate.AddDenyRule(pattern)
					}
					if err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to add %s rule %q: %v\n",
							map[bool]string{true: "allow", false: "deny"}[allow], pattern, err)
					}
				}
			}
		}
	}

	// Record violation overrides when user allows a command with violations
	if allow && m.expandedCmd.EvalResult != nil && m.expandedCmd.EvalResult.HasViolation {
		for _, v := range m.expandedCmd.EvalResult.Violations {
			m.violOverrides[v.Type] = true
		}
	}

	baseCmd := extractBaseName(m.expandedCmd.Command)
	fmt.Printf("Executing: %s %s for %s %s (duration=%d)\n", decision, reason, baseCmd, m.expandedCmd.Args, duration)

	// Get env decisions from the command
	var envDecisions []EnvVarDecision
	if len(m.expandedCmd.EnvDecisions) > 0 {
		envDecisions = m.expandedCmd.EnvDecisions
	}

	err := MakeDecision(m.expandedCmd.RequestID, allow, reason, duration, envDecisions)
	if err != nil {
		// Decision failed - queue event to store for retry
		fmt.Fprintf(os.Stderr, "Decision failed: %v (will retry)\n", err)
		m.eventChan <- Event{
			Type:              EventAddPendingRetry,
			RequestID:         m.expandedCmd.RequestID,
			RetryDecision:     decision,
			RetryReason:       reason,
			RetryDuration:     duration,
			RetryEnvDecisions: envDecisions,
		}
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

	if m.flashTimer > 0 && m.flashMessage != "" {
		sb.WriteString(infoStyle.Render("  " + m.flashMessage))
		sb.WriteString("\n")
	}

	if m.step == 1 {
		// Each item takes 3 lines (top border + content + bottom border), total lines = 3*N + 5 = height, so N = (height - 5) / 3
		historyAvailable := (m.height - 5) / 3
		if historyAvailable < 1 {
			historyAvailable = 1
		}
		m.renderHistoryList(&sb, historyAvailable)
	} else {
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
		controls = "↑↓ navigate  Enter/A/D expand  C clear policy  q/ctrl+c quit"
	} else if m.viewOnly {
		controls = "↑↓ scroll  Esc back"
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
		case "POLICY ALLOW":
			decisionStr = allowStyle.Render("✓")
		case "DENY":
			decisionStr = denyStyle.Render("✗")
		case "POLICY DENY":
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
	case "POLICY ALLOW":
		decisionStr = allowStyle.Render("✓ POLICY ALLOW")
	case "DENY":
		decisionStr = denyStyle.Render("✗ DENY")
	case "POLICY DENY":
		decisionStr = denyStyle.Render("✗ POLICY DENY")
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


	// Render details section with scrolling
	detailsFocus := dimStyle
	if m.focus == "details" {
		detailsFocus = infoStyle
	}

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
		for i, env := range cmd.EnvVars {
			var decisionStr string
			if i < len(cmd.EnvDecisions) && cmd.EnvDecisions[i].Decision == 0 {
				decisionStr = allowStyle.Render(fmt.Sprintf("  [✓] %s (%.2f)", env.Name, env.Score))
			} else {
				decisionStr = denyStyle.Render(fmt.Sprintf("→  %s (%.2f)", env.Name, env.Score))
			}
			if i == 0 {
				if i == m.envVarCursor {
					sb.WriteString(fmt.Sprintf("  Env: > %s\n", decisionStr))
				} else {
					sb.WriteString(fmt.Sprintf("  Env:   %s\n", decisionStr))
				}
			} else {
				if i == m.envVarCursor {
					sb.WriteString(fmt.Sprintf("       > %s\n", decisionStr))
				} else {
					sb.WriteString(fmt.Sprintf("         %s\n", decisionStr))
				}
			}
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

	// Build full command text (strip caller prefix)
	fullText := cmd.Command
	if strings.HasPrefix(fullText, "[") {
		endBracket := strings.Index(fullText, "]")
		if endBracket > 0 {
			rest := fullText[endBracket+1:]
			fullText = strings.TrimPrefix(rest, " ")
		}
	}
	fullText = strings.TrimSpace(fullText)

	// Shellgate depgraph display
	if cmd.EvalResult != nil {
		ev := cmd.EvalResult

		sb.WriteString(detailsFocus.Render(fmt.Sprintf("  $ %s", fullText)))
		sb.WriteString("\n")

		// Subcommand breakdown with depgraph info
		if len(ev.Subcmds) > 0 {
			for i, sc := range ev.Subcmds {
				pfx := "  │"
				if i == len(ev.Subcmds)-1 {
					pfx = "  └"
				}
				scVerdict := shell.VerdictName(sc.Verdict)
				var annotations []string
				if sc.WriteCount > 0 {
					annotations = append(annotations, fmt.Sprintf("W%d", sc.WriteCount))
				}
				if sc.ReadCount > 0 {
					annotations = append(annotations, fmt.Sprintf("R%d", sc.ReadCount))
				}
				if sc.EnvCount > 0 {
					annotations = append(annotations, fmt.Sprintf("E%d", sc.EnvCount))
				}
				var annStr string
				if len(annotations) > 0 {
					annStr = dimStyle.Render(fmt.Sprintf(" [%s]", strings.Join(annotations, ",")))
				}
				var verdictStyle lipgloss.Style
				switch sc.Verdict {
				case shell.VerdictAllow:
					verdictStyle = allowStyle
				case shell.VerdictDeny, shell.VerdictReject:
					verdictStyle = denyStyle
				default:
					verdictStyle = dimStyle
				}
				sb.WriteString(fmt.Sprintf("%s %s %s%s", pfx, sc.Command, verdictStyle.Render(scVerdict), annStr))
				if sc.RejectReason != "" {
					sb.WriteString(dimStyle.Render(fmt.Sprintf(" (%s)", sc.RejectReason)))
				}
				sb.WriteString("\n")
			}
		}

		// Overall verdict
		verdictStr := shell.VerdictName(ev.Verdict)
		switch ev.Verdict {
		case shell.VerdictAllow:
			sb.WriteString(allowStyle.Render(fmt.Sprintf("  Policy: %s", verdictStr)))
		case shell.VerdictDeny:
			sb.WriteString(denyStyle.Render(fmt.Sprintf("  Policy: %s", verdictStr)))
			if ev.DenyReason != "" {
				sb.WriteString(denyStyle.Render(fmt.Sprintf(" (%s)", ev.DenyReason)))
			}
		case shell.VerdictReject:
			sb.WriteString(denyStyle.Render(fmt.Sprintf("  Policy: %s", verdictStr)))
		case shell.VerdictUndetermined:
			sb.WriteString(dimStyle.Render(fmt.Sprintf("  Policy: %s", verdictStr)))
			if ev.DenyReason != "" {
				sb.WriteString(denyStyle.Render(fmt.Sprintf(" (%s)", ev.DenyReason)))
			}
		}
		sb.WriteString("\n")

		// Violations
		if ev.HasViolation && len(ev.Violations) > 0 {
			sb.WriteString("\n")
			sb.WriteString(denyStyle.Render("  Violations:"))
			sb.WriteString("\n")
			for _, v := range ev.Violations {
				cat := shell.ViolationTypeName(v.Type)
				severityBar := strings.Repeat("▓", int(v.Severity/10))
				severityEmpty := strings.Repeat("░", 10-len(severityBar))
				sb.WriteString(fmt.Sprintf("    %s [%s%s] %s: %s",
					cat, severityBar, severityEmpty,
					v.Description, dimStyle.Render(v.Detail)))
				sb.WriteString("\n")
			}
		}
	} else {
		// Fallback: no eval result, show raw command
		sb.WriteString(detailsFocus.Render(fmt.Sprintf("  $ %s", fullText)))
		sb.WriteString("\n")
	}

	// ACTIONS PALETTE
	if !m.viewOnly && cmd.Decision == "PENDING" {
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

		// Policy suggestion rows
		if m.suggCount() > 0 {
			active := m.activeSuggestions()
			for si, sugg := range active {
				rowIdx := 4 + si
				prefix := "  "
				if m.focus == "actions" && m.cursor == rowIdx {
					prefix = "> "
				}
				accepted := m.suggAccepted[si]
				var text string
				if accepted {
					text = allowStyle.Render("[✓] " + sugg)
				} else {
					text = infoStyle.Render("→ " + sugg)
				}
				sb.WriteString("           " + prefix + text + "\n")
			}
		}

		// Log toggle + focus indicator
		if m.step == 2 {
			var tabLabel string
			if m.focus == "details" {
				tabLabel = "[Tab] Actions"
			} else {
				tabLabel = "[Tab] Details"
			}
			var logLabel string
			if m.logDecision {
				logLabel = infoStyle.Render("[L] Log")
			} else {
				logLabel = dimStyle.Render("[L] Log")
			}
			sb.WriteString(fmt.Sprintf("  %s    %s\n", dimStyle.Render(tabLabel), logLabel))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("  This command has already been " + decisionStr))
		sb.WriteString("\n")
		if cmd.Reason != "" {
			sb.WriteString(dimStyle.Render("  Reason: " + cmd.Reason))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
}

func gateAddDefaults(gate *shell.Gate) {
	if gate == nil {
		return
	}
	rules := []string{
		"echo *", "ls", "cat #path", "grep *", "find *",
		"head", "tail", "wc", "sort", "uniq", "diff *",
	}
	for _, r := range rules {
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

	// Create model
	model := NewModel()
	model.gate = gate

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
				// Server stopped - exit loop, main thread closes channel after p.Run()
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
			model.eventChan <- Event{
				Type:       EventNewRequest,
				RequestID:  requestID,
				Req:        req,
				Command:    cmd,
				Args:       argsStr,
				Caller:     caller,
				Syscall:    syscall,
				EnvVars:    envVars,
			}
		}
	}()

	// Run TUI (blocks until exit)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	close(model.eventChan)

	fmt.Println("\nShutting down...")
	if model.gate != nil {
		model.gate.Close()
	}
	server.Stop()
	server.Free()
}
