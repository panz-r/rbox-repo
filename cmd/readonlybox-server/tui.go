package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

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
			Padding(0, 1).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2")).
			Background(lipgloss.Color("#44475A")).
			Padding(0, 1).
			Width(40)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4")).
			Padding(0, 1)
)

type CommandLog struct {
	Timestamp time.Time
	Decision  string
	Command   string
	Args      string
	Reason    string
	ClientID  string
	RequestID int
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

type Event struct {
	Type      EventType
	Decision  string
	Command   string
	Args      string
	Reason    string
	Log       string
	RequestID int
	ClientID  string
}

type Model struct {
	commands     []CommandLog
	logs         []string
	width        int
	height       int
	scrollY      int
	stats        Stats
	connections  int
	lastCmd      string
	lastDecision string
	lastTime     time.Time
	flashTimer   int
	eventChan    chan Event
	step         int  // 1 = select allow/deny, 2 = select duration/policy
	cursor       int  // for step 1: 0=Allow, 1=Deny; for step 2: 0-3=durations, 4==, 5=+
	allowChosen  bool // true = Allow chosen in step 1, false = Deny chosen
	selectedCmd  *CommandLog
	focus        string // "details" or "actions" - for Tab navigation
}

func NewModel() *Model {
	return &Model{
		commands:  make([]CommandLog, 0),
		logs:      make([]string, 0),
		stats:     Stats{},
		eventChan: make(chan Event, 100),
		step:      1,
		cursor:    0,
		focus:     "actions",
	}
}

func (m *Model) AddConnection() {
	m.connections++
}

func (m *Model) AddCommand(decision, cmd, args, reason, clientID string, requestID int) {
	m.lastCmd = cmd + " " + args
	m.lastDecision = decision
	m.lastTime = time.Now()
	m.flashTimer = 3

	log := CommandLog{
		Timestamp: time.Now(),
		Decision:  decision,
		Command:   cmd,
		Args:      args,
		Reason:    reason,
		ClientID:  clientID,
		RequestID: requestID,
	}
	m.commands = append(m.commands, log)

	// Only count finalized decisions in stats
	if decision == "ALLOW" {
		m.stats.totalAllowed++
	} else if decision == "DENY" {
		m.stats.totalDenied++
	}
	// PENDING doesn't count toward stats until finalized

	if len(m.commands)-m.scrollY > m.height-10 {
		m.scrollY = len(m.commands) - m.height + 10
	}
}

func (m *Model) AddLog(log string) {
	m.logs = append(m.logs, log)
	if len(m.logs) > 50 {
		m.logs = m.logs[len(m.logs)-50:]
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
			if m.step == 2 && len(m.commands) > 0 {
				if m.focus == "details" {
					// Scroll up in details
					m.scrollY--
					if m.scrollY < 0 {
						m.scrollY = 0
					}
				} else {
					if m.cursor == 4 {
						m.cursor = 3 // = -> last duration
					} else if m.cursor == 5 {
						m.cursor = 4 // + -> =
					} else if m.cursor > 0 {
						m.cursor--
					}
				}
			} else if m.scrollY > 0 {
				m.scrollY--
			}
		case "down":
			if m.step == 2 && len(m.commands) > 0 {
				if m.focus == "details" {
					// Scroll down in details
					m.scrollY++
				} else {
					if m.cursor >= 0 && m.cursor < 4 {
						m.cursor = 4 // duration or = -> next
					} else if m.cursor == 4 {
						m.cursor = 5 // = -> +
					}
				}
			} else if m.scrollY < len(m.commands)-1 {
				m.scrollY++
			}
		case "left":
			if m.step == 1 {
				m.cursor--
				if m.cursor < 0 {
					m.cursor = 1
				}
			} else if m.step == 2 && len(m.commands) > 0 {
				if m.cursor <= 3 {
					m.cursor--
					if m.cursor < 0 {
						m.cursor = 3
					}
				} else if m.cursor == 4 {
					m.cursor = 3 // = -> last duration
				} else if m.cursor == 5 {
					m.cursor = 4 // + -> =
				}
			}
		case "right":
			if m.step == 1 {
				m.cursor++
				if m.cursor > 1 {
					m.cursor = 0
				}
			} else if m.step == 2 && len(m.commands) > 0 {
				if m.cursor <= 3 {
					m.cursor++
					if m.cursor > 3 {
						m.cursor = 4 // durations -> =
					}
				} else if m.cursor == 4 {
					m.cursor = 5 // = -> +
				} else if m.cursor == 5 {
					m.cursor = 0 // + -> first duration
				}
			}
		case "home":
			m.scrollY = 0
		case "end":
			m.scrollY = max(0, len(m.commands)-1)
		case "a", "A":
			if m.step == 1 && len(m.commands) > 0 {
				m.cursor = 0
				m.step = 2
				m.allowChosen = true
				m.selectedCmd = m.findPendingCommand()
			}
		case "d", "D":
			if m.step == 1 && len(m.commands) > 0 {
				m.cursor = 1
				m.step = 2
				m.allowChosen = false
				m.selectedCmd = m.findPendingCommand()
			}
		case "1":
			if m.step == 2 && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 0
				m.executeDecision()
			}
		case "2":
			if m.step == 2 && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 1
				m.executeDecision()
			}
		case "3":
			if m.step == 2 && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 2
				m.executeDecision()
			}
		case "4":
			if m.step == 2 && m.cursor >= 0 && m.cursor <= 3 {
				m.cursor = 3
				m.executeDecision()
			}
		case "=":
			if m.step == 2 && m.focus == "actions" {
				m.cursor = 4
				m.executeDecision()
			}
		case "+":
			if m.step == 2 && m.focus == "actions" {
				m.cursor = 5
				m.executeDecision()
			}
		case "tab":
			if m.step == 2 {
				if m.focus == "actions" {
					m.focus = "details"
				} else {
					m.focus = "actions"
				}
			}
		case "enter":
			if m.step == 1 && len(m.commands) > 0 {
				m.allowChosen = m.cursor == 0
				m.step = 2
				m.selectedCmd = m.findPendingCommand()
				m.cursor = 0
			} else if m.step == 2 && len(m.commands) > 0 {
				m.executeDecision()
			}
		case "esc":
			if m.step == 2 {
				m.step = 1
				m.cursor = 0
				m.selectedCmd = nil
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
			m.AddCommand("PENDING", msg.Command, msg.Args, "waiting for decision", msg.ClientID, msg.RequestID)
		case EventCommand:
			// Update flash display if needed, but don't add to history (already done in executeDecision)
			// This handles cases where server auto-decides before TUI
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

func durationToReason(allow bool, choice int) (decision, reason string) {
	if allow {
		decision = "ALLOW"
	} else {
		decision = "DENY"
	}

	switch choice {
	case 0:
		reason = "once"
	case 1:
		reason = "15m"
	case 2:
		reason = "1h"
	case 3:
		reason = "4h"
	case 5:
		reason = "session"
	case 6:
		reason = "always"
	case 7:
		reason = "pattern"
	default:
		reason = "unknown"
	}
	return
}

func (m *Model) executeDecision() {
	pendingCmd := m.findPendingCommand()
	if pendingCmd == nil || m.step != 2 {
		return
	}

	// Get the request ID from the pending command
	requestID := pendingCmd.RequestID

	// Execute the decision
	allow := m.allowChosen
	decision, reason := durationToReason(allow, m.cursor)
	fmt.Printf("Executing: %s %s for %s %s\n", decision, reason, pendingCmd.Command, pendingCmd.Args)

	// Set the decision in the server's request queue (with allowance tracking)
	SetDecisionWithAllowance(requestID, allow, reason)

	// Find and update the pending command in our list
	for i := range m.commands {
		if m.commands[i].Decision == "PENDING" &&
			m.commands[i].RequestID == requestID {
			m.commands[i].Decision = decision
			m.commands[i].Reason = reason
			m.lastDecision = decision
			m.lastTime = time.Now()
			m.flashTimer = 3
			break
		}
	}

	// Update stats
	switch decision {
	case "ALLOW":
		m.stats.totalAllowed++
	case "DENY":
		m.stats.totalDenied++
	default:
		m.stats.totalUnknown++
	}

	// Reset state - go back to stats page
	m.step = 1
	m.cursor = 0
	m.selectedCmd = nil
}

func (m *Model) View() string {
	var sb strings.Builder

	// Check if there's a pending command
	pendingCmd := m.findPendingCommand()
	hasPending := pendingCmd != nil
	isDeciding := m.step == 2 && m.selectedCmd != nil

	// STATS PAGE - shown when no pending decision
	if !hasPending {
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

		// Center align the stats
		padding := m.width - len(statsStr)
		if m.width == 0 {
			padding = 30
		}
		if padding < 0 {
			padding = 0
		}
		leftPadding := padding / 2
		rightPadding := padding - leftPadding

		headerLine := strings.Repeat(" ", leftPadding) + statsStr + strings.Repeat(" ", rightPadding)
		sb.WriteString(titleStyle.Render(headerLine))
		sb.WriteString("\n")

		// History list - only show finalized commands (not PENDING)
		if len(m.commands) == 0 {
			sb.WriteString(cardStyle.Render(dimStyle.Render("  Waiting for commands...")))
			sb.WriteString("\n")
		} else {
			// Collect finalized commands (not PENDING)
			var finalized []CommandLog
			for i := len(m.commands) - 1; i >= 0; i-- {
				if m.commands[i].Decision != "PENDING" {
					finalized = append(finalized, m.commands[i])
				}
			}

			showCount := minInt(6, len(finalized))
			for i := 0; i < showCount; i++ {
				cmd := finalized[i]
				ts := cmd.Timestamp.Format("15:04:05")

				var decisionStr string
				switch cmd.Decision {
				case "ALLOW":
					decisionStr = allowStyle.Render("✓ ALLOW")
				case "DENY":
					decisionStr = denyStyle.Render("✗ DENY")
				default:
					decisionStr = dimStyle.Render("? UNKNOWN")
				}

				row := fmt.Sprintf("  %s  %s  %s %s [%s]",
					dimStyle.Render(ts),
					decisionStr,
					titleStyle.Render(cmd.Command),
					dimStyle.Render(cmd.Args),
					infoStyle.Render(cmd.Reason))
				sb.WriteString(cardStyle.Render(row))
				sb.WriteString("\n")
			}
		}
	} else {
		// DECISION PAGE - shown when there's a pending decision

		// Pending line
		ts := pendingCmd.Timestamp.Format("15:04:05")
		decisionStr := infoStyle.Render("◌ PENDING")
		pendingLine := fmt.Sprintf("  %s  %s  %s %s [%s]",
			dimStyle.Render(ts),
			decisionStr,
			titleStyle.Render(pendingCmd.Command),
			dimStyle.Render(pendingCmd.Args),
			infoStyle.Render(pendingCmd.Reason))
		sb.WriteString(cardStyle.Render(pendingLine))
		sb.WriteString("\n")

		// Details view - scrollable command details
		detailsFocus := dimStyle
		if m.focus == "details" {
			detailsFocus = infoStyle
		}
		sb.WriteString(detailsFocus.Render("  Details:"))
		sb.WriteString("\n")

		// Command info
		cmdLine := "    command: " + titleStyle.Render(pendingCmd.Command)
		if len(pendingCmd.Args) > 0 {
			cmdLine += " " + dimStyle.Render(pendingCmd.Args)
		}
		sb.WriteString(detailsFocus.Render(cmdLine))
		sb.WriteString("\n")

		// Environment info (placeholder - would need to store env in CommandLog)
		sb.WriteString(detailsFocus.Render("    env:     (not available)"))
		sb.WriteString("\n")

		// Spacer lines
		for i := 0; i < 2; i++ {
			sb.WriteString(cardStyle.Render(dimStyle.Render("  ")))
			sb.WriteString("\n")
		}

		// Action palette
		sb.WriteString("\n")

		// Step 1: Allow/Deny selection
		var allowStr, denyStr string
		if !isDeciding {
			if m.cursor == 0 {
				allowStr = allowSelectedStyle.Render(" [A] Allow")
				denyStr = denyStyle.Render(" [D] Deny")
			} else {
				allowStr = allowStyle.Render(" [A] Allow")
				denyStr = denySelectedStyle.Render(" [D] Deny")
			}
		} else {
			if m.allowChosen {
				allowStr = allowSelectedStyle.Render(" [A] Allow")
				denyStr = denyStyle.Render(" [D] Deny")
			} else {
				allowStr = allowStyle.Render(" [A] Allow")
				denyStr = denySelectedStyle.Render(" [D] Deny")
			}
		}

		backStr := dimStyle.Render("[Esc] Back")
		paddingLen := m.width - 40
		if m.width == 0 || paddingLen < 0 {
			paddingLen = 40
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
		if isDeciding && m.focus == "actions" {
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
			if isDeciding && m.focus == "actions" && m.cursor == d.num {
				prefix = "> "
			}
			sb.WriteString(prefix + durationStyle.Render(d.text) + "  ")
		}
		sb.WriteString("\n")

		// Policy rows (= and +) - aligned with durations
		cmdSuggestion := pendingCmd.Command
		if len(pendingCmd.Args) > 0 {
			cmdSuggestion = pendingCmd.Command + " " + pendingCmd.Args
		}

		equalsPrefix := "  "
		plusPrefix := "  "
		if isDeciding && m.focus == "actions" {
			if m.cursor == 4 {
				equalsPrefix = "> "
			} else if m.cursor == 5 {
				plusPrefix = "> "
			}
		}
		equalsContent := "[=] command: " + dimStyle.Render(cmdSuggestion)
		plusContent := "[+] access:  " + dimStyle.Render("location-suggestion")
		if isDeciding && m.focus == "actions" {
			sb.WriteString("           " + equalsPrefix + durationStyle.Render(equalsContent) + "\n")
			sb.WriteString("           " + plusPrefix + durationStyle.Render(plusContent) + "\n")
		} else {
			sb.WriteString("           " + equalsPrefix + dimStyle.Render(equalsContent) + "\n")
			sb.WriteString("           " + plusPrefix + dimStyle.Render(plusContent) + "\n")
		}

		// Focus indicator
		if m.focus == "details" {
			sb.WriteString(dimStyle.Render("  (Tab to Actions)"))
		} else {
			sb.WriteString(dimStyle.Render("  (Tab to Details)"))
		}
		sb.WriteString("\n")
	}

	// Footer
	footer := fmt.Sprintf(" %s  Connections: %d  |  %s  q/ctrl+c to quit",
		infoStyle.Render("Controls:"),
		m.connections,
		infoStyle.Render("Exit:"))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render(strings.Repeat("─", m.width)))
	sb.WriteString("\n")
	sb.WriteString(footerStyle.Render(footer))

	return sb.String()
}

func (m *Model) findPendingCommand() *CommandLog {
	for i := range m.commands {
		if m.commands[i].Decision == "PENDING" {
			return &m.commands[i]
		}
	}
	return nil
}

func RunTUIMode() {
	model := NewModel()

	server := NewServer()
	server.onConnect = func() {
		select {
		case model.eventChan <- Event{Type: EventConnect}:
		default:
		}
	}
	server.onCommand = func(requestID int, decision, cmd string, args []string, reason string) {
		argsStr := strings.Join(args, " ")
		select {
		case model.eventChan <- Event{Type: EventCommand, RequestID: requestID, Decision: decision, Command: cmd, Args: argsStr, Reason: reason}:
		default:
		}
	}
	server.onLog = func(log string) {
		select {
		case model.eventChan <- Event{Type: EventLog, Log: log}:
		default:
		}
	}
	server.onRequest = func(requestID int, clientID string, cmd string, args []string) {
		argsStr := strings.Join(args, " ")
		select {
		case model.eventChan <- Event{Type: EventRequest, RequestID: requestID, ClientID: clientID, Command: cmd, Args: argsStr}:
		default:
		}
	}

	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	go func() {
		for event := range model.eventChan {
			p.Send(event)
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	fmt.Println("\nShutting down...")
	server.Stop()
}
