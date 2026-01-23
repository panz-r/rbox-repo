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
	commands      []CommandLog
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
	step          int         // 1 = history list, 2 = duration selection
	cursor        int         // position in history list or duration selection
	allowChosen   bool        // true = Allow chosen in step 2, false = Deny chosen
	selectedIdx   int         // currently selected command in history (for expansion)
	focus         string      // "history" or "actions"
	detailsScroll int         // scroll position in details view
	expandedCmd   *CommandLog // currently expanded command
}

func NewModel() *Model {
	return &Model{
		commands:  make([]CommandLog, 0),
		logs:      make([]string, 0),
		stats:     Stats{},
		eventChan: make(chan Event, 100),
		step:      1,
		cursor:    0,
		focus:     "history",
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

	// Select the new command
	m.selectedIdx = len(m.commands) - 1
	m.expandedCmd = &m.commands[m.selectedIdx]
	m.detailsScroll = 0

	// Count pending commands in unknown
	if decision == "PENDING" {
		m.stats.totalUnknown++
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
			if m.step == 1 && m.selectedIdx > 0 {
				m.selectedIdx--
			} else if m.step == 2 {
				// Scroll details up
				if m.detailsScroll > 0 {
					m.detailsScroll--
				}
			}
		case "down":
			if m.step == 1 && m.selectedIdx < len(m.commands)-1 {
				m.selectedIdx++
			} else if m.step == 2 {
				// Scroll details down
				m.detailsScroll++
			}
		case "home":
			if m.step == 1 && len(m.commands) > 0 {
				m.selectedIdx = 0
				m.scrollY = 0
				m.expandedCmd = &m.commands[0]
				m.detailsScroll = 0
			}
		case "end":
			if m.step == 1 && len(m.commands) > 0 {
				m.selectedIdx = len(m.commands) - 1
				m.expandedCmd = &m.commands[m.selectedIdx]
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
				m.expandedCmd = &m.commands[m.selectedIdx]
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
				m.expandedCmd = &m.commands[m.selectedIdx]
			} else if m.step == 2 {
				// Switch to Deny mode
				m.allowChosen = false
				m.cursor = 0
				m.focus = "actions"
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
	if m.expandedCmd == nil || m.step != 2 {
		return
	}

	requestID := m.expandedCmd.RequestID
	allow := m.allowChosen
	decision, reason := durationToReason(allow, m.cursor)
	fmt.Printf("Executing: %s %s for %s %s\n", decision, reason, m.expandedCmd.Command, m.expandedCmd.Args)

	SetDecisionWithAllowance(requestID, allow, reason)

	// Find and update the command in our list
	for i := range m.commands {
		if m.commands[i].RequestID == requestID {
			oldDecision := m.commands[i].Decision
			m.commands[i].Decision = decision
			m.commands[i].Reason = reason
			m.lastDecision = decision
			m.lastTime = time.Now()
			m.flashTimer = 3

			// Update stats only if it was previously pending
			if oldDecision == "PENDING" {
				m.stats.totalUnknown--
				switch decision {
				case "ALLOW":
					m.stats.totalAllowed++
				case "DENY":
					m.stats.totalDenied++
				}
			}
			break
		}
	}

	// Update stats only if command was previously pending

	// Go back to history view
	m.step = 1
	m.cursor = 0
	m.focus = "history"
	m.expandedCmd = nil
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

	// Calculate maximum valid scrollY to keep header visible
	// scrollY can never exceed (total items - available height for items)
	maxScrollY := len(m.commands) - maxHeight
	if maxScrollY < 0 {
		maxScrollY = 0
	}

	// Hard clamp scrollY - THIS IS THE CRITICAL FIX
	// scrollY must never push header off screen
	if m.scrollY > maxScrollY {
		m.scrollY = maxScrollY
	}
	if m.scrollY < 0 {
		m.scrollY = 0
	}

	// Ensure selectedIdx is visible
	if m.selectedIdx < m.scrollY {
		m.scrollY = m.selectedIdx
	}
	if m.selectedIdx >= m.scrollY+maxHeight {
		m.scrollY = max(0, m.selectedIdx-maxHeight+1)
	}

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

		// Truncate command and args
		maxWidth := m.width - 50
		if maxWidth < 20 {
			maxWidth = 20
		}
		truncatedCmd := truncateString(cmd.Command, 15)
		truncatedArgs := truncateString(cmd.Args, maxWidth-20)

		// Highlight selected item
		if i == m.selectedIdx {
			row := fmt.Sprintf(" ▶ %s  %s  %s %s [%s]",
				dimStyle.Render(ts),
				decisionStr,
				selectedStyle.Render(truncatedCmd),
				selectedStyle.Render(truncatedArgs),
				infoStyle.Render(cmd.Reason))
			sb.WriteString(cardStyle.Render(row))
		} else {
			row := fmt.Sprintf("   %s  %s  %s %s [%s]",
				dimStyle.Render(ts),
				decisionStr,
				titleStyle.Render(truncatedCmd),
				dimStyle.Render(truncatedArgs),
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
	case "DENY":
		decisionStr = denyStyle.Render("✗ DENY")
	default:
		decisionStr = dimStyle.Render("◌ PENDING")
	}

	// Render expanded command header
	row := fmt.Sprintf("  %s  %s  %s %s [%s]",
		dimStyle.Render(ts),
		decisionStr,
		titleStyle.Render(cmd.Command),
		dimStyle.Render(cmd.Args),
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

	// Build full command text
	fullText := cmd.Command
	if len(cmd.Args) > 0 {
		fullText += " " + cmd.Args
	}

	// Wrap text and apply scrolling
	wrappedLines := wrapText(fullText, m.width-12)
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
	if len(cmd.Args) > 0 {
		cmdSuggestion += " " + cmd.Args
	}
	equalsContent := "[=] " + truncateString(cmdSuggestion, 30)
	plusContent := "[+] session"

	if m.focus == "actions" {
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
