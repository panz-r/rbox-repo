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
)

type Event struct {
	Type     EventType
	Decision string
	Command  string
	Args     string
	Reason   string
	Log      string
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
}

func NewModel() *Model {
	return &Model{
		commands:  make([]CommandLog, 0),
		logs:      make([]string, 0),
		stats:     Stats{},
		eventChan: make(chan Event, 100),
	}
}

func (m *Model) AddConnection() {
	m.connections++
}

func (m *Model) AddCommand(decision, cmd, args, reason, clientID string) {
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
	}
	m.commands = append(m.commands, log)

	switch decision {
	case "ALLOW":
		m.stats.totalAllowed++
	case "DENY":
		m.stats.totalDenied++
	default:
		m.stats.totalUnknown++
	}

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
			if m.scrollY > 0 {
				m.scrollY--
			}
		case "down":
			if m.scrollY < len(m.commands)-1 {
				m.scrollY++
			}
		case "home":
			m.scrollY = 0
		case "end":
			m.scrollY = max(0, len(m.commands)-1)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case Event:
		switch msg.Type {
		case EventConnect:
			m.connections++
		case EventCommand:
			m.AddCommand(msg.Decision, msg.Command, msg.Args, msg.Reason, "")
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

func (m *Model) View() string {
	var sb strings.Builder

	title := fmt.Sprintf(" readonlybox-server v1.0 | %d commands | %s ",
		len(m.commands),
		time.Now().Format("15:04:05"))
	sb.WriteString(titleStyle.Render(title))
	sb.WriteString("\n")

	statsBar := fmt.Sprintf(" %s %d  %s %d  %s %d ",
		allowStyle.Render("●"),
		m.stats.totalAllowed,
		denyStyle.Render("●"),
		m.stats.totalDenied,
		dimStyle.Render("●"),
		m.stats.totalUnknown)
	sb.WriteString(headerStyle.Render(statsBar))
	sb.WriteString("\n")

	if m.flashTimer > 0 && m.lastCmd != "" {
		var flashStr string
		switch m.lastDecision {
		case "ALLOW":
			flashStr = allowStyle.Render("⚡ " + m.lastCmd)
		case "DENY":
			flashStr = denyStyle.Render("⚡ " + m.lastCmd)
		default:
			flashStr = dimStyle.Render("⚡ " + m.lastCmd)
		}
		sb.WriteString(cardStyle.Render(flashStr))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")

	if len(m.commands) == 0 {
		sb.WriteString(dimStyle.Render("  Waiting for commands...\n"))
	} else {
		start := maxInt(0, len(m.commands)-m.scrollY-8)
		if start > len(m.commands)-8 {
			start = maxInt(0, len(m.commands)-8)
		}
		end := minInt(len(m.commands), start+8)
		if end < 8 {
			end = minInt(len(m.commands), 8)
		}

		for i := start; i < end; i++ {
			cmd := m.commands[len(m.commands)-1-i]
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

			row := fmt.Sprintf("  %s  %s  %s %s %s",
				dimStyle.Render(ts),
				decisionStr,
				titleStyle.Render(cmd.Command),
				dimStyle.Render(cmd.Args),
				infoStyle.Render(fmt.Sprintf("[%s]", cmd.Reason)),
			)
			sb.WriteString(cardStyle.Render(row))
			sb.WriteString("\n")
		}

		if len(m.commands) > 8 {
			sb.WriteString(fmt.Sprintf("\n%s  Use ↑↓ to scroll, q to quit\n",
				dimStyle.Render(fmt.Sprintf("Showing %d of %d commands", end-start, len(m.commands)))))
		}
	}

	/* Log section */
	if len(m.logs) > 0 {
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render(" Logs:"))
		sb.WriteString("\n")
		start := len(m.logs) - 5
		if start < 0 {
			start = 0
		}
		for i := start; i < len(m.logs); i++ {
			logLine := dimStyle.Render("  ") + infoStyle.Render(m.logs[i])
			sb.WriteString(cardStyle.Render(logLine))
			sb.WriteString("\n")
		}
	}

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

func RunTUIMode() {
	model := NewModel()

	server := NewServer()
	server.onConnect = func() {
		select {
		case model.eventChan <- Event{Type: EventConnect}:
		default:
		}
	}
	server.onCommand = func(decision, cmd string, args []string, reason string) {
		argsStr := strings.Join(args, " ")
		select {
		case model.eventChan <- Event{Type: EventCommand, Decision: decision, Command: cmd, Args: argsStr, Reason: reason}:
		default:
		}
	}
	server.onLog = func(log string) {
		select {
		case model.eventChan <- Event{Type: EventLog, Log: log}:
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
