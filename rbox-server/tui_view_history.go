// tui_view_history.go - History list view.

package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbletea"
)

// HistoryListView displays the command history list (step 1).
type HistoryListView struct {
	router   *Router
	cursor   int    // selectedIdx
	scrollY  int    // scroll offset
}

// NewHistoryListView creates a new history list view.
func NewHistoryListView(router *Router) *HistoryListView {
	return &HistoryListView{
		router:  router,
		cursor:  0,
		scrollY: 0,
	}
}

func (v *HistoryListView) Router() *Router { return v.router }
func (v *HistoryListView) Name() string    { return "HistoryListView" }
func (v *HistoryListView) Init() tea.Cmd  { return nil }

// Update handles navigation within the history list.
func (v *HistoryListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		commands := v.router.Commands()
		if len(commands) == 0 {
			return v, nil
		}

		switch msg.String() {
		case "up":
			if v.cursor > 0 {
				v.cursor--
				if v.cursor < v.scrollY {
					v.scrollY = maxInt(0, v.scrollY-1)
				}
			}

		case "down":
			if v.cursor < len(commands)-1 {
				v.cursor++
				historyAvailable := (v.router.Height() - 5) / 3
				if historyAvailable < 1 {
					historyAvailable = 1
				}
				if v.cursor >= v.scrollY+historyAvailable {
					v.scrollY++
				}
			}

		case "home":
			v.cursor = 0
			v.scrollY = 0

		case "end":
			v.cursor = len(commands) - 1
			historyAvailable := (v.router.Height() - 5) / 3
			if historyAvailable < 1 {
				historyAvailable = 1
			}
			v.scrollY = maxInt(0, len(commands)-historyAvailable)

		case "enter", "a", "A", "d", "D":
			if v.cursor >= 0 && v.cursor < len(commands) {
				selectedCmd := commands[v.cursor]
				// Push decision view for PENDING commands or if explicitly selected with A/D
				if selectedCmd.Decision == "PENDING" || msg.String() != "enter" {
					allowChosen := msg.String() == "a" || msg.String() == "A"
					view := NewDecisionView(v.router, selectedCmd, allowChosen)
					return v, PushView(view)
				}
			}

		case "c", "C":
			// Clear policy
			return v, PolicyCleared()

		case "ctrl+z":
			// No-op in history view (already at root)
			return v, nil

		case "shift+tab":
			return v, PushView(NewModeModalView(v.router))
		}

	case Event:
		// A new command arrived - auto-select it only if the cursor was already
		// at (or near) the newest entry. This avoids disorienting jumps when the
		// user is browsing older history entries.
		if msg.Type == EventNewRequest && v.router != nil {
			commands := v.router.Commands()
			if len(commands) > 1 && v.cursor >= len(commands)-2 {
				v.cursor = len(commands) - 1
				// Adjust scroll to show new item
				historyAvailable := (v.router.Height() - 5) / 3
				if historyAvailable < 1 {
					historyAvailable = 1
				}
				v.scrollY = maxInt(0, len(commands)-historyAvailable)
			}
		}
	}

	return v, nil
}

// View renders the history list.
func (v *HistoryListView) View() string {
	var sb strings.Builder
	commands := v.router.Commands()
	width := v.router.Width()
	height := v.router.Height()

	historyAvailable := (height - 5) / 3
	if historyAvailable < 1 {
		historyAvailable = 1
	}

	// Clamp scroll and compute visible range
	if v.cursor < v.scrollY {
		v.scrollY = v.cursor
	}
	if v.cursor >= v.scrollY+historyAvailable {
		v.scrollY = maxInt(0, v.cursor-historyAvailable+1)
	}
	var visibleStart, visibleEnd int
	v.scrollY, visibleStart, visibleEnd = clipScrollSlice(v.scrollY, historyAvailable, len(commands))

	// Header
	renderHeader(&sb, width, v.router.FlashTimer(), v.router.Stats(), len(v.router.PendingRetry()), v.router.OpMode(), v.router.FlashMessage())

	// History items
	maxWidth := width - 50
	if maxWidth < MinTruncateWidth {
		maxWidth = MinTruncateWidth
	}

	for i := visibleStart; i < visibleEnd; i++ {
		cmd := commands[i]
		ts := cmd.Timestamp.Format("15:04:05")

		var decisionStr string
		switch cmd.Decision {
		case "ALLOW", "POLICY ALLOW":
			decisionStr = allowStyle.Render("✓")
		case "DENY", "POLICY DENY":
			decisionStr = denyStyle.Render("✗")
		case "RETRY":
			decisionStr = infoStyle.Render("↻")
		default:
			decisionStr = dimStyle.Render("?")
		}

		if cmd.Decision == "PENDING" {
			decisionStr = dimStyle.Render("◌")
		}

		summary := buildCommandSummary(cmd)
		truncatedSummary := truncateString(summary, maxWidth)

		if i == v.cursor {
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

	// Footer
	controls := "↑↓ navigate  Enter/A/D expand  C clear policy  Shift+Tab mode  q/ctrl+c quit"
	renderFooter(&sb, width, controls)

	return sb.String()
}

// OnFocus is a no-op (history list always shows cursor).
func (v *HistoryListView) OnFocus() {
}

// OnBlur is a no-op (history list always shows cursor).
func (v *HistoryListView) OnBlur() {
}

// Teardown is a no-op for HistoryListView.
func (v *HistoryListView) Teardown() {
}