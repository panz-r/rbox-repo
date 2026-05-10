// tui_router.go - The main Router that replaces the original Model.

package main

import (
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/panz-r/rbox-repo/rbox-server/shell"
)

// Router is the top-level Bubble Tea model. It owns all truly global state
// and a stack of View instances. All keyboard/command handling that is
// global (e.g., quit, mode modal) lives here; view-specific handling
// is delegated to the top-of-stack view.
type Router struct {
	// --- Truly global state (was spread across original Model) ---
	commands        []*CommandLog
	width           int
	height          int
	stats           Stats
	flashTimer      int
	flashMessage    string
	eventChan       chan Event
	gate            *shell.Gate
	pendingRetry    map[int]*CommandLog
	violOverrides   map[uint32]bool
	opMode          OpMode

	// --- View stack ---
	viewStack []View

	// --- Edit mode state (shared by DecisionView + EditSuggestionView) ---
	editMode          bool
	editTokenIdx      int
	editVariantIdx    int
	editVariants      [][]string
	editSuggestionIdx int
}

// NewRouter creates a new Router with the given shellgate policy engine.
func NewRouter(gate *shell.Gate) *Router {
	return &Router{
		commands:        make([]*CommandLog, 0),
		stats:           Stats{},
		eventChan:       make(chan Event, EventChanBufferSize),
		gate:            gate,
		pendingRetry:    make(map[int]*CommandLog),
		violOverrides:   make(map[uint32]bool),
		opMode:          OpModeInteractive,

		// Edit mode
		editMode:          false,
		editTokenIdx:      0,
		editVariantIdx:    0,
		editSuggestionIdx: -1,
	}
}

// Init starts the timer tick for flash messages and pushes the initial view.
func (m *Router) Init() tea.Cmd {
	return tea.Batch(
		PushView(NewHistoryListView(m)),
		tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return t
		}),
	)
}

// currentView returns the top view on the stack, or nil if empty.
func (m *Router) currentView() View {
	if len(m.viewStack) == 0 {
		return nil
	}
	return m.viewStack[len(m.viewStack)-1]
}

// --- State accessors ---

func (m *Router) Commands() []*CommandLog         { return m.commands }
func (m *Router) Stats() Stats                    { return m.stats }
func (m *Router) Width() int                     { return m.width }
func (m *Router) Height() int                   { return m.height }
func (m *Router) OpMode() OpMode                 { return m.opMode }
func (m *Router) Gate() *shell.Gate               { return m.gate }
func (m *Router) FlashTimer() int                { return m.flashTimer }
func (m *Router) FlashMessage() string           { return m.flashMessage }
func (m *Router) PendingRetry() map[int]*CommandLog { return m.pendingRetry }
func (m *Router) ViolOverrides() map[uint32]bool { return m.violOverrides }
func (m *Router) EventChan() chan<- Event         { return m.eventChan }

// AddCommand appends a new command log entry.
func (m *Router) AddCommand(cmd *CommandLog) {
	m.commands = append(m.commands, cmd)
	// Enforce MaxHistory limit
	if len(m.commands) > MaxHistory {
		start := len(m.commands) - MaxHistory
		m.commands = m.commands[start:]
	}
	// Update stats based on decision
	switch cmd.Decision {
	case "PENDING":
		m.stats.totalUnknown++
	case "POLICY ALLOW", "ALLOW":
		m.stats.totalAllowed++
	case "POLICY DENY", "DENY":
		m.stats.totalDenied++
	}
}

// SetFlash sets a flash message with a duration.
func (m *Router) SetFlash(msg string, ticks int) {
	m.flashMessage = msg
	m.flashTimer = ticks
}

// RecordDecision updates stats after a decision is executed.
func (m *Router) RecordDecision(decision string) {
	switch decision {
	case "ALLOW":
		m.stats.totalAllowed++
	case "DENY":
		m.stats.totalDenied++
	}
}

// GetCommand returns the command log entry at the given index.
func (m *Router) GetCommand(idx int) *CommandLog {
	if idx < 0 || idx >= len(m.commands) {
		return nil
	}
	return m.commands[idx]
}

// Teardown calls Teardown on all views in the stack.
// Safe to call multiple times; each view's Teardown is idempotent.
func (m *Router) Teardown() {
	for _, v := range m.viewStack {
		if f, ok := v.(Focusable); ok {
			f.Teardown()
		}
	}
}