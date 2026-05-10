// tui_router_update.go - Router.Update delegation and global key handling.

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/panz-r/rbox-repo/rbox-server/shell"
)

// Update handles all messages. Global keys (quit, mode modal, resize) are handled
// here. All other keys are delegated to the top-of-stack view.
func (m *Router) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	// --- Global key handling ---
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.Teardown()
			return m, tea.Quit

		default:
			if len(m.viewStack) > 0 {
				_, cmd := m.currentView().Update(msg)
				if cmd != nil {
					cmds = append(cmds, cmd)
				}
			}
			return m, tea.Batch(cmds...)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		for _, v := range m.viewStack {
			v.Update(msg)
		}
		return m, nil

	// --- Push/Pop view stack ---
	case PushViewMsg:
		if len(m.viewStack) > 0 {
			if fb, ok := m.currentView().(Focusable); ok {
				fb.OnBlur()
			}
		}
		m.viewStack = append(m.viewStack, msg.View)
		if fb, ok := msg.View.(Focusable); ok {
			fb.OnFocus()
		}
		return m, tea.Batch(
			msg.View.Init(),
			func() tea.Msg { return tea.WindowSizeMsg{Width: m.width, Height: m.height} },
		)

	case PopViewMsg:
		if len(m.viewStack) == 0 {
			return m, nil
		}
		top := m.currentView()
		if fb, ok := top.(Focusable); ok {
			fb.OnBlur()
		}
		m.viewStack = m.viewStack[:len(m.viewStack)-1]
		if len(m.viewStack) > 0 {
			if fb, ok := m.currentView().(Focusable); ok {
				fb.OnFocus()
			}
		}
		return m, nil

	// --- Shared messages from views ---
	case DecisionExecutedMsg:
		if len(m.viewStack) == 0 {
			return m, nil
		}
		top := m.currentView()
		if fb, ok := top.(Focusable); ok {
			fb.OnBlur()
		}
		m.viewStack = m.viewStack[:len(m.viewStack)-1]
		if len(m.viewStack) > 0 {
			if fb, ok := m.currentView().(Focusable); ok {
				fb.OnFocus()
			}
		}
		return m, nil

	case PolicyClearedMsg:
		if m.gate != nil {
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
		}
		m.SetFlash("Policy cleared", FlashTimerSeconds)
		return m, nil

	// --- Incoming events from the server ---
	case Event:
		cmds = append(cmds, m.handleEvent(msg)...)
		if len(m.viewStack) > 0 {
			if _, vcmd := m.currentView().Update(msg); vcmd != nil {
				cmds = append(cmds, vcmd)
			}
		}
		return m, tea.Batch(cmds...)

	// --- Timer tick ---
	case time.Time:
		if m.flashTimer > 0 {
			m.flashTimer--
		}
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg { return t })
	}

	return m, nil
}