// tui_views.go - View interface for the view-stack architecture.

package main

import "github.com/charmbracelet/bubbletea"

// View is the interface all screen views must implement.
// Embedding tea.Model means views are full Bubble Tea models with Init/Update/View,
// plus a Name() for routing and debugging.
type View interface {
	tea.Model
	// Name returns a unique identifier for this view, used for routing/debugging.
	Name() string
}

// Focusable is implemented by views that manage cursor visibility.
// OnFocus is called when the view gains focus (becomes the top of the stack).
// OnBlur is called when the view loses focus (pushed down or popped from stack).
// Teardown is called when the program is quitting, after all views are popped.
type Focusable interface {
	View
	// OnFocus hides the cursor (writes \033[?25l to terminal).
	OnFocus()
	// OnBlur restores the cursor (writes \033[?25h to terminal).
	OnBlur()
	// Teardown is called on program exit; use to restore terminal to a clean state.
	// For views that hide the cursor, this should restore it (\033[?25h).
	Teardown()
}