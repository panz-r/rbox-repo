// tui_messages.go - Custom message types for view-stack communication.

package main

import "github.com/charmbracelet/bubbletea"

// PushViewMsg is the internal message used to push a view onto the stack.
type PushViewMsg struct {
	View View
}

// PopViewMsg signals that the top view should be popped from the stack.
type PopViewMsg struct{}

// PushView returns a tea.Cmd that sends a PushViewMsg wrapping the given view.
// Usage: return m, PushView(NewHistoryListView(router))
func PushView(v View) tea.Cmd {
	return func() tea.Msg {
		return PushViewMsg{View: v}
	}
}

// PopView returns a tea.Cmd that pops the top view from the stack.
// Usage: return m, PopView()
func PopView() tea.Cmd {
	return func() tea.Msg {
		return PopViewMsg{}
	}
}

// SuggestionEditedMsg is sent when a user finishes editing a suggestion pattern.
type SuggestionEditedMsg struct {
	SuggestionIdx int
	NewPattern    string
	Accepted      bool
}

// DecisionExecutedMsg is sent after executeDecision completes successfully.
type DecisionExecutedMsg struct{}

// PolicyClearedMsg is sent after the policy gate is cleared.
type PolicyClearedMsg struct{}

// PolicyCleared returns a tea.Cmd that sends a PolicyClearedMsg.
func PolicyCleared() tea.Cmd {
	return func() tea.Msg {
		return PolicyClearedMsg{}
	}
}