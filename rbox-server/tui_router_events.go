// tui_router_events.go - Event handling for the router.

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/panz-r/rbox-repo/rbox-server/shell"
)

// handleEvent processes an incoming Event and updates router state.
func (m *Router) handleEvent(evt Event) []tea.Cmd {
	var cmds []tea.Cmd

	switch evt.Type {
	case EventNewRequest:
		// Close any stale edit view across the entire stack
		kept := make([]View, 0, len(m.viewStack))
		for _, v := range m.viewStack {
			if ev, ok := v.(*EditSuggestionView); ok {
				if ev.cmd != nil && ev.cmd.RequestID != evt.RequestID {
					// Stale edit view — call Teardown and skip it
					if fb, ok := v.(Focusable); ok {
						fb.Teardown()
					}
					m.endEditMode()
					continue
				}
			}
			kept = append(kept, v)
		}
		m.viewStack = kept

		// Restore focus to new top view if it implements Focusable
		if len(m.viewStack) > 0 {
			if fb, ok := m.currentView().(Focusable); ok {
				fb.OnFocus()
			}
		}

		// Evaluate through shellgate (single-threaded gate access)
		var evalResult *shell.EvalResult
		if m.gate != nil {
			var err error
			evalResult, err = m.gate.Eval(evt.Command)
			if err != nil {
				evalResult = &shell.EvalResult{
					Verdict:    shell.VerdictUndetermined,
					DenyReason: "eval error: " + err.Error(),
				}
			} else if evalResult != nil && evalResult.Truncated {
				fmt.Fprintf(os.Stderr, "Warning: shellgate buffer truncated for command: %s\n", evt.Command)
			}
		}

		// Auto-allow/auto-deny logic
		autoAllowed := false
		autoDenied := false
		if evalResult != nil && len(evt.EnvVars) == 0 {
			ev := evalResult
			if ev.Verdict == shell.VerdictAllow && len(ev.Suggestions) == 0 {
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
					evt.Req.Decide(DecisionAllow, "once", 0, nil)
					m.AddCommand(&CommandLog{
						Timestamp:    time.Now(),
						Decision:     "POLICY ALLOW",
						Command:      evt.Command,
						Args:         evt.Args,
						Caller:       evt.Caller,
						Syscall:      evt.Syscall,
						Reason:       "policy-allow",
						ClientID:     evt.ClientID,
						RequestID:    evt.RequestID,
						Cwd:          evt.Cwd,
						EnvVars:      evt.EnvVars,
						EnvDecisions: make([]EnvVarDecision, len(evt.EnvVars)),
						EvalResult:   evalResult,
					})
				}
			} else if ev.Verdict == shell.VerdictDeny && len(ev.DenySuggestions) == 0 {
				autoDenied = true
				evt.Req.Decide(DecisionDeny, "once", 0, nil)
				m.AddCommand(&CommandLog{
					Timestamp:    time.Now(),
					Decision:     "POLICY DENY",
					Command:      evt.Command,
					Args:         evt.Args,
					Caller:       evt.Caller,
					Syscall:      evt.Syscall,
					Reason:       "policy-deny",
					ClientID:     evt.ClientID,
					RequestID:    evt.RequestID,
					Cwd:          evt.Cwd,
					EnvVars:      evt.EnvVars,
					EnvDecisions: make([]EnvVarDecision, len(evt.EnvVars)),
					EvalResult:   evalResult,
				})
			}
		}

		if !autoAllowed && !autoDenied {
			switch m.opMode {
			case OpModePassthrough:
				evt.Req.Decide(DecisionAllow, "once", 0, nil)
				m.AddCommand(&CommandLog{
					Timestamp:    time.Now(),
					Decision:     "ALLOW",
					Command:      evt.Command,
					Args:         evt.Args,
					Caller:       evt.Caller,
					Syscall:      evt.Syscall,
					Reason:       "passthrough",
					ClientID:     evt.ClientID,
					RequestID:    evt.RequestID,
					Cwd:          evt.Cwd,
					EnvVars:      evt.EnvVars,
					EnvDecisions: make([]EnvVarDecision, len(evt.EnvVars)),
					EvalResult:   evalResult,
				})
			case OpModeAuto:
				if evalResult != nil && (len(evalResult.Suggestions) > 0 || len(evalResult.DenySuggestions) > 0 || len(evt.EnvVars) > 0) {
					evt.Req.Decide(DecisionDeny, "once", 0, nil)
					m.AddCommand(&CommandLog{
						Timestamp:    time.Now(),
						Decision:     "DENY",
						Command:      evt.Command,
						Args:         evt.Args,
						Caller:       evt.Caller,
						Syscall:      evt.Syscall,
						Reason:       "auto-deny: needs user input",
						ClientID:     evt.ClientID,
						RequestID:    evt.RequestID,
						Cwd:          evt.Cwd,
						EnvVars:      evt.EnvVars,
						EnvDecisions: make([]EnvVarDecision, len(evt.EnvVars)),
						EvalResult:   evalResult,
					})
				} else {
					StoreRequest(evt.RequestID, evt.Req)
					m.AddCommand(&CommandLog{
						Timestamp:    time.Now(),
						Decision:     "PENDING",
						Command:      evt.Command,
						Args:         evt.Args,
						Caller:       evt.Caller,
						Syscall:      evt.Syscall,
						Reason:       "waiting for decision",
						ClientID:     evt.ClientID,
						RequestID:    evt.RequestID,
						Cwd:          evt.Cwd,
						EnvVars:      evt.EnvVars,
						EnvDecisions: make([]EnvVarDecision, len(evt.EnvVars)),
						EvalResult:   evalResult,
					})
				}
			default:
				StoreRequest(evt.RequestID, evt.Req)
				m.AddCommand(&CommandLog{
					Timestamp:    time.Now(),
					Decision:     "PENDING",
					Command:      evt.Command,
					Args:         evt.Args,
					Caller:       evt.Caller,
					Syscall:      evt.Syscall,
					Reason:       "waiting for decision",
					ClientID:     evt.ClientID,
					RequestID:    evt.RequestID,
					Cwd:          evt.Cwd,
					EnvVars:      evt.EnvVars,
					EnvDecisions: make([]EnvVarDecision, len(evt.EnvVars)),
					EvalResult:   evalResult,
				})
			}
		}

	case EventAddPendingRetry:
		var cmdLog *CommandLog
		for _, c := range m.commands {
			if c.RequestID == evt.RequestID {
				cmdLog = c
				break
			}
		}
		if cmdLog != nil {
			cmdLog.Decision = "RETRY"
			cmdLog.IntendedDecision = evt.RetryDecision
			cmdLog.OriginalReason = evt.RetryReason
			cmdLog.Duration = evt.RetryDuration
			cmdLog.EnvDecisions = evt.RetryEnvDecisions
			m.pendingRetry[evt.RequestID] = cmdLog
			m.SetFlash("Retrying...", FlashTimerSeconds)
		}
	}

	return cmds
}

// endEditMode resets the edit mode state on the router.
// Idempotent: calling when not in edit mode is a no-op.
func (m *Router) endEditMode() {
	if !m.editMode {
		return
	}
	m.editMode = false
	m.editTokenIdx = 0
	m.editVariantIdx = 0
	m.editVariants = nil
	m.editSuggestionIdx = -1
}

