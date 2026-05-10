// tui_router_view.go - Router.View rendering.

package main

import (
	"fmt"
	"os"
)

// View renders the current view stack.
func (m *Router) View() string {
	if len(m.viewStack) == 0 {
		return ""
	}

	// Render the top view (mode modal if on stack renders on top)
	top := m.currentView()
	return top.View()
}

// retryPendingDecisions retries any pending failed decisions.
// MaxRetries is the maximum number of retry attempts before giving up.
const MaxRetries = 3

// retryPendingDecisions retries any pending failed decisions.
func (m *Router) retryPendingDecisions() {
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

		if cmd.RetryCount >= MaxRetries {
			// Give up: mark as timed out and clean up
			delete(pendingRequests, id)
			delete(m.pendingRetry, id)
			cmd.Decision = "DENY"
			cmd.Reason = "request timed out"
			m.SetFlash("Request timed out", FlashTimerSeconds)
			m.stats.totalUnknown--
			m.stats.totalDenied++
			continue
		}

		decision := DecisionAllow
		if cmd.IntendedDecision == "DENY" {
			decision = DecisionDeny
		}
		cmd.RetryCount++

		err := req.Decide(decision, cmd.OriginalReason, cmd.Duration, cmd.EnvDecisions)
		if err != nil {
			continue
		}

		// Successful retry - update command log
		delete(pendingRequests, id)
		delete(m.pendingRetry, id)

		cmd.Decision = cmd.IntendedDecision
		cmd.Reason = cmd.OriginalReason
		m.SetFlash(cmd.IntendedDecision+" succeeded", FlashTimerSeconds)

		// Update stats
		m.stats.totalUnknown--
		m.RecordDecision(cmd.IntendedDecision)
	}
}