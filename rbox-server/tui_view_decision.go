// tui_view_decision.go - Decision view (step 2).

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/panz-r/rbox-repo/rbox-server/shell"
)

// DecisionView handles the allow/deny decision flow with durations, suggestions, and env vars.
type DecisionView struct {
	router         *Router
	command        *CommandLog
	allowChosen    bool
	focus          string   // "actions" or "details"
	cursor         int      // position: 0-3=duration, 4+=suggestions
	envVarCursor   int      // -1 = command selected, 0+ = index of selected env var
	suggAccepted   []bool   // per-suggestion accept state
	suggDuration   int      // last selected duration (0-3)
	viewOnly       bool
	logDecision    bool
	detailsScrollY int     // scroll offset for details pane
}

// NewDecisionView creates a new decision view for a command.
func NewDecisionView(router *Router, cmd *CommandLog, allowChosen bool) *DecisionView {
	v := &DecisionView{
		router:         router,
		command:        cmd,
		allowChosen:    allowChosen,
		focus:          "actions",
		cursor:         0,
		envVarCursor:   -1,
		viewOnly:       cmd.Decision != "PENDING",
		detailsScrollY: 0,
	}
	v.initSuggestions()
	return v
}

func (v *DecisionView) Router() *Router     { return v.router }
func (v *DecisionView) Name() string        { return "DecisionView" }
func (v *DecisionView) Init() tea.Cmd       { return nil }
func (v *DecisionView) Command() *CommandLog { return v.command }

func (v *DecisionView) initSuggestions() {
	if v.command != nil && v.command.EvalResult != nil {
		ev := v.command.EvalResult
		suggs := ev.Suggestions
		if !v.allowChosen {
			if len(ev.DenySuggestions) > 0 {
				suggs = ev.DenySuggestions
			} else if len(ev.Suggestions) > 0 {
				suggs = ev.Suggestions
			}
		}
		if len(suggs) > 0 {
			v.suggAccepted = make([]bool, len(suggs))
			return
		}
	}
	v.suggAccepted = nil
}

func (v *DecisionView) activeSuggestions() []string {
	if v.command == nil || v.command.EvalResult == nil {
		return nil
	}
	ev := v.command.EvalResult
	if !v.allowChosen && len(ev.DenySuggestions) > 0 {
		return ev.DenySuggestions
	}
	return ev.Suggestions
}

func (v *DecisionView) suggCount() int {
	return len(v.suggAccepted)
}

func (v *DecisionView) maxCursor() int {
	return 3 + v.suggCount()
}

// Update handles decision interactions.
func (v *DecisionView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if v.viewOnly {
			return v, v.handleViewOnlyKeys(msg)
		}
		return v, v.handleInteractiveKeys(msg)

	case SuggestionEditedMsg:
		// A suggestion was edited; update the EvalResult
		if v.command != nil && v.command.EvalResult != nil {
			active := v.activeSuggestions()
			if msg.SuggestionIdx >= 0 && msg.SuggestionIdx < len(active) {
				if !v.allowChosen {
					v.command.EvalResult.DenySuggestions[msg.SuggestionIdx] = msg.NewPattern
				} else {
					v.command.EvalResult.Suggestions[msg.SuggestionIdx] = msg.NewPattern
				}
			}
			if msg.Accepted {
				v.suggAccepted[msg.SuggestionIdx] = true
			}
		}

	case time.Time:
		// Handle pending retries
		v.router.retryPendingDecisions()
	}

	return v, nil
}

func (v *DecisionView) handleViewOnlyKeys(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "ctrl+z":
		return PopView()
	case "home":
		if v.focus == "details" {
			v.envVarCursor = 0
			v.detailsScrollY = 0
		}
	case "end":
		if v.focus == "details" && len(v.command.EnvVars) > 0 {
			v.envVarCursor = len(v.command.EnvVars) - 1
		}
		v.detailsScrollY = 9999
	case "up":
		if v.focus == "details" {
			if len(v.command.EnvVars) > 0 && v.envVarCursor > 0 {
				v.envVarCursor--
			}
			if v.detailsScrollY > 0 {
				v.detailsScrollY--
			}
		}
	case "down":
		if v.focus == "details" {
			if len(v.command.EnvVars) > 0 && v.envVarCursor < len(v.command.EnvVars)-1 {
				v.envVarCursor++
			}
			v.detailsScrollY++
		}
	case "tab":
		v.toggleFocus()
	case "shift+tab":
		return PushView(NewModeModalView(v.router))
	}
	return nil
}

func (v *DecisionView) handleInteractiveKeys(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "home":
		if v.focus == "actions" {
			v.cursor = 0
			v.suggDuration = 0
		} else if v.focus == "details" {
			v.envVarCursor = 0
			v.detailsScrollY = 0
		}
	case "end":
		if v.focus == "actions" {
			v.cursor = v.maxCursor()
			if v.cursor > 3 {
				v.suggDuration = 3
			}
		} else if v.focus == "details" {
			if len(v.command.EnvVars) > 0 {
				v.envVarCursor = len(v.command.EnvVars) - 1
			}
			// Set to large value; renderDetails clamps it to valid range
			v.detailsScrollY = 9999
		}

	case "up":
		if v.focus == "actions" {
			v.cursor--
			if v.cursor < 0 {
				v.cursor = v.maxCursor()
			}
			if v.cursor <= 3 {
				v.suggDuration = v.cursor
			}
		} else if v.focus == "details" {
			if len(v.command.EnvVars) > 0 && v.envVarCursor > 0 {
				v.envVarCursor--
			}
			if v.detailsScrollY > 0 {
				v.detailsScrollY--
			}
		}

	case "down":
		if v.focus == "actions" {
			v.cursor++
			if v.cursor > v.maxCursor() {
				v.cursor = 0
			}
			if v.cursor <= 3 {
				v.suggDuration = v.cursor
			}
		} else if v.focus == "details" {
			if len(v.command.EnvVars) > 0 && v.envVarCursor < len(v.command.EnvVars)-1 {
				v.envVarCursor++
			}
			v.detailsScrollY++
		}

	case "left":
		if v.focus == "details" && v.envVarCursor >= 0 {
			if v.envVarCursor < len(v.command.EnvDecisions) {
				v.command.EnvDecisions[v.envVarCursor].Decision = 1
			}
		} else if v.focus == "actions" {
			if v.cursor <= 3 {
				v.cursor--
				if v.cursor < 0 {
					v.cursor = v.maxCursor()
				}
				v.suggDuration = v.cursor
			} else {
				si := v.cursor - 4
				if si >= 0 && si < v.suggCount() {
					v.suggAccepted[si] = false
				}
			}
		}

	case "right":
		if v.focus == "details" && v.envVarCursor >= 0 {
			if v.envVarCursor < len(v.command.EnvDecisions) {
				v.command.EnvDecisions[v.envVarCursor].Decision = 0
			}
		} else if v.focus == "actions" {
			if v.cursor <= 3 {
				v.cursor++
				if v.cursor > 3 && v.suggCount() > 0 {
					v.cursor = 4
				} else if v.cursor > 3 {
					v.cursor = 0
				}
				v.suggDuration = v.cursor
			} else {
				si := v.cursor - 4
				if si >= 0 && si < v.suggCount() {
					v.suggAccepted[si] = true
				}
			}
		}

	case "tab":
		v.toggleFocus()
	case "shift+tab":
		return PushView(NewModeModalView(v.router))

	case "a", "A":
		if v.focus == "details" && v.envVarCursor >= 0 {
			if v.envVarCursor < len(v.command.EnvDecisions) {
				v.command.EnvDecisions[v.envVarCursor].Decision = 0
			}
		} else {
			v.allowChosen = true
			v.cursor = 0
			v.focus = "actions"
			v.initSuggestions()
		}

	case "d", "D":
		if v.focus == "details" && v.envVarCursor >= 0 {
			if v.envVarCursor < len(v.command.EnvDecisions) {
				v.command.EnvDecisions[v.envVarCursor].Decision = 1
			}
		} else {
			v.allowChosen = false
			v.cursor = 0
			v.focus = "actions"
			v.initSuggestions()
		}

	case "l", "L":
		v.logDecision = !v.logDecision

	case "1":
		v.cursor = 0
		v.suggDuration = 0
		return func() tea.Msg { return v.executeDecision() }
	case "2":
		v.cursor = 1
		v.suggDuration = 1
		return func() tea.Msg { return v.executeDecision() }
	case "3":
		v.cursor = 2
		v.suggDuration = 2
		return func() tea.Msg { return v.executeDecision() }
	case "4":
		v.cursor = 3
		v.suggDuration = 3
		return func() tea.Msg { return v.executeDecision() }

	case "=":
		if v.suggCount() > 0 {
			v.cursor = 4
			return func() tea.Msg { return v.executeDecision() }
		}
	case "+":
		if v.suggCount() > 1 {
			v.cursor = 5
			return func() tea.Msg { return v.executeDecision() }
		}

	case "enter":
		// If cursor is on a suggestion (row 4+), start edit mode
		if v.cursor >= 4 && v.suggCount() > 0 {
			si := v.cursor - 4
			if si >= 0 && si < v.suggCount() {
				active := v.activeSuggestions()
				pattern := active[si]
				editView := NewEditSuggestionView(v.router, v.command, si, v.allowChosen, pattern)
				return PushView(editView)
			}
		}
		return func() tea.Msg { return v.executeDecision() }

	case "esc", "ctrl+z":
		return PopView()
	}
	return nil
}

func (v *DecisionView) toggleFocus() {
	if v.focus == "actions" {
		v.focus = "details"
	} else {
		v.focus = "actions"
	}
}

func (v *DecisionView) executeDecision() tea.Msg {
	v.router.retryPendingDecisions()

	allow := v.allowChosen
	durationCursor := v.cursor
	if durationCursor > 3 {
		durationCursor = v.suggDuration
		if durationCursor < 0 || durationCursor > 3 {
			durationCursor = 0
		}
	}
	decision, reason, duration := durationToReason(allow, durationCursor)

	// Add accepted suggestions as rules to gate
	if v.router.gate != nil {
		active := v.activeSuggestions()
		for si, accepted := range v.suggAccepted {
			if accepted && si < len(active) {
				pattern := active[si]
				if pattern != "" {
					var err error
					if allow {
						err = v.router.gate.AddRule(pattern)
					} else {
						err = v.router.gate.AddDenyRule(pattern)
					}
					if err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to add %s rule %q: %v\n",
							map[bool]string{true: "allow", false: "deny"}[allow], pattern, err)
					}
				}
			}
		}
	}

	// Record violation overrides
	if allow && v.command.EvalResult != nil && v.command.EvalResult.HasViolation {
		for _, viol := range v.command.EvalResult.Violations {
			v.router.violOverrides[viol.Type] = true
		}
	}

	baseCmd := extractBaseName(v.command.Command)
	fmt.Printf("Executing: %s %s for %s %s (duration=%d)\n", decision, reason, baseCmd, v.command.Args, duration)

	var envDecisions []EnvVarDecision
	if len(v.command.EnvDecisions) > 0 {
		envDecisions = v.command.EnvDecisions
	}

	err := MakeDecision(v.command.RequestID, allow, reason, duration, envDecisions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decision failed: %v (will retry)\n", err)
		v.router.eventChan <- Event{
			Type:              EventAddPendingRetry,
			RequestID:         v.command.RequestID,
			RetryDecision:     decision,
			RetryReason:       reason,
			RetryDuration:     duration,
			RetryEnvDecisions: envDecisions,
		}
		return nil
	}

	if v.logDecision {
		v.logDecisionToFile(decision, reason)
	}

	oldDecision := v.command.Decision
	v.command.Decision = decision
	v.command.Reason = reason
	v.router.SetFlash(fmt.Sprintf("%s %s %s", decision, baseCmd, v.command.Args), FlashTimerSeconds)

	if oldDecision == "PENDING" {
		v.router.stats.totalUnknown--
		v.router.RecordDecision(decision)
	}

	// Return to history view
	return DecisionExecutedMsg{}
}

func (v *DecisionView) logDecisionToFile(decision, reason string) {
	logFile := "user_log.xml"
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	escapeXML := func(s string) string {
		s = strings.ReplaceAll(s, "&", "&amp;")
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		s = strings.ReplaceAll(s, "\"", "&quot;")
		s = strings.ReplaceAll(s, "'", "&apos;")
		return s
	}

	logEntry := fmt.Sprintf(`<response timestamp="%s">
  <request id="%d" client="%s" cwd="%s">
    <command>%s</command>
    <args>%s</args>
  </request>
  <decision action="%s" duration="%s"/>
</response>
`,
		timestamp,
		v.command.RequestID,
		escapeXML(v.command.ClientID),
		escapeXML(v.command.Cwd),
		escapeXML(v.command.Command),
		escapeXML(v.command.Args),
		decision,
		reason,
	)

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open user_log.xml: %v\n", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write to user_log.xml: %v\n", err)
	}
}

// View renders the decision view.
func (v *DecisionView) View() string {
	var sb strings.Builder
	width := v.router.Width()

	// Header
	renderHeader(&sb, width, v.router.FlashTimer(), v.router.Stats(), len(v.router.PendingRetry()), v.router.OpMode(), v.router.FlashMessage())

	if v.command == nil {
		return sb.String()
	}

	cmd := v.command
	ts := cmd.Timestamp.Format("15:04:05")

	var decisionStr string
	switch cmd.Decision {
	case "ALLOW", "POLICY ALLOW":
		decisionStr = allowStyle.Render("✓ ALLOW")
	case "DENY", "POLICY DENY":
		decisionStr = denyStyle.Render("✗ DENY")
	case "RETRY":
		decisionStr = infoStyle.Render("↻ RETRY")
	default:
		decisionStr = dimStyle.Render("◌ PENDING")
	}

	row := fmt.Sprintf("  %s  %s  %s [%s]",
		dimStyle.Render(ts),
		decisionStr,
		titleStyle.Render(cmd.Command),
		infoStyle.Render(cmd.Reason))
	sb.WriteString(cardStyle.Render(row))
	sb.WriteString("\n")

	detailsFocus := dimStyle
	if v.focus == "details" {
		detailsFocus = infoStyle
	}

	// Calculate available height for details pane
	height := v.router.Height()
	detailsMaxHeight := height - 12 // leave room for header, card, actions, footer
	if detailsMaxHeight < 5 {
		detailsMaxHeight = 5
	}

	// Details content
	v.renderDetails(&sb, detailsFocus, detailsMaxHeight)

	// Actions palette
	if !v.viewOnly && cmd.Decision == "PENDING" {
		v.renderActionsPalette(&sb, width)
	} else {
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("  This command has already been " + decisionStr))
		sb.WriteString("\n")
		if cmd.Reason != "" {
			sb.WriteString(dimStyle.Render("  Reason: " + cmd.Reason))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Footer
	var controls string
	if v.viewOnly {
		controls = "↑↓ scroll  Shift+Tab mode  Esc back"
	} else {
		controls = "A/D decision  1-4 duration  Shift+Tab mode  Esc back"
	}
	renderFooter(&sb, width, controls)

	return sb.String()
}

func (v *DecisionView) renderDetails(sb *strings.Builder, focus lipgloss.Style, maxHeight int) {
	cmd := v.command

	// Render to a temp buffer so we can clip to visible range
	var tmp strings.Builder

	tmp.WriteString(focus.Render(fmt.Sprintf("  Command: %s", cmd.Command)))
	tmp.WriteString("\n")

	if cmd.Cwd != "" {
		tmp.WriteString(focus.Render(fmt.Sprintf("  Cwd: %s", cmd.Cwd)))
	} else {
		tmp.WriteString(focus.Render("  Cwd: <unknown>"))
	}
	tmp.WriteString("\n")

	// Env vars
	if len(cmd.EnvVars) > 0 {
		for i, env := range cmd.EnvVars {
			var envStr string
			if i < len(cmd.EnvDecisions) && cmd.EnvDecisions[i].Decision == 0 {
				envStr = allowStyle.Render(fmt.Sprintf("  [✓] %s (%.2f)", env.Name, env.Score))
			} else {
				envStr = denyStyle.Render(fmt.Sprintf("→  %s (%.2f)", env.Name, env.Score))
			}
			if i == 0 {
				if i == v.envVarCursor {
					tmp.WriteString(fmt.Sprintf("  Env: > %s\n", envStr))
				} else {
					tmp.WriteString(fmt.Sprintf("  Env:   %s\n", envStr))
				}
			} else {
				if i == v.envVarCursor {
					tmp.WriteString(fmt.Sprintf("       > %s\n", envStr))
				} else {
					tmp.WriteString(fmt.Sprintf("         %s\n", envStr))
				}
			}
		}
	} else {
		v.envVarCursor = -1
	}

	// Shellgate analysis
	if cmd.EvalResult != nil {
		ev := cmd.EvalResult

		// Strip caller prefix
		fullText := cmd.Command
		if strings.HasPrefix(fullText, "[") {
			endBracket := strings.Index(fullText, "]")
			if endBracket > 0 {
				fullText = strings.TrimPrefix(fullText[endBracket+1:], " ")
			}
		}
		fullText = strings.TrimSpace(fullText)

		tmp.WriteString(focus.Render(fmt.Sprintf("  $ %s", fullText)))
		tmp.WriteString("\n")

		// Subcommands
		if len(ev.Subcmds) > 0 {
			for i, sc := range ev.Subcmds {
				pfx := "  │"
				if i == len(ev.Subcmds)-1 {
					pfx = "  └"
				}
				scVerdict := shell.VerdictName(sc.Verdict)
				var annotations []string
				if sc.WriteCount > 0 {
					annotations = append(annotations, fmt.Sprintf("W%d", sc.WriteCount))
				}
				if sc.ReadCount > 0 {
					annotations = append(annotations, fmt.Sprintf("R%d", sc.ReadCount))
				}
				if sc.EnvCount > 0 {
					annotations = append(annotations, fmt.Sprintf("E%d", sc.EnvCount))
				}
				var annStr string
				if len(annotations) > 0 {
					annStr = dimStyle.Render(fmt.Sprintf(" [%s]", strings.Join(annotations, ",")))
				}
				var verdictStyle lipgloss.Style
				switch sc.Verdict {
				case shell.VerdictAllow:
					verdictStyle = allowStyle
				case shell.VerdictDeny, shell.VerdictReject:
					verdictStyle = denyStyle
				default:
					verdictStyle = dimStyle
				}
				tmp.WriteString(fmt.Sprintf("%s %s %s%s", pfx, sc.Command, verdictStyle.Render(scVerdict), annStr))
				if sc.RejectReason != "" {
					tmp.WriteString(dimStyle.Render(fmt.Sprintf(" (%s)", sc.RejectReason)))
				}
				tmp.WriteString("\n")
			}
		}

		// Overall verdict
		verdictStr := shell.VerdictName(ev.Verdict)
		switch ev.Verdict {
		case shell.VerdictAllow:
			tmp.WriteString(allowStyle.Render(fmt.Sprintf("  Policy: %s", verdictStr)))
		case shell.VerdictDeny:
			tmp.WriteString(denyStyle.Render(fmt.Sprintf("  Policy: %s", verdictStr)))
			if ev.DenyReason != "" {
				tmp.WriteString(denyStyle.Render(fmt.Sprintf(" (%s)", ev.DenyReason)))
			}
		case shell.VerdictReject:
			tmp.WriteString(denyStyle.Render(fmt.Sprintf("  Policy: %s", verdictStr)))
		case shell.VerdictUndetermined:
			tmp.WriteString(dimStyle.Render(fmt.Sprintf("  Policy: %s", verdictStr)))
			if ev.DenyReason != "" {
				tmp.WriteString(dimStyle.Render(fmt.Sprintf(" (%s)", ev.DenyReason)))
			}
		}
		tmp.WriteString("\n")

		// Violations
		if ev.HasViolation && len(ev.Violations) > 0 {
			tmp.WriteString("\n")
			tmp.WriteString(denyStyle.Render("  Violations:"))
			tmp.WriteString("\n")
			for _, viol := range ev.Violations {
				cat := shell.ViolationTypeName(viol.Type)
				severityBar := strings.Repeat("▓", int(viol.Severity/10))
				severityEmpty := strings.Repeat("░", 10-len(severityBar))
				tmp.WriteString(fmt.Sprintf("    %s [%s%s] %s: %s",
					cat, severityBar, severityEmpty,
					viol.Description, dimStyle.Render(viol.Detail)))
				tmp.WriteString("\n")
			}
		}
	}

	// Now clip to visible range using detailsScrollY
	allLines := strings.Split(strings.TrimRight(tmp.String(), "\n"), "\n")

	// clipLines clamps internally; sync to the actual top of the visible window
	result := clipLines(allLines, v.detailsScrollY, maxHeight)
	v.detailsScrollY = result.AboveCount

	// Indicator if there's more above (appears at top)
	if result.HasAbove {
		aboveLabel := "line"
		if result.AboveCount != 1 {
			aboveLabel = "lines"
		}
		sb.WriteString(dimStyle.Render(fmt.Sprintf("  ... %d %s above", result.AboveCount, aboveLabel)))
		sb.WriteString("\n")
	}

	// Write visible slice
	for i, line := range result.Lines {
		sb.WriteString(line)
		if i < len(result.Lines)-1 {
			sb.WriteString("\n")
		}
	}

	// Indicator if there's more below
	if result.HasBelow {
		sb.WriteString("\n")
		belowLabel := "line"
		if result.BelowCount != 1 {
			belowLabel = "lines"
		}
		sb.WriteString(dimStyle.Render(fmt.Sprintf("  ... %d more %s below", result.BelowCount, belowLabel)))
	}
}

func (v *DecisionView) renderActionsPalette(sb *strings.Builder, width int) {
	sb.WriteString("\n")

	// Allow/Deny selection
	var allowStr, denyStr string
	if v.focus == "actions" {
		if v.allowChosen {
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
	paddingLen := width - 50
	if width == 0 || paddingLen < 0 {
		paddingLen = 20
	}
	sb.WriteString(fmt.Sprintf("  %s  %s%s%s\n", allowStr, denyStr, strings.Repeat(" ", paddingLen), backStr))
	sb.WriteString("\n")

	// Duration selection
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
	if v.focus == "actions" {
		if v.allowChosen {
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
		if v.focus == "actions" && v.cursor == d.num {
			prefix = "> "
		}
		sb.WriteString(prefix + durationStyle.Render(d.text) + "  ")
	}
	sb.WriteString("\n")

	// Suggestions
	if v.suggCount() > 0 {
		active := v.activeSuggestions()
		for si, sugg := range active {
			rowIdx := 4 + si
			prefix := "  "
			if v.focus == "actions" && v.cursor == rowIdx {
				prefix = "> "
			}
			accepted := v.suggAccepted[si]
			var text string
			if accepted {
				text = allowStyle.Render("[✓] " + sugg)
			} else {
				text = infoStyle.Render("→ " + sugg)
			}
			sb.WriteString("           " + prefix + text + "\n")
		}
	}

	// Edit mode display when active
	if v.router.editMode {
		v.renderEditModeHint(sb)
	}

	// Focus/log indicators
	var tabLabel string
	if v.focus == "details" {
		tabLabel = "[Tab] Actions"
	} else {
		tabLabel = "[Tab] Details"
	}
	var logLabel string
	if v.logDecision {
		logLabel = infoStyle.Render("[L] Log")
	} else {
		logLabel = dimStyle.Render("[L] Log")
	}
	sb.WriteString(fmt.Sprintf("  %s    %s\n", dimStyle.Render(tabLabel), logLabel))
	sb.WriteString("\n")
}

func (v *DecisionView) renderEditModeHint(sb *strings.Builder) {
	if v.router.editSuggestionIdx < 0 || len(v.router.editVariants) == 0 {
		return
	}
	active := v.activeSuggestions()
	if len(active) == 0 || v.router.editSuggestionIdx >= len(active) {
		return
	}

	origTokens := parsePatternTokens(active[v.router.editSuggestionIdx])
	if v.router.editTokenIdx >= len(origTokens) {
		return
	}

	var argvParts []string
	for i, tok := range origTokens {
		if i == v.router.editTokenIdx && i < len(v.router.editVariants) && len(v.router.editVariants[i]) > 0 && v.router.editVariantIdx < len(v.router.editVariants[i]) {
			argvParts = append(argvParts, editStyle.Render(v.router.editVariants[i][v.router.editVariantIdx]))
		} else {
			argvParts = append(argvParts, tok)
		}
	}
	argvDisplay := "Argv: [" + strings.Join(argvParts, "] [") + "]"
	sb.WriteString("\n   " + allowStyle.Render(argvDisplay) + "\n")
	sb.WriteString(fmt.Sprintf("   %s  %s  %s\n",
		dimStyle.Render("←→ move"),
		dimStyle.Render("↑↓ generalize"),
		dimStyle.Render("Enter accept Esc cancel")))
}

// OnFocus is a no-op (cursor managed by router)
func (v *DecisionView) OnFocus() {
}

// OnBlur is a no-op (cursor managed by router)
func (v *DecisionView) OnBlur() {
}

// Teardown is a no-op for DecisionView.
// DecisionView does not manage cursor visibility, so no restore needed.
func (v *DecisionView) Teardown() {}