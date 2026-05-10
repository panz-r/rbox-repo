// tui_helpers.go - Shared helper functions for view-stack architecture.

package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// parsePatternTokens parses a pattern like "ls #path" into tokens
func parsePatternTokens(pattern string) []string {
	tokens := strings.Fields(pattern)
	return tokens
}

// tokenOrder defines a total ordering for wildcard tokens from most-specific to most-general.
// Index 0 = most specific, last index = most general.
var tokenOrder = []string{"#path", "#regex", "#num", "#val", "#any"}

// isWildcardToken returns true if the token is a type wildcard.
func isWildcardToken(t string) bool {
	return strings.HasPrefix(t, "#")
}

// specificityRank returns a rank (0=most specific) for a token.
// Non-wildcards return -1 (literal, treated as maximally specific in context).
func specificityRank(t string) int {
	for i, w := range tokenOrder {
		if w == t {
			return i
		}
	}
	return -1
}

// generateVariantsForToken generates ordered variant options for a token.
// Down (narrow) moves toward literal; Up (generalize) moves toward #any.
// Order in returned slice: [current, ..., #any] (most→least specific).
func generateVariantsForToken(token string) []string {
	// If literal, order is: literal → #val → #any
	if !isWildcardToken(token) {
		return []string{token, "#val", "#any"}
	}

	// If already a wildcard, build path from current toward #any
	// e.g. #path → [#path, #val, #any]
	// e.g. #num → [#num, #val, #any]
	// e.g. #any → [#any]
	variants := []string{token}
	rank := specificityRank(token)
	if rank < 0 {
		// Unknown wildcard (e.g. #custom) — skip to #any
		return []string{token, "#any"}
	}
	for i := rank + 1; i < len(tokenOrder); i++ {
		variants = append(variants, tokenOrder[i])
	}
	return variants
}

// --- Shared rendering helpers ---

// renderHeader renders the shared header (stats, mode indicator, flash message)
func renderHeader(sb *strings.Builder, width int, flashTimer int, stats Stats, pendingRetry int, opMode OpMode, flashMessage string) {
	total := stats.totalAllowed + stats.totalDenied + stats.totalUnknown
	statsStr := fmt.Sprintf(" %s %d  %s %d  %s %d = %d ",
		allowStyle.Render("●"), stats.totalAllowed,
		denyStyle.Render("●"), stats.totalDenied,
		infoStyle.Render("●"), stats.totalUnknown,
		total)

	if pendingRetry > 0 {
		statsStr += fmt.Sprintf("  %s %d pending", infoStyle.Render("●"), pendingRetry)
	}

	var modeText string
	switch opMode {
	case OpModePassthrough:
		modeText = "PASSTHROUGH"
	case OpModeAuto:
		modeText = "AUTO"
	default:
		modeText = "INTERACTIVE"
	}
	modeStr := dimStyle.Render("[" + modeText + "]")

	// Use lipgloss.Width to account for ANSI escape sequences in styled strings
	visualWidth := lipgloss.Width(statsStr) + lipgloss.Width(modeStr)
	padding := width - visualWidth
	if width == 0 {
		padding = DefaultPadding
	}
	if padding < 0 {
		padding = 0
	}
	leftPadding := padding / 2
	rightPadding := padding - leftPadding
	headerLine := strings.Repeat(" ", leftPadding) + statsStr + strings.Repeat(" ", rightPadding)
	headerLine = modeStr + strings.Repeat(" ", 2) + headerLine

	sb.WriteString(titleStyle.Render(headerLine))
	sb.WriteString("\n")

	if flashTimer > 0 && flashMessage != "" {
		sb.WriteString(infoStyle.Render("  " + flashMessage))
		sb.WriteString("\n")
	}
}

// renderFooter renders the shared footer
func renderFooter(sb *strings.Builder, width int, controls string) {
	footer := fmt.Sprintf(" %s  |  %s  q/ctrl+c to quit",
		infoStyle.Render(controls),
		infoStyle.Render("Exit:"))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render(strings.Repeat("─", width)))
	sb.WriteString("\n")
	sb.WriteString(footerStyle.Render(footer))
}

// buildCommandSummary builds the summary string for a command log entry
func buildCommandSummary(cmd *CommandLog) string {
	baseCmd := extractBaseName(cmd.Command)
	var summary string
	if cmd.Caller != "" {
		callerPrefix := cmd.Caller
		if cmd.Syscall != "" {
			callerPrefix = cmd.Caller + ":" + cmd.Syscall
		}
		callerPrefix += "$"
		if cmd.Args != "" {
			summary = fmt.Sprintf("%s %s %s", callerPrefix, baseCmd, truncateString(cmd.Args, TruncateWidth))
		} else {
			summary = fmt.Sprintf("%s %s", callerPrefix, baseCmd)
		}
	} else {
		summary = baseCmd
		if cmd.Args != "" {
			summary = fmt.Sprintf("%s %s", baseCmd, truncateString(cmd.Args, TruncateWidth))
		}
	}
	return summary
}

// joinTokens re-assembles a token slice into a pattern string
func joinTokens(tokens []string) string {
	result := ""
	for i, t := range tokens {
		if i > 0 {
			result += " "
		}
		result += t
	}
	return result
}

// --- Scroll helpers ---

// clipScrollSlice clamps a scroll offset and computes a visible slice window.
// Returns (clampedScrollY, visibleStart, visibleEnd) suitable for data[visibleStart:visibleEnd].
// Callers pass scrollY (current offset), visibleCount (viewport height in items),
// and totalItems (total items in the list). If totalItems is 0, returns zeros.
func clipScrollSlice(scrollY, visibleCount, totalItems int) (int, int, int) {
	if totalItems == 0 {
		return 0, 0, 0
	}
	if scrollY < 0 {
		scrollY = 0
	}
	maxScrollY := maxInt(0, totalItems-visibleCount)
	if scrollY > maxScrollY {
		scrollY = maxScrollY
	}
	visibleEnd := scrollY + visibleCount
	if visibleEnd > totalItems {
		visibleEnd = totalItems
	}
	return scrollY, scrollY, visibleEnd
}

// ScrollResult holds the output of clipLines, ready for rendering.
type ScrollResult struct {
	Lines      []string // visible slice
	HasAbove   bool     // there are hidden lines above
	AboveCount int      // how many lines hidden above
	HasBelow   bool     // there are hidden lines below
	BelowCount int      // how many lines hidden below
}

// clipLines clips a slice of lines to a visible window given a scroll offset and viewport height.
// Returns a ScrollResult with the visible slice and above/below indicator metadata.
// Callers render result.Lines and optionally append scroll indicators.
// maxHeight must be >= 1; if not it is clamped to 1.
func clipLines(allLines []string, scrollY int, maxHeight int) ScrollResult {
	if maxHeight < 1 {
		maxHeight = 1
	}
	totalLines := len(allLines)
	if scrollY < 0 {
		scrollY = 0
	}
	if scrollY >= totalLines {
		scrollY = maxInt(0, totalLines-1)
	}

	// Determine which indicators are needed
	hasAbove := scrollY > 0
	hasBelow := (scrollY + maxHeight) < totalLines

	// Reserve space for indicators
	indicatorLines := 0
	if hasAbove {
		indicatorLines++
	}
	if hasBelow {
		indicatorLines++
	}

	// If indicators would exceed viewport, suppress the less useful one
	if indicatorLines >= maxHeight && maxHeight >= 2 {
		aboveCount := scrollY
		belowCount := totalLines - (scrollY + maxHeight - 1)
		if aboveCount >= belowCount {
			hasBelow = false
		} else {
			hasAbove = false
		}
		indicatorLines = 0
		if hasAbove {
			indicatorLines++
		}
		if hasBelow {
			indicatorLines++
		}
	} else if indicatorLines >= maxHeight {
		// maxHeight == 1 and we need indicators: suppress both
		hasAbove = false
		hasBelow = false
		indicatorLines = 0
	}

	contentHeight := maxHeight - indicatorLines
	if contentHeight < 1 {
		contentHeight = 1
	}

	visibleEnd := scrollY + contentHeight
	if visibleEnd > totalLines {
		visibleEnd = totalLines
	}
	// hasBelow is already set above; do not overwrite after suppression

	return ScrollResult{
		Lines:      allLines[scrollY:visibleEnd],
		HasAbove:   hasAbove,
		AboveCount: scrollY,
		HasBelow:   hasBelow,
		BelowCount: totalLines - visibleEnd,
	}
}