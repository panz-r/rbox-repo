// tui_view_edit_suggestion.go - Edit suggestion overlay view.

package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// EditSuggestionView allows editing a token variant in a suggestion pattern.
type EditSuggestionView struct {
	router          *Router
	cmd             *CommandLog // the command whose suggestion we're editing
	suggIdx         int         // which suggestion (index into active suggestions list)
	allowChosen     bool        // true = allow suggestions, false = deny suggestions
	tokens          []string    // current tokens during editing (mutated by left/right/up/down)
	cmdTokens       []string    // tokens of the actual command (for narrowing suggestion tokens)
}

// NewEditSuggestionView creates a new edit suggestion overlay.
func NewEditSuggestionView(router *Router, cmd *CommandLog, suggIdx int, allowChosen bool, pattern string) *EditSuggestionView {
	parsed := parsePatternTokens(pattern)
	cmdParsed := parsePatternTokens(cmd.Command)
	return &EditSuggestionView{
		router:      router,
		cmd:        cmd,
		suggIdx:    suggIdx,
		allowChosen: allowChosen,
		tokens:     parsed, // mutable working copy
		cmdTokens:  cmdParsed,
	}
}

func (v *EditSuggestionView) Router() *Router { return v.router }
func (v *EditSuggestionView) Name() string   { return "EditSuggestionView" }
func (v *EditSuggestionView) Init() tea.Cmd {
	r := v.router
	r.editMode = true
	r.editTokenIdx = 0
	r.editVariantIdx = 0
	r.editSuggestionIdx = v.suggIdx

	// Reconstruct full pattern from tokens
	fullPattern := joinTokens(v.tokens)

	r.editVariants = make([][]string, len(v.tokens))
	for i := range v.tokens {
		if r.gate != nil {
			if variants, err := r.gate.SuggestionTokenVariantsAt(fullPattern, i); err == nil && len(variants) > 0 {
				r.editVariants[i] = v.filterPos0Variants(variants, i)
			} else {
				// Fallback: generate variants from type lattice
				r.editVariants[i] = v.filterPos0Variants(generateVariantsForToken(v.tokens[i]), i)
			}
		} else {
			r.editVariants[i] = v.filterPos0Variants(generateVariantsForToken(v.tokens[i]), i)
		}
		// Ensure at least one variant exists (original token as fallback)
		if len(r.editVariants[i]) == 0 {
			r.editVariants[i] = []string{v.tokens[i]}
		}
		// Inject the actual command token as the most narrow option for narrowing a
		// suggestion that was generalized beyond the real value (e.g., #p → #path,
		// but the real command was /usr/lib/command-not-found)
		r.editVariants[i] = v.injectCmdToken(r.editVariants[i], i)
		// De-duplicate across all sources
		r.editVariants[i] = v.deduplicate(r.editVariants[i])
	}
	return nil
}

// deduplicate returns a copy of variants with duplicates removed.
// The first occurrence of each unique string is kept (preserves order).
func (v *EditSuggestionView) deduplicate(variants []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(variants))
	for _, cv := range variants {
		if !seen[cv] {
			seen[cv] = true
			out = append(out, cv)
		}
	}
	return out
}

// injectCmdToken prepends the actual command token as the most specific variant
// so the user can narrow a suggestion back down to the real value.
func (v *EditSuggestionView) injectCmdToken(variants []string, pos int) []string {
	if pos >= len(v.cmdTokens) {
		return variants
	}
	cmdLiteral := v.cmdTokens[pos]
	// Don't duplicate
	for _, cv := range variants {
		if cv == cmdLiteral {
			return variants
		}
	}
	return append([]string{cmdLiteral}, variants...)
}

// filterPos0Variants removes overly-specific types for the first token (command name).
// #sha, #regex, #num are not useful generalizations of a command name like "ls".
// The literal itself is always preserved as the most specific option.
func (v *EditSuggestionView) filterPos0Variants(variants []string, pos int) []string {
	if pos != 0 {
		return variants
	}
	allowed := map[string]bool{"#path": true, "#val": true, "#any": true}
	filtered := make([]string, 0, len(variants))
	for _, v := range variants {
		if allowed[v] {
			filtered = append(filtered, v)
		}
	}
	// Ensure the literal is present as the most narrow option
	literal := v.tokens[0]
	found := false
	for _, f := range filtered {
		if f == literal {
			found = true
			break
		}
	}
	if !found {
		filtered = append([]string{literal}, filtered...)
	}
	if len(filtered) == 0 {
		return variants
	}
	return filtered
}

// findVariantIdxForCurrentToken finds the variant index in r.editVariants
// that matches the current value of v.tokens[r.editTokenIdx]. This is
// needed when navigating left/right to restore the correct selection
// rather than defaulting to index 0.
func (v *EditSuggestionView) findVariantIdxForCurrentToken() int {
	r := v.router
	if r.editTokenIdx >= len(v.tokens) || r.editTokenIdx >= len(r.editVariants) {
		return 0
	}
	current := v.tokens[r.editTokenIdx]
	variants := r.editVariants[r.editTokenIdx]
	for i, tv := range variants {
		if tv == current {
			return i
		}
	}
	return 0
}

// Update handles token navigation, variant cycling, and policy toggle.
func (v *EditSuggestionView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		r := v.router

		switch msg.String() {
		case "left":
			if r.editTokenIdx > 0 {
				r.editTokenIdx--
				// Find the variant index that matches the current token value
				r.editVariantIdx = v.findVariantIdxForCurrentToken()
			}

		case "right":
			if r.editTokenIdx < len(v.tokens)-1 {
				r.editTokenIdx++
				// Find the variant index that matches the current token value
				r.editVariantIdx = v.findVariantIdxForCurrentToken()
			}

		case "home":
			if len(v.tokens) > 0 {
				r.editTokenIdx = 0
				r.editVariantIdx = v.findVariantIdxForCurrentToken()
			}

		case "end":
			if len(v.tokens) > 0 {
				r.editTokenIdx = len(v.tokens) - 1
				r.editVariantIdx = v.findVariantIdxForCurrentToken()
			}

		case "up":
			// Generalize: move toward more general (end of variants list)
			if len(r.editVariants) > r.editTokenIdx && len(r.editVariants[r.editTokenIdx]) > 0 {
				if r.editVariantIdx < len(r.editVariants[r.editTokenIdx])-1 {
					r.editVariantIdx++
					v.tokens[r.editTokenIdx] = r.editVariants[r.editTokenIdx][r.editVariantIdx]
				}
			}

		case "down":
			// Narrow: move toward more specific (start of variants list)
			if len(r.editVariants) > r.editTokenIdx && len(r.editVariants[r.editTokenIdx]) > 0 {
				if r.editVariantIdx > 0 {
					r.editVariantIdx--
					v.tokens[r.editTokenIdx] = r.editVariants[r.editTokenIdx][r.editVariantIdx]
				}
			}

		case "shift+tab":
			// Push mode modal on top; edit state stays intact beneath it
			return v, PushView(NewModeModalView(v.router))

		case "enter":
			// Accept: build new pattern from current tokens, update EvalResult, pop, notify DecisionView
			newPattern := joinTokens(v.tokens)
			if v.cmd != nil && v.cmd.EvalResult != nil {
				active := v.cmd.EvalResult.Suggestions
				if !v.allowChosen && len(v.cmd.EvalResult.DenySuggestions) > 0 {
					active = v.cmd.EvalResult.DenySuggestions
				}
				if v.suggIdx < len(active) {
					active[v.suggIdx] = newPattern
				}
			}
			v.router.endEditMode()
			return v, tea.Sequence(
				PopView(),
				func() tea.Msg {
					return SuggestionEditedMsg{SuggestionIdx: v.suggIdx, NewPattern: newPattern, Accepted: true}
				},
			)

		case "esc", "ctrl+z":
			// Cancel: clear edit state and pop
			v.router.endEditMode()
			return v, PopView()
		}

	case tea.WindowSizeMsg:
		return v, nil
	}

	return v, nil
}

// View renders the edit suggestion overlay.
func (v *EditSuggestionView) View() string {
	width := v.router.Width()

	// Policy indicator
	var policyLine string
	if v.allowChosen {
		policyLine = allowStyle.Render("ALLOW") + dimStyle.Render(" policy")
	} else {
		policyLine = denyStyle.Render("DENY") + dimStyle.Render(" policy")
	}

	// Token counter
	tokenCounter := dimStyle.Render(fmt.Sprintf("  token %d/%d", v.router.editTokenIdx+1, len(v.tokens)))

	// Title row: Edit Suggestion [@pos n/m]
	title := fmt.Sprintf(" Edit Suggestion [@pos %d/%d] ", v.router.editTokenIdx+1, len(v.tokens))
	titleWidth := width - 4
	if titleWidth < 20 {
		titleWidth = 20
	}
	titleStyle := lipgloss.NewStyle().
		Width(titleWidth).
		Foreground(lipgloss.Color("#FF79C6")).
		Bold(true)

	boxStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#6272A4")).
		Padding(1, 2).
		Width(width - 4)

	argvDisplay := v.buildArgvDisplay()
	controlsLine := dimStyle.Render("←→ token  ↑↓ generalize/narrow  Enter add rule  Esc cancel")

	content := titleStyle.Render(title) + "\n\n" +
		policyLine + "\n" +
		tokenCounter + "\n\n" +
		argvDisplay + "\n\n" +
		controlsLine

	return boxStyle.Render(content)
}

// buildArgvDisplay builds the argv display with the current token highlighted
// and the variants list shown clearly below.
func (v *EditSuggestionView) buildArgvDisplay() string {
	var sb strings.Builder
	r := v.router

	// Build current pattern from variants
	current := make([]string, len(v.tokens))
	copy(current, v.tokens)
	if r.editTokenIdx < len(r.editVariants) && len(r.editVariants[r.editTokenIdx]) > 0 &&
		r.editVariantIdx >= 0 && r.editVariantIdx < len(r.editVariants[r.editTokenIdx]) {
		current[r.editTokenIdx] = r.editVariants[r.editTokenIdx][r.editVariantIdx]
	}

	// Style for selected token: dark bg in ALLOW/DENY color, black text
	var selectedTokStyle lipgloss.Style
	if v.allowChosen {
		selectedTokStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#50FA7B")).
			Foreground(lipgloss.Color("#000000")).
			Padding(0, 1)
	} else {
		selectedTokStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#FF5555")).
			Foreground(lipgloss.Color("#000000")).
			Padding(0, 1)
	}

	// Style for unselected tokens: mid-tone (not too dim, not white)
	unselectedTokStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#9585BE"))

	// Line 1: argv: token1 token2 [token3] token4
	sb.WriteString("  argv: ")
	for i, tok := range current {
		if i == r.editTokenIdx {
			sb.WriteString(selectedTokStyle.Render(tok))
		} else {
			sb.WriteString(unselectedTokStyle.Render(tok))
		}
		if i < len(current)-1 {
			sb.WriteString(" ")
		}
	}

	// Line 2: available variants
	if r.editTokenIdx < len(r.editVariants) && len(r.editVariants[r.editTokenIdx]) > 0 &&
		r.editVariantIdx >= 0 && r.editVariantIdx < len(r.editVariants[r.editTokenIdx]) {
		variants := r.editVariants[r.editTokenIdx]
		altList := strings.Join(variants, ", ")
		currentTok := current[r.editTokenIdx]
		// e.g. "  ↑↓ timeout, #val, #any  (now: timeout)"
		variantLine := fmt.Sprintf("  %s  (now: %s)",
			dimStyle.Render("↑↓ "+altList),
			selectedTokStyle.Render(currentTok))
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("       " + variantLine))
	}

	return sb.String()
}

// OnFocus hides the cursor.
func (v *EditSuggestionView) OnFocus() {
	fmt.Print("\033[?25l")
}

// OnBlur restores the cursor. Edit state is NOT cleared here because
// the view may still be on the stack (e.g., when the mode modal opens via Shift+Tab).
// Edit state is cleaned up by endEditMode() in the Enter/Esc handlers or handleEvent.
func (v *EditSuggestionView) OnBlur() {
	fmt.Print("\033[?25h") // show cursor
}

// Teardown restores the cursor on program exit.
func (v *EditSuggestionView) Teardown() {
	fmt.Print("\033[?25h")
}