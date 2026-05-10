// tui_view_mode_modal.go - Mode selection modal overlay view.

package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Package-level modal styles ---

var (
	modalTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF79C6"))
	modalOptionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2"))
	modalSelectedOptionStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#44475A")).
			Foreground(lipgloss.Color("#F8F8F2"))
	modalDimOptionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4"))
	modalBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#6272A4")).
			Padding(1, 2)
)

// ModeModalView is a modal overlay for switching operational modes.
type ModeModalView struct {
	router  *Router
	cursor  int
}

// NewModeModalView creates a new mode modal overlay.
func NewModeModalView(router *Router) *ModeModalView {
	return &ModeModalView{
		router:  router,
		cursor:  int(router.opMode),
	}
}

func (v *ModeModalView) Router() *Router { return v.router }
func (v *ModeModalView) Name() string     { return "ModeModalView" }

func (v *ModeModalView) Init() tea.Cmd {
	return nil
}

// Update handles mode modal keybindings.
func (v *ModeModalView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			v.cursor = (v.cursor - 1 + 3) % 3

		case "down", "tab":
			v.cursor = (v.cursor + 1) % 3

		case "enter", "m":
			v.router.opMode = OpMode(v.cursor)
			v.router.SetFlash("Mode: "+v.router.opMode.String(), FlashTimerSeconds)
			return v, PopView()

		case "esc", "ctrl+z", "shift+tab":
			return v, PopView()
		}

	case tea.WindowSizeMsg:
		return v, nil
	}

	return v, nil
}

// View renders the mode modal centered on a clear full-screen background.
func (v *ModeModalView) View() string {
	width := v.router.Width()
	height := v.router.Height()

	modalWidth := width - 4
	if modalWidth < 30 {
		modalWidth = 30
	}

	// Apply dynamic width to each style (chain returns a new Style, doesn't mutate)
	titleStyle := modalTitleStyle.Width(modalWidth)
	optionStyle := modalOptionStyle.Width(modalWidth)
	selectedOptionStyle := modalSelectedOptionStyle.Width(modalWidth)
	dimOptionStyle := modalDimOptionStyle.Width(modalWidth)
	boxStyle := modalBoxStyle.Width(modalWidth)

	opts := []struct {
		mode OpMode
		name string
		desc string
	}{
		{OpModeInteractive, "Interactive", "Wait for user input on each request"},
		{OpModePassthrough, "Passthrough", "Allow all requests without user involvement"},
		{OpModeAuto, "Auto", "Allow/deny by policy, auto-deny requests needing user input"},
	}

	var sb strings.Builder
	sb.WriteString(boxStyle.Render(titleStyle.Render("  Choose Mode  ")))
	sb.WriteString("\n")

	for i, opt := range opts {
		var row string
		if i == v.cursor {
			row = fmt.Sprintf(" > %s - %s", opt.name, opt.desc)
			sb.WriteString(selectedOptionStyle.Render(row))
		} else {
			row = fmt.Sprintf("   %s - %s", opt.name, opt.desc)
			sb.WriteString(optionStyle.Render(row))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(dimOptionStyle.Render("\n   ↑↓ change  Enter confirm  Esc cancel"))

	content := sb.String()
	// lipgloss.Place fills the entire screen with spaces, effectively clearing any
	// remnants of the underlying view so the modal appears on a clean background.
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, content)
}

// OnFocus hides the cursor.
func (v *ModeModalView) OnFocus() {
	fmt.Print("\033[?25l")
}

// OnBlur shows the cursor.
func (v *ModeModalView) OnBlur() {
	fmt.Print("\033[?25h")
}

// Teardown restores the cursor on program exit.
func (v *ModeModalView) Teardown() {
	fmt.Print("\033[?25h")
}
