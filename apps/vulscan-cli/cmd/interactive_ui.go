// Interactive-mode UI: lipgloss styles, banner, spinner, and status panel.
package cmd

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	uiAccent  = lipgloss.Color("#A78BFA") // soft purple, matches report theme
	uiNavy    = lipgloss.Color("#1E1B4B")
	uiMuted   = lipgloss.Color("#6B7280")
	uiSuccess = lipgloss.Color("#34D399")
	uiDanger  = lipgloss.Color("#F87171")
	uiWarning = lipgloss.Color("#FBBF24")

	styleBrand = lipgloss.NewStyle().
			Bold(true).
			Foreground(uiAccent)

	styleMuted = lipgloss.NewStyle().Foreground(uiMuted)

	stylePrompt = lipgloss.NewStyle().
			Bold(true).
			Foreground(uiAccent)

	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(uiAccent).
			Padding(0, 2)

	styleOK   = lipgloss.NewStyle().Foreground(uiSuccess)
	styleErr  = lipgloss.NewStyle().Foreground(uiDanger)
	styleWarn = lipgloss.NewStyle().Foreground(uiWarning)

	styleCmdName = lipgloss.NewStyle().Foreground(uiAccent).Bold(true)
	styleCmdDesc = lipgloss.NewStyle().Foreground(lipgloss.Color("#D1D5DB"))
)

// uiInfo prints a standard info line.
func uiInfo(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  %s\n", styleCmdDesc.Render(fmt.Sprintf(format, args...)))
}

// uiOK prints a success line.
func uiOK(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", styleOK.Render("✓"), styleCmdDesc.Render(fmt.Sprintf(format, args...)))
}

// uiFail prints an error line without killing the REPL.
func uiFail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", styleErr.Render("✗"), styleErr.Render(fmt.Sprintf(format, args...)))
}

// uiHint prints a muted hint line.
func uiHint(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  %s\n", styleMuted.Render(fmt.Sprintf(format, args...)))
}

// spinnerFrames are braille frames for the loading animation.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinner is a minimal terminal animation bound to real work: run it while
// initialization happens, then stop. It never pads the wait artificially.
type spinner struct {
	msg     string
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func newSpinner(msg string) *spinner {
	return &spinner{msg: msg, stop: make(chan struct{}), stopped: make(chan struct{})}
}

func (s *spinner) start() {
	go func() {
		defer close(s.stopped)
		tick := time.NewTicker(80 * time.Millisecond)
		defer tick.Stop()
		i := 0
		for {
			select {
			case <-s.stop:
				// Clear the animation line.
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-tick.C:
				frame := styleBrand.Render(spinnerFrames[i%len(spinnerFrames)])
				fmt.Fprintf(os.Stderr, "\r\033[K  %s %s", frame, styleMuted.Render(s.msg))
				i++
			}
		}
	}()
}

func (s *spinner) done() {
	s.once.Do(func() {
		close(s.stop)
		<-s.stopped
	})
}

// statusPanel renders the welcome/status box: brand, version, and the
// current provider/model/key/project state.
func statusPanel(version, provider, model, maskedKey, activeProject string) string {
	if activeProject == "" {
		activeProject = styleMuted.Render("(none — use /project)")
	}
	title := styleBrand.Render("911VulScan") + styleMuted.Render("  LLM-powered SAST "+version)
	rows := []string{
		title,
		"",
		fmt.Sprintf("%s  %s", styleMuted.Render("Provider "), styleCmdDesc.Render(provider)),
		fmt.Sprintf("%s  %s", styleMuted.Render("Model    "), styleCmdDesc.Render(model)),
		fmt.Sprintf("%s  %s", styleMuted.Render("API key  "), styleCmdDesc.Render(maskedKey)),
		fmt.Sprintf("%s  %s", styleMuted.Render("Project  "), activeProject),
		"",
		styleMuted.Render("Type /help to see all commands, /exit to quit."),
	}
	return stylePanel.Render(strings.Join(rows, "\n"))
}

// printBanner clears any spinner residue and prints the welcome panel.
func printBanner(version, provider, model, maskedKey, activeProject string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, statusPanel(version, provider, model, maskedKey, activeProject))
	fmt.Fprintln(os.Stderr)
}
