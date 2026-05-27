package tui

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/term"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

// ── ANSI codes ────────────────────────────────────────────────────────────────
const (
	esc   = "\x1b["
	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"

	cyan    = "\x1b[36m"
	green   = "\x1b[32m"
	red     = "\x1b[31m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"

	bgBlack = "\x1b[40m"
	bgBlue  = "\x1b[44m"
	bgCyan  = "\x1b[46m"

	// 256-color helpers
	teal    = "\x1b[38;5;30m"
	lblue   = "\x1b[38;5;39m"
	lgreen  = "\x1b[38;5;82m"
	amber   = "\x1b[38;5;214m"
	lpink   = "\x1b[38;5;213m"
	white   = "\x1b[38;5;231m"
	grey    = "\x1b[38;5;245m"
	lred    = "\x1b[38;5;196m"
	lteal   = "\x1b[38;5;123m"

	bgTeal  = "\x1b[48;5;24m"
	bgLblue = "\x1b[48;5;39m"
	bgDark  = "\x1b[48;5;236m"
	bgLred  = "\x1b[48;5;52m"
)

func hideCursor()  { os.Stdout.WriteString(esc + "?25l") }
func showCursor()  { os.Stdout.WriteString(esc + "?25h") }
func altScreen()   { os.Stdout.WriteString(esc + "?1049h") }
func mainScreen()  { os.Stdout.WriteString(esc + "?1049l") }

func termSize() (w, h int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80, 24
	}
	return w, h
}

// pad pads/truncates s to exactly n visible runes.
func pad(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		if n <= 3 {
			return string(r[:n])
		}
		return string(r[:n-1]) + "…"
	}
	return s + strings.Repeat(" ", n-len(r))
}

// rpad right-pads (left-aligns number) in n columns.
func rpad(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return string(r[:n])
	}
	return strings.Repeat(" ", n-len(r)) + s
}

// hline returns w copies of ch.
func hline(w int, ch string) string { return strings.Repeat(ch, w) }

// writeLine writes s followed by clear-to-EOL + newline into b.
// Every line MUST go through writeLine so old content is always erased.
func writeLine(b *strings.Builder, s string, _ int) {
	b.WriteString(s)
	b.WriteString("\x1b[0K\n")
}

// flush writes the entire buffer to stdout in a single syscall to minimise tearing.
func flush(b *strings.Builder) {
	os.Stdout.WriteString(b.String())
	b.Reset()
}

// readInput blocks and reads raw input, calling onCtrlC or onCtrlD.
func readInput(onCtrlC func(), onCtrlD func()) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			onCtrlD()
			return
		}
		switch buf[0] {
		case 3: // Ctrl+C
			onCtrlC()
			return
		case 4: // Ctrl+D
			onCtrlD()
			return
		}
	}
}

// ── Shared widgets ────────────────────────────────────────────────────────────

// renderHeader draws a full-width header bar that uses ONLY plain spaces for
// padding (no ANSI in the pad region) so the visual width is always exact.
func renderHeader(b *strings.Builder, w int, title, right, badge string) {
	// Left side: "  ◈  GoTunnel Server"  — visible chars only
	leftPlain := "  ◈  " + title + "  "
	leftColored := bgTeal + white + bold + "  ◈  " + reset + bgTeal + white + bold + title + reset + bgTeal + white + "  "

	// Right side: subtitle
	rightPlain := "  " + right + "  "
	rightColored := bgTeal + grey + "  " + right + "  " + reset

	// Badge: " SERVER "
	badgePlain := " " + badge + " "
	badgeColored := bgLblue + "\x1b[38;5;17m" + bold + " " + badge + " " + reset

	padding := w - len([]rune(leftPlain)) - len([]rune(rightPlain)) - len([]rune(badgePlain))
	if padding < 0 {
		padding = 0
	}

	line := leftColored + bgTeal + strings.Repeat(" ", padding) + reset + rightColored + badgeColored
	writeLine(b, line, w)
}

// renderFooter draws a full-width footer bar for keybind hints.
func renderFooter(b *strings.Builder, w int, leftHint, rightHint string) {
	leftPlain := "  ⌨  " + leftHint + "  "
	leftColored := bgDark + grey + "  " + lblue + "⌨" + grey + "  " + leftHint + "  "

	rightPlain := "  " + rightHint + "  ✕  "
	rightColored := bgDark + grey + "  " + rightHint + "  " + red + "✕" + grey + "  " + reset

	padding := w - len([]rune(leftPlain)) - len([]rune(rightPlain))
	if padding < 0 {
		padding = 0
	}

	line := leftColored + strings.Repeat(" ", padding) + rightColored
	writeLine(b, line, w)
}

// ── Box Panel Helpers ─────────────────────────────────────────────────────────

func panelTop(b *strings.Builder, title string, w int) {
	titleVis := len([]rune(stripANSI(title)))
	dashCount := w - 8 - titleVis
	if dashCount < 0 {
		dashCount = 0
	}
	leftDashes := dashCount / 2
	rightDashes := dashCount - leftDashes

	line := "  " + dim + "╭─" + strings.Repeat("─", leftDashes) + reset + " " + bold + title + reset + " " + dim + strings.Repeat("─", rightDashes) + "─╮" + reset + "  "
	writeLine(b, line, w)
}

func panelBottom(b *strings.Builder, w int) {
	dashCount := w - 4
	if dashCount < 0 {
		dashCount = 0
	}
	line := "  " + dim + "╰" + strings.Repeat("─", dashCount-2) + "╯" + reset + "  "
	writeLine(b, line, w)
}

func panelSep(b *strings.Builder, w int) {
	dashCount := w - 4
	if dashCount < 0 {
		dashCount = 0
	}
	line := "  " + dim + "├" + strings.Repeat("─", dashCount-2) + "┤" + reset + "  "
	writeLine(b, line, w)
}

func panelRow(b *strings.Builder, content string, w int) {
	vis := len([]rune(stripANSI(content)))
	padLen := (w - 8) - vis
	if padLen < 0 {
		padLen = 0
	}
	line := "  " + dim + "│ " + reset + content + strings.Repeat(" ", padLen) + dim + " │" + reset + "  "
	writeLine(b, line, w)
}

// renderSplash renders a centered message on an empty screen.
func renderSplash(b *strings.Builder, w, h int, msg string) {
	for i := 0; i < h/2-1; i++ {
		writeLine(b, "", w)
	}
	vis := len([]rune(stripANSI(msg))) 
	padding := (w - vis) / 2
	if padding < 0 {
		padding = 0
	}
	writeLine(b, strings.Repeat(" ", padding)+msg, w)
}

// cfgCell renders a label+value info cell padded to `width` visible chars.
func cfgCell(label, value string, width int) string {
	if value == "" || value == "/" {
		value = "—"
	}
	content := dim + label + reset + " " + lteal + value + reset
	// visual width = len(label) + 1 + len(value)
	vis := len([]rune(label)) + 1 + len([]rune(value))
	padLen := width - vis
	if padLen < 1 {
		padLen = 1
	}
	return content + strings.Repeat(" ", padLen)
}

// statsBadge renders a stat item without the bar, for a cleaner look.
func statsBadge(label, value, valueColor string) string {
	return dim + label + " " + reset + valueColor + bold + value + reset + "    "
}

// logStyleFull returns color, symbol and short label for a log level.
func logStyleFull(level int) (color, sym, label string) {
	switch level {
	case 0:
		return lblue, "·", "INFO "
	case 1:
		return amber, "!", "WARN "
	case 2:
		return lred, "✗", "ERROR"
	case 3:
		return lgreen, "✓", "OK   "
	default:
		return dim, "·", "INFO "
	}
}

func logStyle(level int) (color, sym string) {
	c, s, _ := logStyleFull(level)
	return c, s
}

// ── Format helpers ────────────────────────────────────────────────────────────

func fmtDuration(d interface{ Seconds() float64 }) string {
	total := int(d.Seconds())
	h := total / 3600
	m := (total % 3600) / 60
	s := total % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}

func maskSecret(s string) string {
	if s == "" {
		return "—"
	}
	if len(s) <= 8 {
		return "••••••••"
	}
	return s[:4] + "••••" + s[len(s)-2:]
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// infoCell is kept for compatibility.
func infoCell(label, value string, width int) string {
	return cfgCell(label, value, width)
}
