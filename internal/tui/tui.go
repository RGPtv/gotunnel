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
	if len(r) > n {
		if n <= 3 {
			return string(r[:n])
		}
		return string(r[:n-1]) + "…"
	}
	return s + strings.Repeat(" ", n-len(r))
}

// rpad right-aligns s in n columns.
func rpad(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return strings.Repeat(" ", n-len(r)) + s
}

// hline returns w copies of ch.
func hline(w int, ch string) string { return strings.Repeat(ch, w) }

// writeLine writes s followed by clear-to-EOL + CRLF into b.
// Every line MUST go through writeLine so old content is always erased.
func writeLine(b *strings.Builder, s string, _ int) {
	b.WriteString(s)
	b.WriteString("\x1b[0K\r\n")
}

// flush writes the entire buffer to stdout in a single atomic write.
// It wraps the content in DEC Synchronized Output escape sequences
// (\x1b[?2026h / \x1b[?2026l) so the terminal renders the full frame
// at once — eliminating flicker on Windows Terminal, xterm, iTerm2, etc.
// Terminals that don't recognise the sequence silently ignore it.
func flush(b *strings.Builder) {
	const syncBegin = "\x1b[?2026h"
	const syncEnd   = "\x1b[?2026l"
	payload := syncBegin + b.String() + syncEnd
	os.Stdout.Write([]byte(payload))
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

// renderHeader draws a full-width header bar.
func renderHeader(b *strings.Builder, w int, title, right, badge string) {
	leftPlain := "  ◈  " + title + "  "
	leftColored := bgTeal + white + bold + "  ◈  " + reset + bgTeal + white + bold + title + reset + bgTeal + white + "  "

	rightPlain := "  " + right + "  "
	rightColored := bgTeal + grey + "  " + right + "  "

	badgePlain := " " + badge + " "
	badgeColored := bgLblue + "\x1b[38;5;17m" + bold + " " + badge + " " + reset

	padding := w - len([]rune(leftPlain)) - len([]rune(rightPlain)) - len([]rune(badgePlain))
	if padding < 0 {
		padding = 0
	}

	line := leftColored + bgTeal + strings.Repeat(" ", padding) + rightColored + badgeColored
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
	dashCount := w - 10 - titleVis
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
	if dashCount < 2 {
		dashCount = 2
	}
	line := "  " + dim + "╰" + strings.Repeat("─", dashCount-2) + "╯" + reset + "  "
	writeLine(b, line, w)
}

func panelSep(b *strings.Builder, w int) {
	dashCount := w - 4
	if dashCount < 2 {
		dashCount = 2
	}
	line := "  " + dim + "├" + strings.Repeat("─", dashCount-2) + "┤" + reset + "  "
	writeLine(b, line, w)
}

// panelRow writes one content row inside a box. It measures the visible
// width of `content` after stripping ANSI and right-pads to fill the box.
func panelRow(b *strings.Builder, content string, w int) {
	innerW := w - 8 // "  │ " (4) + " │  " (4)
	if innerW < 0 {
		innerW = 0
	}
	vis := len([]rune(stripANSI(content)))
	padLen := innerW - vis
	if padLen < 0 {
		padLen = 0
	}
	line := "  " + dim + "│ " + reset + content + strings.Repeat(" ", padLen) + dim + " │" + reset + "  "
	writeLine(b, line, w)
}

// renderSplash renders a centered message on an empty screen.
func renderSplash(b *strings.Builder, w, h int, msg string) {
	rows := h/2 - 1
	if rows < 0 {
		rows = 0
	}
	for i := 0; i < rows; i++ {
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
// Long values are truncated with an ellipsis so the box never overflows.
func cfgCell(label, value string, width int) string {
	if value == "" || value == "/" {
		value = "—"
	}
	labelVis := len([]rune(label))
	// +2 for the leading " " separator between label and value
	maxValVis := width - labelVis - 1
	if maxValVis < 1 {
		maxValVis = 1
	}
	valRunes := []rune(value)
	if len(valRunes) > maxValVis {
		if maxValVis > 1 {
			value = string(valRunes[:maxValVis-1]) + "…"
		} else {
			value = string(valRunes[:maxValVis])
		}
	}
	content := dim + label + reset + " " + lteal + value + reset
	vis := labelVis + 1 + len([]rune(value))
	padLen := width - vis
	if padLen < 0 {
		padLen = 0
	}
	return content + strings.Repeat(" ", padLen)
}

// statsBadge renders a stat item for the stats strip.
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


