package tui

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ANSI sequences
const (
	esc   = "\x1b["
	reset = "\x1b[0m"

	bold      = "\x1b[1m"
	dim       = "\x1b[2m"

	cyan   = "\x1b[36m"
	green  = "\x1b[32m"
	red    = "\x1b[31m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	magenta= "\x1b[35m"

	bgBlack = "\x1b[40m"
	bgBlue  = "\x1b[44m"
	bgCyan  = "\x1b[46m"
)

func clearScreen() { fmt.Print(esc + "2J" + esc + "H") }
func hideCursor()  { fmt.Print(esc + "?25l") }
func showCursor()  { fmt.Print(esc + "?25h") }
func altScreen()   { fmt.Print(esc + "?1049h") }
func mainScreen()  { fmt.Print(esc + "?1049l") }

func termSize() (w, h int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80, 24
	}
	return w, h
}

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

func rpad(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return string(r[:n])
	}
	return strings.Repeat(" ", n-len(r)) + s
}

func hline(w int, ch string) string { return strings.Repeat(ch, w) }

func writeLine(b *strings.Builder, s string, w int) {
	b.WriteString(s)
	b.WriteString(esc + "0K\n") // clear to end of line, then newline
}

// readInput blocks and reads raw input, calling onCtrlC or onCtrlD
func readInput(onCtrlC func(), onCtrlD func()) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			onCtrlD() // EOF
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
