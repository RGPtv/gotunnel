package tui

import "testing"

func TestTerminalTooSmallMessageFitsWidth(t *testing.T) {
	for _, width := range []int{0, 1, 5, 20, 60} {
		if got := len([]rune(terminalTooSmallMessage(width))); got > width {
			t.Fatalf("width %d: message has %d runes", width, got)
		}
	}
}
