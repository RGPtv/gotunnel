//go:build !windows

package tui

func initTerminal() {
	// VT processing is natively enabled on most Unix terminals
}
