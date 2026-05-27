//go:build windows

package tui

import (
	"os"

	"golang.org/x/sys/windows"
)

func initTerminal() {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	windows.GetConsoleMode(handle, &mode)
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	windows.SetConsoleMode(handle, mode)
}
