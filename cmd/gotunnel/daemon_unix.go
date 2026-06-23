//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func setDaemonAttr(cmd *exec.Cmd) {
	// Setsid puts the child process into a new session, detaching it from the
	// controlling terminal. Without this, pressing Ctrl+C in the terminal
	// sends SIGINT to the whole process group — including the daemon — causing
	// it to shut down even when only the TUI is being closed.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
