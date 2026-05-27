//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

func setDaemonAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
