//go:build !windows

package main

import (
	"os/exec"
)

func setDaemonAttr(cmd *exec.Cmd) {
	// No special attributes needed for unix backgrounding in this context
}
