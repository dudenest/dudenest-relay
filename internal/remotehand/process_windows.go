//go:build windows

package remotehand

import "os/exec"

func setProcessGroup(cmd *exec.Cmd) {}

func killProcessTree(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
