//go:build !windows

package remotehand

import (
	"os/exec"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func killProcessTree(cmd *exec.Cmd) {
	// Kill the whole process group (negative pid) so Chromium and its child tree
	// die with the sidecar — a lone Process.Kill leaves orphaned Chromium procs.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill() // fallback if the group kill didn't apply
}
