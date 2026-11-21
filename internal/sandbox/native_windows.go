//go:build windows

package sandbox

import (
	"context"
	"os/exec"
	"syscall"
)

func detectNativeBackend() (backend, toolBin string) {
	return "windows-restricted", ""
}

func (r *NativeRunner) buildNativeCmd(ctx context.Context, _, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "cmd")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// /S strips only our outer quotes so internal quotes and spaces pass verbatim.
		CmdLine: `cmd /S /C "` + command + `"`,
	}
	return cmd
}
