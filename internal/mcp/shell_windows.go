//go:build windows

package mcp

import (
	"context"
	"os/exec"
	"syscall"
)

func buildShellCommand(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "cmd")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// /S strips strictly the outer quotes we add, preserving internal quotes and spaces verbatim.
		CmdLine: `cmd /S /C "` + command + `"`,
	}
	return cmd
}
