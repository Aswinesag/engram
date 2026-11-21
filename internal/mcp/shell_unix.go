//go:build !windows

package mcp

import (
	"context"
	"os/exec"
)

func buildShellCommand(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", command)
}
