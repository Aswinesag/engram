//go:build !windows

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"runtime"
)

func detectNativeBackend() (backend, toolBin string) {
	switch runtime.GOOS {
	case "darwin":
		if p, err := exec.LookPath("sandbox-exec"); err == nil {
			return "sandbox-exec", p
		}
	case "linux":
		if p, err := exec.LookPath("bwrap"); err == nil {
			return "bwrap", p
		}
	}
	return "unix-restricted", ""
}

func (r *NativeRunner) buildNativeCmd(ctx context.Context, absWorktreePath, command string) *exec.Cmd {
	allowLocalProxy := len(r.cfg.ProxyEnv) > 0 || r.cfg.AllowNetwork

	switch r.backend {
	case "sandbox-exec":
		profile := BuildSeatbeltProfile(absWorktreePath, allowLocalProxy)
		return exec.CommandContext(ctx, r.toolBin, "-p", profile, "sh", "-c", command)
	case "bwrap":
		var roDirs []string
		for _, d := range []string{"/usr", "/bin", "/lib", "/lib64", "/etc"} {
			if info, err := os.Stat(d); err == nil && info.IsDir() {
				roDirs = append(roDirs, d)
			}
		}
		args := BuildBubblewrapArgs(absWorktreePath, command, allowLocalProxy, roDirs)
		return exec.CommandContext(ctx, r.toolBin, args...)
	default:
		return exec.CommandContext(ctx, "sh", "-c", command)
	}
}
