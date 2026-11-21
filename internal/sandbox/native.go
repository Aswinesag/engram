package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// NativeRunner executes commands using OS-native fast sandboxing:
// - macOS: Seatbelt (`sandbox-exec`) restricting writes to worktree+/tmp and egress to localhost proxy
// - Linux: Bubblewrap (`bwrap`) with read-only system mounts and worktree-only writable bind
// - Windows: Worktree-scoped restricted runner with secret-stripped environment and proxy injection
type NativeRunner struct {
	cfg     Config
	backend string
	toolBin string
}

// NewNativeRunner selects the fastest available OS-native isolation backend.
func NewNativeRunner(cfg Config) (*NativeRunner, error) {
	backend, toolBin := detectNativeBackend()
	return &NativeRunner{
		cfg:     cfg,
		backend: backend,
		toolBin: toolBin,
	}, nil
}

// Backend returns the active native isolation backend identifier.
func (r *NativeRunner) Backend() string { return r.backend }

// Run executes req.Command inside the isolated worktree with sanitized env and proxy routing.
func (r *NativeRunner) Run(ctx context.Context, req ExecRequest) (ExecResult, error) {
	absWT, timeout, err := validateExecRequest(req)
	if err != nil {
		return ExecResult{}, err
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := r.buildNativeCmd(runCtx, absWT, req.Command)
	cmd.Dir = absWT
	cmd.Env = SanitizeEnvironment(os.Environ(), r.cfg.KeepHostSecrets, r.cfg.ProxyEnv, req.Env)

	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	runErr := cmd.Run()
	res := ExecResult{
		Output:  combined.String(),
		Backend: r.backend,
	}
	if runErr == nil {
		return res, nil
	}

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		res.ExitCode = 124
		res.TimedOut = true
		return res, nil
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("sandbox: native backend %q failed: %w", r.backend, runErr)
}

// BuildSeatbeltProfile constructs a macOS Seatbelt (SBPL) policy that confines
// filesystem writes strictly to worktreePath and /tmp, and confines outbound
// network traffic to localhost (forcing all egress through Engram's local Go proxy).
func BuildSeatbeltProfile(worktreePath string, allowLocalProxy bool) string {
	escapedWT := escapeSBPLString(worktreePath)

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	b.WriteString("(allow process*)\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow mach-lookup)\n")
	b.WriteString("(allow ipc-posix-shm*)\n")
	b.WriteString("(allow file-read*)\n")
	fmt.Fprintf(&b, "(allow file-write* (subpath %q))\n", escapedWT)
	b.WriteString("(allow file-write* (subpath \"/tmp\"))\n")
	b.WriteString("(allow file-write* (subpath \"/private/tmp\"))\n")
	b.WriteString("(allow file-write* (literal \"/dev/null\"))\n")
	b.WriteString("(allow file-write* (literal \"/dev/tty\"))\n")
	if allowLocalProxy {
		b.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
		b.WriteString("(allow network-outbound (remote ip \"127.0.0.1:*\"))\n")
	}
	return b.String()
}

// BuildBubblewrapArgs constructs Linux bubblewrap (`bwrap`) arguments mounting
// host system paths read-only and binding only worktreePath read-write.
func BuildBubblewrapArgs(worktreePath, command string, allowLocalProxy bool, existingDirs []string) []string {
	args := []string{
		"--die-with-parent",
		"--unshare-pid",
		"--new-session",
	}
	if !allowLocalProxy {
		args = append(args, "--unshare-net")
	}

	for _, dir := range existingDirs {
		args = append(args, "--ro-bind", dir, dir)
	}

	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--bind", worktreePath, worktreePath,
		"--chdir", worktreePath,
		"--",
		"sh", "-c", command,
	)
	return args
}

func escapeSBPLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
