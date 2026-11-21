package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const DefaultContainerImage = "ubuntu:24.04"

// StrictRunner executes commands inside ephemeral, hardened Docker/Podman containers
// with only the active detached Git worktree bind-mounted at /workspace.
type StrictRunner struct {
	cfg        Config
	runtimeBin string
	backend    string
}

// NewStrictRunner detects Docker or Podman and initializes a StrictRunner.
func NewStrictRunner(cfg Config) (*StrictRunner, error) {
	if strings.TrimSpace(cfg.ContainerImage) == "" {
		cfg.ContainerImage = DefaultContainerImage
	}

	bin, backend, err := resolveContainerRuntime(cfg.ContainerRuntime)
	if err != nil {
		return nil, err
	}

	return &StrictRunner{
		cfg:        cfg,
		runtimeBin: bin,
		backend:    backend,
	}, nil
}

// Backend returns the container runtime backend name ("docker" or "podman").
func (r *StrictRunner) Backend() string { return r.backend }

// BuildContainerArgs constructs deterministic, hardened container CLI arguments
// enforcing read-only rootfs, dropped capabilities, worktree-only bind mount,
// and proxy-only or disabled networking.
func BuildContainerArgs(cfg Config, absWorktreePath, command string, extraEnv []string) []string {
	image := strings.TrimSpace(cfg.ContainerImage)
	if image == "" {
		image = DefaultContainerImage
	}

	args := []string{
		"run",
		"--rm",
		"--init",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--pids-limit=256",
		"--memory=2g",
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,size=512m",
		"-v", absWorktreePath + ":/workspace:rw",
		"-w", "/workspace",
	}

	hasProxy := len(cfg.ProxyEnv) > 0
	if hasProxy {
		args = append(args, "--add-host=host.docker.internal:host-gateway")
		for _, kv := range RewriteProxyEnvForContainer(cfg.ProxyEnv) {
			args = append(args, "-e", kv)
		}
	} else if !cfg.AllowNetwork {
		args = append(args, "--network=none")
	}

	for _, kv := range extraEnv {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || (!cfg.KeepHostSecrets && isSensitiveEnvKey(k)) {
			continue
		}
		args = append(args, "-e", kv)
	}

	args = append(args, image, "sh", "-c", command)
	return args
}

// Run launches an ephemeral container for req.Command and cleans it up automatically.
func (r *StrictRunner) Run(ctx context.Context, req ExecRequest) (ExecResult, error) {
	absWT, timeout, err := validateExecRequest(req)
	if err != nil {
		return ExecResult{}, err
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := BuildContainerArgs(r.cfg, absWT, req.Command, req.Env)
	cmd := exec.CommandContext(runCtx, r.runtimeBin, args...)

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
	return res, fmt.Errorf("sandbox: run %s container: %w", r.backend, runErr)
}

func resolveContainerRuntime(preferred string) (binPath, backend string, err error) {
	preferred = strings.TrimSpace(preferred)
	if preferred != "" {
		path, lookErr := exec.LookPath(preferred)
		if lookErr != nil {
			return "", "", fmt.Errorf("%w: %s (%v)", ErrContainerRuntimeNotFound, preferred, lookErr)
		}
		return path, preferred, nil
	}

	for _, candidate := range []string{"docker", "podman"} {
		if path, lookErr := exec.LookPath(candidate); lookErr == nil {
			return path, candidate, nil
		}
	}
	return "", "", ErrContainerRuntimeNotFound
}
